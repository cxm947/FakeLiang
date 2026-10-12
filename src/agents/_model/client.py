"""The shared model client: one prompt in, one JSON object out.

The executor is model-driven now, so this module is a transport plus an envelope reader, not a
decision table. A caller builds one prompt (card knowledge + the frozen endpoint + this run's own
history), the model answers with one call or one finish, and the run records the exchange and
checks the citations itself. Deliberately absent:

* **no menu and no rule fallback** - a caller that cannot reach a model reports that instead of
  inventing an answer (``run_lean_task.drive`` raises ``LEAN_MODEL_UNAVAILABLE``);
* **no prompt builders and no validators** - the shape of an answer is the caller's business, so
  the prompt lives next to the caller that needs it;
* **no ``model.jsonl`` writing** - the caller records the exchange with ``runtime.model_log``.

What stays, because a caller has to be able to tell "an answer arrived" from "it did not":
:class:`ModelReply` (ok / payload / error / tokens / finish reason / attempts), a retry policy
that only retries what a retry can fix, and the rule that the transport credential never lands
in a record.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from hashlib import sha256

from .contract import (
    EMPTY_CONTENT_ERROR, TRUNCATED_ERROR, UNPARSEABLE_ANSWER_ERROR, WIRES,
    ModelClient, ModelReply, NoModel,
)
from .sdk import _sdk_module, sdk_kwargs
from .text import FENCE, _decoded_dump, _digest, _excerpt, _json_object_prompts, _parse_json_text

#: **默认不设输出上限**（爷爷 2026-10-06 口径：用 effort=none，别掐 token 量）。
#: 为什么：这条线上思考关不掉（实测 none/minimal/不传 都产出 reasoning 项，off/0 被 400 拒），
#: 而且推理与正文**共享**同一个输出上限 —— 掐上限的结果是"思考吃光预算、正文 0 字节"
#: （walk-58 node 7/19：6000 token、正文空、finish=length）。不写这个字段，就交给供应商自己的
#: 默认/硬上限。调用方**显式**给了上限才带上，而且撞满也不偷偷加倍（那是产品约束，不是"再问一次"
#: 的起点）。卡里若显式声明 output_budget，就是显式上限；今天没有卡声明它。

#: An upstream that answered 5xx (or 429) is having a bad minute, not refusing this prompt: the
#: same request is worth sending again, patiently. Measured 2026-10-06 (e2e-full-38): three nodes
#: ended on LEAN_MODEL_REPLY_UNAVAILABLE during one ~1-minute 502 window, because the whole retry
#: budget - five attempts, ~18 s of backoff - fitted inside that window.
TRANSIENT_STATUS_EXTRA_ATTEMPTS = 4


def _backoff(attempt: int, *, transient: bool) -> float:
    """How long to wait before attempt ``attempt + 1``.

    A hiccupping model and a broken upstream need different patience: five seconds is plenty for
    the first, while a gateway that is down needs tens of seconds to come back.
    """
    if transient:
        return min(5.0 * attempt, 30.0)
    return min(2.0 * attempt, 5.0)


DEFAULT_BASE_URL = "https://api.openai.com/v1"


class HttpModel(ModelClient):
    """An OpenAI-compatible chat-completions client on the standard library.

    Design notes, all of them deliberate:

    * **no new dependency** - one HTTP POST is not a reason to grow the dependency surface;
      ``urllib`` is enough;
    * **deterministic-ish** - temperature 0 and ``response_format=json_object`` are asked for; a
      provider that ignores either still has to parse as JSON;
    * **retries only where a retry can help** - transport errors, 429, 5xx and an empty
      completion are retried (a reasoning model that spent its whole budget thinking has not
      answered); a 4xx (bad key, unknown model) is reported once and never hammered;
    * **the key never lands in a log** - it is read from the environment (or passed in) and never
      written into the transcript; a provider response that echoes it is refused.
    """

    def __init__(self, *, name: str, base_url: str, api_key: str, timeout: float = 60.0,
    retries: int = 4, max_tokens: int | None = None,
                 temperature: float = 0.0, reasoning_effort: str = "", opener=None,
                 wire: str = "chat"):
        self.name = str(name or "")
        #: 说哪一种线协议；不认识的写法当场拒绝，别静默退回 chat（那会得到一个 404 而不是一个答案）。
        self.wire = str(wire or "chat").strip().lower()
        if self.wire not in WIRES:
            raise ValueError("MODEL_WIRE_UNKNOWN: %r (known: %s)" % (wire, ", ".join(WIRES)))
        self.base_url = str(base_url or "").rstrip("/")
        self._api_key = str(api_key or "")
        self.timeout = float(timeout)
        self.retries = max(0, int(retries))
        self.max_tokens = int(max_tokens or 0)
        self.temperature = float(temperature)
        #: How hard the provider should *think* before answering. Empty = the provider's own
        #: default. A machine-checkable decision does not need a scratchpad: the live runs
        #: measured 48-57 s for one port probe while the model reasoned, and a much shorter wait
        #: for the same decision with the scratchpad turned off.
        self.reasoning_effort = str(reasoning_effort or "").strip().lower()
        self._opener = opener or self._post
        #: 调用方没塞替身 transport 时，chat 线优先走官方 SDK（爷爷 2026-10-06 口径：
        #: 所有调用都用 ``from openai import OpenAI`` + ``chat.completions.create``）。
        #: 塞了替身（单测的 opener）就照样走自带 urllib —— 测试钉的是信封与重试，不是 HTTP 库。
        self._opener_is_default = opener is None

    def _sdk_opener(self, system: str, user: str, effort: str, budget):
        """把一次调用交给官方 SDK，并把结果翻译成 chat 线信封交给 ``_read`` 同一套记账。

        这样 token 计数、空答复重试、回显凭据拒收这些行为在两条 transport 上完全一致；
        换 transport 只换"怎么把话发出去"，不换"怎么判断答没答"。
        """
        kwargs = sdk_kwargs(model=self.name, system=system, user=user,
                            temperature=self.temperature, max_tokens=budget or 0, effort=effort)
        api_key, base_url = self._api_key, self.base_url

        def call(url, body, headers, timeout):
            openai = _sdk_module()
            client = openai.OpenAI(api_key=api_key, base_url=base_url or None,
                                   timeout=timeout, max_retries=0)
            try:
                completion = client.chat.completions.create(timeout=timeout, **kwargs)
            except Exception as error:  # SDK 把 4xx/5xx 包成自己的异常
                status = int(getattr(error, "status_code", 0) or 0)
                return (status or 599, "%s: %s" % (type(error).__name__, error))
            dump = completion.model_dump() if hasattr(completion, "model_dump") else {}
            return (200, json.dumps(dump, ensure_ascii=False, default=str))

        return call

    def available(self) -> bool:
        return bool(self.name and self.base_url and self._api_key)

    def _post(self, url: str, body: bytes, headers: dict, timeout: float):
        """The real transport: one POST, returned as (status, text)."""
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return (int(getattr(response, "status", 200)),
                        response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as error:
            return int(error.code), error.read().decode("utf-8", "replace")

    def complete(self, *, task: str, system: str, user: str, timeout: float | None = None,
                 retries: int | None = None, reasoning_effort: str = "",
                 max_tokens: int | None = None, deadline_at: float | None = None) -> ModelReply:
        limit = float(timeout if timeout is not None else self.timeout)
        tries = self.retries if retries is None else max(0, int(retries))
        if deadline_at is not None:
            # The saved owner decides the next attempt; unclear sends stay unknown.
            tries = 0
        effort = str(reasoning_effort or self.reasoning_effort or "").strip().lower()
        #: 上限：调用方（或卡）**显式**给了才带上；没给就一个字段都不写（默认不设限）。
        #: 显式给了就照给，撞满**不偷偷加倍** —— 那个上限是产品约束，不是"再问一次也许能写完"的起点
        #: （2026-10-06：模型动辄写 1.5k–16.6k，其中大部分是解释，调用方只取 JSON，其余付了钱全扔）。
        budget = int(max_tokens) if max_tokens else (self.max_tokens or None)
        system, user = _json_object_prompts(system, user)
        url, body = self._request(system, user, effort, budget)
        request_id = _digest(system + "\n" + user)
        headers = {"Content-Type": "application/json", "Authorization": "Bearer " + self._api_key}
        opener = self._opener
        if self._opener_is_default and self.wire == "chat" and _sdk_module() is not None:
            opener = self._sdk_opener(system, user, effort, budget)
        started = time.monotonic()
        # Fixed at entry; a transient response never extends this deadline.
        deadline = started + max(120.0, limit * (tries + 1) + 90.0)
        if deadline_at is not None:
            deadline = min(deadline, time.monotonic() + max(0.0, deadline_at - time.time()))
        last_error = ""
        attempt = 0
        allowed = tries
        transient_bonus_granted = False

        def wait_for_retry(*, transient: bool) -> bool:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(_backoff(attempt, transient=transient), remaining))
            return time.monotonic() < deadline

        while attempt <= allowed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                last_error = "MODEL_CALL_DEADLINE_EXCEEDED"
                break
            attempt += 1
            try:
                status, text = opener(url, body, headers, min(limit, remaining))
            except Exception as error:  # transport: DNS, TLS, timeout, reset
                last_error = type(error).__name__
                if deadline_at is None and not transient_bonus_granted:
                    allowed += TRANSIENT_STATUS_EXTRA_ATTEMPTS
                    transient_bonus_granted = True
                if attempt <= allowed:
                    if wait_for_retry(transient=True):
                        continue
                    last_error = "MODEL_CALL_DEADLINE_EXCEEDED"
                break
            if time.monotonic() >= deadline:
                last_error = "MODEL_CALL_DEADLINE_EXCEEDED"
                break
            if status == 200:
                reply = self._read(text, request_id=request_id, attempt=attempt, started=started,
                                   budget=budget)
                retryable = (reply.error.startswith(EMPTY_CONTENT_ERROR)
                              or reply.error.startswith(UNPARSEABLE_ANSWER_ERROR))
                if reply.ok or not retryable or deadline_at is not None:
                    return reply
                last_error = reply.error
                if attempt <= allowed:
                    if wait_for_retry(transient=False):
                        continue
                    last_error = "MODEL_CALL_DEADLINE_EXCEEDED"
                    break
                return reply
            last_error = "HTTP " + str(status)
            if deadline_at is not None:
                break
            if status == 429 or 500 <= status < 600:
                if deadline_at is None and not transient_bonus_granted:
                    allowed += TRANSIENT_STATUS_EXTRA_ATTEMPTS
                    transient_bonus_granted = True
                if attempt <= allowed:
                    if wait_for_retry(transient=True):
                        continue
                    last_error = "MODEL_CALL_DEADLINE_EXCEEDED"
            break
        return ModelReply(ok=False, model=self.name, error=last_error or "the call failed",
                          attempts=attempt, request_sha256=request_id,
                          latency_ms=int((time.monotonic() - started) * 1000))


    def _request(self, system: str, user: str, effort: str, budget: int | None = None) -> tuple:
        """按线协议组一次请求，返回 (url, body)。两条线的字段名不同，形状相同。"""
        #: ``budget`` 为空 = 不设限：这个字段干脆不写（供应商用自己的默认/硬上限）。
        system, user = _json_object_prompts(system, user)
        max_out = int(budget) if budget else 0
        if self.wire == "responses":
            payload = {
                "model": self.name,
                "input": [{"role": "system",
                           "content": [{"type": "input_text", "text": system}]},
                          {"role": "user",
                           "content": [{"type": "input_text", "text": user}]}],
                "temperature": self.temperature,
                #: 与 chat 那条线一样要一个 JSON 对象：别让调用方去猜散文里的括号。
                "text": {"format": {"type": "json_object"}},
            }
            if max_out:
                payload["max_output_tokens"] = max_out
            if effort:
                #: Responses 的原生写法；``none`` 是真的把思考关掉。
                payload["reasoning"] = {"effort": effort}
            return (self.base_url + "/responses",
                    json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        payload = {
            "model": self.name,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "temperature": self.temperature,
            "response_format": {"type": "json_object"},
        }
        if max_out:
            payload["max_tokens"] = max_out
        if effort:
            payload["reasoning_effort"] = effort
        return (self.base_url + "/chat/completions",
                json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    def _envelope(self, envelope: dict) -> tuple:
        """从回复里取 (正文, finish_reason, 输入 token, 输出 token, 模型名)。

        两条线把同样的东西放在不同地方：responses 的正文在 output[] 里 type=message 的
        content[] 里（type=output_text），截断写在 status/incomplete_details 里；chat 的在
        choices[0].message.content。取不到正文本身不是错误，调用方按"空答复"重试或报错。
        """
        if self.wire == "responses":
            content = ""
            for item in envelope.get("output") or []:
                if not isinstance(item, dict) or item.get("type") != "message":
                    continue
                for chunk in item.get("content") or []:
                    if isinstance(chunk, dict) and chunk.get("type") == "output_text":
                        content += str(chunk.get("text") or "")
            status = str(envelope.get("status") or "")
            details = envelope.get("incomplete_details")
            reason = str((details or {}).get("reason") or "") if isinstance(details, dict) else ""
            if status == "incomplete" and reason == "max_output_tokens":
                finish_reason = "length"          # 与 chat 那条线同义：预算用完了
            elif status and status != "completed":
                finish_reason = status + (("/" + reason) if reason else "")
            else:
                finish_reason = status
            usage = envelope.get("usage") if isinstance(envelope.get("usage"), dict) else {}
            details = usage.get("output_tokens_details")
            reasoning = int((details or {}).get("reasoning_tokens") or 0) if isinstance(details, dict) else 0
            return (content, finish_reason, int(usage.get("input_tokens") or 0),
                    int(usage.get("output_tokens") or 0),
                    str(envelope.get("model") or self.name), reasoning)
        choices = envelope.get("choices") or []
        choice = choices[0] if choices and isinstance(choices[0], dict) else {}
        message = (choice.get("message") if isinstance(choice.get("message"), dict) else {}) or {}
        usage = envelope.get("usage") if isinstance(envelope.get("usage"), dict) else {}
        details = usage.get("completion_tokens_details")
        reasoning = int((details or {}).get("reasoning_tokens") or 0) if isinstance(details, dict) else 0
        return (str(message.get("content") or ""), str(choice.get("finish_reason") or ""),
                int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0),
                str(envelope.get("model") or self.name), reasoning)

    def _read(self, text: str, *, request_id: str, attempt: int, started: float,
              budget: int | None = None) -> ModelReply:
        latency = int((time.monotonic() - started) * 1000)
        try:
            envelope = json.loads(text)
        except ValueError as error:
            return ModelReply(ok=False, model=self.name, attempts=attempt,
                              error="the provider did not answer with JSON: " + str(error),
                              latency_ms=latency, request_sha256=request_id)
        # Any decoded value is checked, not only an object (run86): a credential echoed through a
        # non-object reply - escaped inside a string or an array - must not be readable in a
        # failure record either.
        if self._api_key and self._api_key in json.dumps(envelope, ensure_ascii=False):
            return ModelReply(ok=False, model=self.name, attempts=attempt,
                              error="provider response included the transport credential",
                              latency_ms=latency, request_sha256=request_id)
        if not isinstance(envelope, dict):
            return ModelReply(ok=False, model=self.name, attempts=attempt,
                              error="the provider did not answer with a JSON object: got "
                                    + type(envelope).__name__,
                              latency_ms=latency, request_sha256=request_id)
        (content, finish_reason, prompt_tokens, completion_tokens, model_name,
         reasoning_tokens) = self._envelope(envelope)
        reply = ModelReply(ok=bool(content), text=content,
                           model=model_name, latency_ms=latency,
                           attempts=attempt, request_sha256=request_id,
                           prompt_tokens=prompt_tokens,
                           completion_tokens=completion_tokens,
                           reasoning_tokens=reasoning_tokens,
                           finish_reason=finish_reason,
                           max_tokens=int(budget or 0))
        if finish_reason == "length":
            reply.ok = False
            reply.error = TRUNCATED_ERROR
            return reply
        if not content:
            reply.error = EMPTY_CONTENT_ERROR + (
                " (finish_reason=" + repr(finish_reason) + ")" if finish_reason else "")
            #: Keep what the provider actually sent, bounded and redacted: a later reader has to
            #: be able to tell "the body was empty" from "our reader missed the content".
            reply.raw_excerpt = _excerpt(text, secret=self._api_key)
            return reply
        parsed, problem = _parse_json_text(content)
        if parsed is None:
            reply.raw_excerpt = _excerpt(content, secret=self._api_key)
            reply.ok = False
            reply.error = problem
            # Not an object - but the decoded value and the raw text are both searched before a
            # failure record keeps them (run86); a hit clears the text as the object case does.
            if self._api_key and (self._api_key in _decoded_dump(content)
                                  or self._api_key in content):
                reply.text = ""
                reply.error = "provider response included the transport credential"
            return reply
        if self._api_key and self._api_key in json.dumps(parsed, ensure_ascii=False):
            reply.ok = False
            reply.text = ""
            reply.error = "provider response included the transport credential"
            return reply
        reply.payload = parsed
        return reply


def client_from_env(*, name: str = "", base_url: str = "", api_key: str = "",
                    api_key_env: str = "AGV_MODEL_API_KEY", timeout: float = 60.0,
                    retries: int = 2, max_tokens: int | None = None,
                    opener=None, wire: str = "", backend: str = "legacy") -> ModelClient:
    """Build the client the caller asked for. Anything missing means `NoModel`.

    The key is read from the environment by default so it never has to appear on a command line
    (and therefore never in a shell history or a process list).
    """
    if backend not in ("legacy", "native"):
        raise ValueError("MODEL_BACKEND_INVALID")
    model = str(name or "").strip()
    if not model:
        missing = NoModel()
        if backend == "native":
            missing.backend = "native"
        return missing
    key = str(api_key or "").strip() or str(os.environ.get(str(api_key_env) or "", "")).strip()
    if not key:
        missing = NoModel()
        if backend == "native":
            missing.backend = "native"
        return missing
    #: ``AGV_MODEL_REASONING_EFFORT=none`` turns the provider's scratchpad off; an empty value
    #: keeps whatever the provider does by default.
    effort = str(os.environ.get("AGV_MODEL_REASONING_EFFORT", "") or "").strip()
    #: 线协议来自参数或 ``AGV_MODEL_WIRE``，默认 chat（OpenAI 兼容）。
    chosen_wire = str(wire or os.environ.get("AGV_MODEL_WIRE", "") or "chat").strip().lower()
    if backend == "native":
        if opener is not None:
            raise ValueError("MODEL_NATIVE_TRANSPORT_OVERRIDE")
        from .chat import ChatModel
        return ChatModel(name=model,
                         base_url=str(base_url or "").strip() or DEFAULT_BASE_URL,
                         api_key=key, timeout=timeout, retries=retries,
                         max_tokens=int(max_tokens) if max_tokens else 0,
                         reasoning_effort=effort, wire=chosen_wire)
    return HttpModel(name=model, base_url=str(base_url or "").strip() or DEFAULT_BASE_URL,
                     api_key=key, timeout=timeout, retries=retries,
                     max_tokens=int(max_tokens) if max_tokens else 0,
                     reasoning_effort=effort, opener=opener, wire=chosen_wire)
