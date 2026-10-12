"""Model exchange objects and error names."""
from __future__ import annotations

from dataclasses import dataclass, field



#: 两种线协议。``chat`` = OpenAI 兼容的 /chat/completions；``responses`` = 原生 Responses API
#: （/responses）。2026-10-06：本机的 model router 只认后者（/chat/completions 直接 404），之前靠
#: tmp/ 里一个只剩 .pyc 的中转壳把 chat 翻成 responses —— 那既不是工具的一部分，也没法维护。
WIRES = ("chat", "responses")

#: A reasoning model can spend the whole budget on its scratchpad and return an empty content
#: string. That is a provider hiccup rather than an answer, so the transport retries it like a
#: 5xx - and a lasting emptiness is reported as a failed reply, never as a decision.
EMPTY_CONTENT_ERROR = "the model returned no content"


#: A model that answers with two objects (or an object plus prose that defeats the reader) has
#: hiccuped the same way an empty answer does; one retry can fix it, and the transport is the
#: only place that knows the answer never reached a caller.
UNPARSEABLE_ANSWER_ERROR = "the answer is not JSON"

#: A reply stopped by the completion budget (``finish_reason="length"``) is a truncation, not an
#: answer: half an object must not reach a caller, and a retry at the same budget cannot help -
#: so it never matches the empty-content retry above.
TRUNCATED_ERROR = "the model output was truncated (finish_reason=length)"

@dataclass
class ModelReply:
    """One exchange with a model: what came back, what it cost, and whether it parsed."""

    ok: bool
    text: str = ""
    payload: dict | None = None
    model: str = ""
    error: str = ""
    latency_ms: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    #: 供应商侧"思考"占了多少 token。实测 2026-10-06：这条线上 effort=none **不等于关掉**思考
    #: （none/minimal/不传 都会产出 reasoning 项，off/0 直接 400），而推理与正文**共享**
    #: max_output_tokens —— 所以"正文为空 + finish=length"的真相常常是思考把预算吃光了。
    #: 不记下来，这事只能靠猜；记下来，一眼能看出该给多少余量。
    reasoning_tokens: int = 0
    request_sha256: str = ""
    attempts: int = 0
    finish_reason: str = ""
    max_tokens: int = 0
    native_message: dict | None = None
    tool_calls: list = field(default_factory=list)
    response_confirmed: bool = False

    def to_json(self) -> dict:
        payload = {"ok": self.ok, "model": self.model, "attempts": self.attempts,
                   "latency_ms": self.latency_ms, "request_sha256": self.request_sha256}
        if self.prompt_tokens or self.completion_tokens:
            payload["prompt_tokens"] = self.prompt_tokens
            payload["completion_tokens"] = self.completion_tokens
        if self.reasoning_tokens:
            payload["reasoning_tokens"] = self.reasoning_tokens
        if self.finish_reason:
            payload["finish_reason"] = self.finish_reason
        if self.max_tokens:
            payload["max_tokens"] = self.max_tokens
        if self.error:
            payload["error"] = self.error
        return payload


class ModelClient:
    """What a caller needs from a model: one prompt in, one JSON object out."""

    name = ""
    backend = "legacy"

    def available(self) -> bool:
        return False

    def complete(self, *, task: str, system: str, user: str, timeout: float = 60.0,
                 retries: int = 2) -> ModelReply:  # pragma: no cover - interface
        raise NotImplementedError


class NoModel(ModelClient):
    """No model configured: ``available()`` is false and the caller reports that, not a guess."""

    name = ""
