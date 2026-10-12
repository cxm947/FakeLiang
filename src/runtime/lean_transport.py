"""Serial dispatch and transport accounting for a lean run."""
from __future__ import annotations

from copy import deepcopy
import json
import re
import shlex
import time
from uuid import uuid4

from graph.files import atomic_write
from runtime import channels, dispatch, lean_http
from runtime.lean_journal import _bytes, _error, _sha
from runtime.markers import call_marker, marker_script, shell_command
from runtime.redact import _HEADER_VALUE, collect_secrets
from runtime.runner import ExecOutcome, execute, new_call_id, ownership


_MATERIAL_VALUE = re.compile(r"(?im)\b(?:password|passwd|pwd|secret|token|ntlm|nthash)\s*[:=]\s*([^\r\n]+)")

#: 一个**动作批次**里块与块之间的默认间隔（秒）。爷爷 2026-10-07：多块一次给出没问题，间隔由
#: 引擎管（"相隔 5 秒执行就好，或者更少"）—— 一秒够跨过一次 RPC 往返，也不至于把一格的回合拖长。
ACTION_GAP_SECONDS = 1.0


def observation_secrets(text, patterns=()):
    """Identify secret spans, never infer the account to which they belong."""
    values = [match.group(1).strip() for pattern in (_HEADER_VALUE, _MATERIAL_VALUE)
              for match in pattern.finditer(text)]
    for pattern in patterns:
        values.extend(match.group("value") for match in re.finditer(pattern, text)
                      if match.group("value"))
    return tuple(value for value in values if value)


def _inline_budget(session) -> int:
    """How much one console line may carry: its declared capacity, or a conservative default."""
    capacity = (session or {}).get("capacity") or {}
    limit = capacity.get("max_bytes")
    return int(limit) if type(limit) is int and limit > 0 else 1024

def stage_payload_for(card, task, declared) -> str:
    """Decide which payload a stage step plants, or "" to keep whatever the card declares.

    The model's own choice always wins. Otherwise a node that has something to hand over
    plants *that*: the card's own default payload is the plain command-execution variant, and
    asking for the card's fixed step should not require remembering which one this node needs
    (measured 2026-10-08, walk-126 node 7: the card's shell was planted, the stager never
    fetched, and the node could not hand over a session).
    """
    if str((declared or {}).get("payload") or "").strip():
        return ""
    handover = str(((task or {}).get("inputs") or {}).get("delivery_payload") or "").strip()
    return handover if handover and isinstance((card or {}).get("stage"), dict) else ""



def _transport_receipt_fields(result, marker, *, framed_required=True):
    """把"运输完成 / 命令退出码 / 为什么停止读取"从观测里读出来（2026-10-07 桥评审定稿）。

    * 只有**完整的有序帧**（且没超时、没工具错）才算 `completed_transport`；
    * 结束帧带了退出码 → 记 `command_rc`；裸 `end` → `command_rc=None`（**没拿到码 ≠ 成功**）；
    * `read_stop` 如实带进回执：`end_marker` / `deadline` / `prompt` / `idle` ——
      没有它，"我读完了"和"我放弃了"在记录里长得一模一样。
    * **没有结束帧的动词**（meterpreter 原生 `sysinfo`/`getuid`/kiwi 一类）：它印出来的就是它的
      答案，不回空就算完成 —— 与 `session_manager` 的原生探活同一口径。以前这里一律要帧，
      于是"答案齐了"的原生调用被记成 `unknown`，那一格因此拿不到证据
      （2026-10-08 walk-131 node 5 实测：sysinfo 回来了、回执却是 unknown）。
    """
    from .runner import observe_marker_frame

    read_stop = getattr(result, "read_stop", None)
    if not framed_required:
        #: 只有"答案自己停住了"才算完成；读满协议超时的捕获可能只拿到半截，那种不认。
        answered = (bool(str(result.stdout or "").strip())
                    and not result.timed_out and not result.tool_error)
        return {"status": "completed_transport" if answered else "unknown",
                "command_rc": 0 if answered else None,
                "read_stop": read_stop}
    framed, command_rc = observe_marker_frame(result.stdout, marker)
    complete = (not result.timed_out and not result.tool_error
                and read_stop in (None, "end_marker", "quiet") and framed)
    return {"status": "completed_transport" if complete else "unknown",
            "command_rc": command_rc if complete else None,
            "read_stop": read_stop}


class _LeanTransport:


    def _receipt_for(self, call_id, marker, result, *, framed_required=True):
        artifacts = {name: {"bytes": len(data), "sha256": _sha(data)}
                     for name in ("stdout.txt", "stderr.txt", "call.json")
                     for data in [self._artifact(call_id, name).read_bytes()]}
        receipt = {"run_id": self.run_id, "call_id": call_id,
                   "effect": "not_verified", "scope": self._safe(self.scope),
                   "executor_label": self._safe(self.executor_label),
                   "returncode": result.returncode, "timed_out": result.timed_out,
                   "tool_error": self._safe(result.tool_error), "artifacts": artifacts,
                   "marker": marker, "observed_at": time.time()}
        receipt.update(_transport_receipt_fields(result, marker,
                                                framed_required=framed_required))
        receipt["produced_output"] = bool(str(result.stdout or "").strip())
        return receipt

    def _publish_receipt(self, call_id, marker, result, *, framed_required=True):
        receipt = self._receipt_for(call_id, marker, result, framed_required=framed_required)
        self._append("commit", call_id=call_id, phase="artifacts_saved",
                     artifacts=receipt["artifacts"])
        atomic_write(self._artifact(call_id, "receipt.json"), _bytes(receipt))
        self._append("receipt", call_id=call_id, receipt=receipt)
        return self._view(receipt)


    def _stage_body(self, argv, marker, parent_call_id="", deadline_at=None):
        """Record each remote chunk as a child call before its write can commit."""
        if not parent_call_id:
            if hasattr(self, "root"):
                _error("LEAN_STAGE_PARENT_REQUIRED")
            from pathlib import Path
            from tempfile import TemporaryDirectory
            with TemporaryDirectory(prefix="agv-body-stage-") as folder:
                values = {"root": Path(folder), "card": {"id": "body.stage"},
                          "scope": {}, "secrets": [], "executor_label": "console",
                          "run_id": "run-" + uuid4().hex}
                existing = {key: getattr(self, key) for key in values if hasattr(self, key)}
                try:
                    for key, value in values.items():
                        if key not in existing:
                            setattr(self, key, value)
                    parent = new_call_id() + "-" + uuid4().hex
                    digest = _sha(str(argv).encode("utf-8"))
                    until = time.time() + float(self.timeout)
                    self._append("intent", call_id=parent, request_digest=digest,
                                 request_record_digest=_sha(_bytes({})), request={},
                                 marker=marker, deadline_at=until)
                    self._append("commit", call_id=parent, phase="before_commit")
                    return self._stage_body(argv, marker, parent, until)
                finally:
                    for key in values:
                        if key in existing:
                            setattr(self, key, existing[key])
                        else:
                            delattr(self, key)
        if (len(argv) != 4 or argv[1] != "-c" or not isinstance(argv[2], str)
                or not isinstance(argv[3], str)):
            _error("LEAN_HTTP_BODY_STAGE_UNSUPPORTED")
        budget = _inline_budget(self.session)
        if len((argv[0] + argv[2]).encode("utf-8")) + 96 > budget:
            _error("LEAN_HTTP_BODY_STAGE_UNSUPPORTED")
        token = re.sub(r"[^0-9a-z]", "", str(marker).lower())
        path = "/tmp/agv-http-%s.b64" % token
        payload = argv[3]
        size = max(256, min(2048, budget // 2))
        pieces = [payload[index:index + size] for index in range(0, len(payload), size)]
        for index, piece in enumerate(pieces):
            remaining = deadline_at - time.time()
            if remaining <= 0:
                _error("LEAN_ACTION_DEADLINE")
            chunk_marker = str(marker) + "w" + str(index)
            inner = ["/bin/sh", "-c", "printf '%%s' '%s' %s %s" % (
                piece, ">" if index == 0 else ">>", path)]
            action = {"operation": "shell",
                      "text": marker_script(inner, chunk_marker, merge_stderr=True, single_line=True),
                      "completion": {"marker": chunk_marker}}
            request = {"tool": "body_stage", "index": index, "remote_path": path,
                       "payload_sha256": _sha(piece.encode("utf-8"))}
            digest = _sha(_bytes(request))
            events = self._read()
            intents, receipts = self._calls(events)
            found = [(key, row) for key, row in intents.items()
                     if row.get("parent_call_id") == parent_call_id
                     and row.get("staging_index") == index]
            if len(found) > 1:
                _error("LEAN_STAGING_ASSOCIATION_LOST")
            if found:
                call_id, intent = found[0]
                if intent.get("request_digest") != digest:
                    _error("LEAN_STAGING_ASSOCIATION_LOST")
                fact = self._recovery_fact(call_id, intent, events)
                if fact["state"] == "finished":
                    receipt = self._calls(self._read())[1][call_id]
                    if receipt.get("command_rc") != 0:
                        _error("LEAN_HTTP_BODY_STAGE_UNCONFIRMED", path)
                    continue
                if fact["state"] != "not_executed":
                    _error("LEAN_STAGING_UNCONFIRMED", call_id)
            else:
                call_id = new_call_id() + "-" + uuid4().hex
                (self.root / "calls" / call_id).mkdir(parents=True, exist_ok=False)
                self._append("intent", call_id=call_id, request_digest=digest,
                             request_record_digest=digest, request=request,
                             marker=chunk_marker, scope=self._safe(self.scope),
                             effect="potential_change", parent_call_id=parent_call_id,
                             staging_index=index, deadline_at=deadline_at,
                             framed_required=True)
                self._append("commit", call_id=call_id, phase="before_commit")

            def transport(tokens, timeout):
                self._append("commit", call_id=call_id, phase="committing")
                outcome = channels.console_call(self.session, action, timeout)
                self._append("commit", call_id=call_id, phase="after_commit")
                discovered = [value for text in (outcome.stdout, outcome.stderr,
                                                  outcome.tool_error or "")
                              for value in observation_secrets(text,
                                  self.card.get("secret_patterns", ()))]
                self.secrets[:] = list(collect_secrets(
                    {"stdout": outcome.stdout, "stderr": outcome.stderr},
                    (*self.secrets, *discovered)))
                return ExecOutcome(outcome.returncode,
                                   self._safe(str(outcome.stdout or "").replace(piece, "<body-chunk>")),
                                   self._safe(str(outcome.stderr or "").replace(piece, "<body-chunk>")),
                                   outcome.timed_out,
                                   self._safe(str(outcome.tool_error).replace(piece, "<body-chunk>"))
                                   if outcome.tool_error is not None else None,
                                   outcome.read_stop)
            transport.audit_argv = lambda tokens: ["lean-http-body-stage", json.dumps(request)]
            transport.label = lambda: self._safe(self.executor_label)
            result = execute(inner, run_dir=self.root / "calls",
                             skill_id=self._safe(self.card["id"]), executor=transport,
                             call_id=call_id, timeout=max(0.001, deadline_at - time.time()),
                             redactions=(*self.secrets, piece))
            receipt = self._publish_receipt(call_id, chunk_marker, result)
            if receipt["status"] != "completed_transport" or receipt["command_rc"] != 0:
                _error("LEAN_HTTP_BODY_STAGE_UNCONFIRMED", path)
        return "%s -c %s \"$(cat %s)\"; rm -f %s\n" % (
            shlex.quote(argv[0]), shlex.quote(argv[2]), path, path)

    def call_many(self, requests, *, gap=None):
        """一次回答里的多个动作块：**一块一条调用**，逐块记账，块间由引擎串行。

        为什么要有它（爷爷 2026-10-07 口径）：模型一次可以给多个**独立**动作块，多步就不必等下一轮
        模型回复；而"每块各记一条回执"让一处失败只影响那一块（walk-69 node 48 把 6 个动作拼进一条
        549 字符长命令，一处坏整条废，长行尾巴还被会话吞掉）。块间隔也由引擎管 —— 模型不必再写
        `ping -n 6` 去"等一等"。
        """
        wait = ACTION_GAP_SECONDS if gap is None else float(gap)
        views = []
        for index, request in enumerate(requests):
            if index and wait:
                time.sleep(wait)
            views.append(self.call(request))
        return views

    def call(self, request, *, resume_call=""):
        with ownership(self.root):
            # Preparation can perform I/O, so unresolved calls must block it too.
            events = self._read()
            pending = self._pending(events)
            intents, receipts = self._calls(events)
            resumed = intents.get(resume_call) if resume_call else None
            if resume_call:
                if resumed is None or self._recovery_fact(resume_call, resumed, events)["state"] != "not_executed":
                    _error("LEAN_UNRESOLVED_CALL", resume_call)
                permitted = {resume_call, *(key for key, row in intents.items()
                                           if row.get("parent_call_id") == resume_call)}
                if any(key not in permitted or self._recovery_fact(key, intents[key], self._read())["state"] == "unknown"
                       for key in pending):
                    _error("LEAN_UNRESOLVED_CALL", ",".join(pending))
            elif pending:
                _error("LEAN_UNRESOLVED_CALL", ",".join(pending))
            tool = request.get("tool") if isinstance(request, dict) else None
            dispatch.require_declared(self.card, tool)
            call_id = resume_call or (new_call_id() + "-" + uuid4().hex)
            marker = resumed["marker"] if resumed else call_marker(call_id)
            #: 模型说"在哪执行"（`via`）：用本步绑定的位置核对。一致就照办；不一致**不猜、不替换**，
            #: 具名回喂。位置本身是引擎写的输入（`position_*`），不是从命令文本里扫出来的。
            via = str(request.get("via") or "").strip()
            if via:
                inputs = self.task.get("inputs") or {}
                known = {str(inputs.get(key) or "") for key in
                         ("position_logical", "position_host", "position_session",
                          "target_host", "target")}
                if via not in {item for item in known if item}:
                    _error("LEAN_VIA_MISMATCH",
                           "this step runs at %s, you said %s"
                           % (next((item for item in known if item), "the bound position"), via))
            declared = deepcopy(request)
            #: `retry_of`/`retry_reason` 是**模型显式声明"我要重发哪一条"**用的，不属于任何工具的
            #: 形状：先取下来，再进指纹与派发（否则指纹会变，重复检测与工具校验都会走样）。
            retry_of = str((declared or {}).pop("retry_of", "") or "").strip()
            retry_reason = str((declared or {}).pop("retry_reason", "") or "")[:200]
            if tool == "stage":
                stage = self.card.get("stage")
                payload = stage_payload_for(self.card, self.task, declared)
                if payload and isinstance(stage, dict):
                    stage = dict(stage, payload=payload)
                declared = lean_http.stage_request(stage, declared)
            safe_request = self._safe(declared)
            #: Two digests, two jobs. The **replay identity** is over the raw request, so two
            #: requests that differ only in a secret stay two different requests (a masked copy
            #: collapses them and the runtime would refuse the second as "already ran").
            #: The **record digest** is over the copy the journal actually holds, so the ledger
            #: can recompute it and prove the row is intact -- recomputing the raw digest from a
            #: masked row can never agree (measured 2026-10-08, walk-138 node 7: the upload that
            #: carries a payload failed RECEIPT_REQUEST_DIGEST_MISMATCH).
            #: 重放身份取**逻辑请求**（去掉重试意图）：同一次操作两次尝试算同一件事，
            #: 但"这次要不要真的再发"由模型显式声明决定（见下面的 `retry_of`）。
            logical_request = ({key: value for key, value in request.items()
                                if key not in ("retry_of", "retry_reason")}
                               if isinstance(request, dict) else request)
            fingerprint = _sha(_bytes(logical_request))
            record_digest = _sha(_bytes(safe_request))
            action = None
            stage_argv = None
            if tool in ("http", "stage"):
                if str((self.session or {}).get("session_type") or "") in ("web", "entry"):
                    #: 入口位置一次只收一条命令行，而 `http`/`stage` 是**引擎在控制端**替模型发的请求：
                    #: 在这里发不出去（真机实测：反复 `LEAN_CALL_UNRESOLVED`，白烧回合）。具名拒绝，
                    #: 并说清该用什么 —— 同一条链用该侧自己的 curl/python 表达。
                    _error("LEAN_ENTRY_POSITION_COMMAND_ONLY",
                           "this position takes one command line per request (tool cmd); express this "
                           "request with the far side's own client (curl/python) instead")
                argv = lean_http.prepare(declared, self.scope, marker, self.python)
                if self.session is not None:
                    platform = str(self.session.get("platform") or "")
                    if not platform:
                        _error("LEAN_POSITION_PLATFORM_MISSING")
                    windows = platform.lower().startswith("windows")
                    text = shell_command(argv, windows=windows) + "\n"
                    if len(text.encode("utf-8")) > _inline_budget(self.session) and not windows:
                        #: One console line has a ceiling (measured 2026-10-08: ~4 KB, and going
                        #: over truncates mid-command), so a big body travels as a file instead
                        #: of as an argument: write it in bounded chunks, then call the client
                        #: with the file's contents.
                        stage_argv = argv
                    action = {"operation": "shell", "text": text,
                              "completion": {"marker": marker}}
            elif self.session is not None:
                action = dispatch.bind_console(declared, self.session, marker=marker,
                                               python=self.python, proxy=self.proxy)
                if action.get("operation") == "asset":
                    #: web 位置：命令由那条入口的客户端发出去（控制端跑这个 argv），
                    #: 引擎按配方包装并带回显。
                    from runtime import lean_web

                    argv = lean_web.command_argv(action["recipe"], action["text"], marker,
                                                 python=self.python)
                else:
                    argv = ["console", action["operation"], action["text"]]
            else:
                argv = dispatch.build(declared,
                                      platform=str((self.task.get("inputs") or {})
                                                   .get("position_platform") or ""),
                                      marker=marker, python=self.python, proxy=self.proxy)
            previous = next((key for key, row in intents.items() if row["request_digest"] == fingerprint), None)
            #: `row` below is the receipt; the request to hand back is the intent's own.
            previous_request = dict((intents.get(previous) or {}).get("request") or {})
            if resumed and resumed["request_digest"] != fingerprint:
                _error("LEAN_REPLAY_IDENTITY_CHANGED", resume_call)
            if previous and not resumed:
                if previous in receipts:
                    row = receipts[previous]
                    if retry_of and retry_of == previous:
                        #: 模型**显式**点名"我要重发这一条"并给出理由：这不是引擎替它推断出来的，
                        #: 而是一次可追责的决定 —— 记一行再发（旧回执仍在账本里，两次都看得见）。
                        #: 外部评审 2026-10-08：非零退出码不等于没有副作用、无关调用成功不等于
                        #: 前提变了，所以引擎**不自动重试**；要重发就得由模型自己声明。
                        self._append("retry", call_id=previous, reason=retry_reason,
                                     request_digest=fingerprint)
                    else:
                        # Hand back the fact that it already ran, with that observation, so the next turn
                        # asks something different (node 12 burned a whole budget re-asking one request).
                        #: `resend` hands over the object to send *as it is*: a tier that does not
                        #: re-read the note kept replaying the same request verbatim and ended the
                        #: step (measured 2026-10-08, walk-173 node 19: the plant command ran after
                        #: the upload, so the upload it needed to redo was refused four times).
                        resend = dict(previous_request)
                        resend["retry_of"] = previous
                        resend["retry_reason"] = ("<say what changed since; e.g. the file this "
                                                  "request reads now exists>")
                        note = ("the observation has not changed. If you changed the world since, ask "
                                "again with retry_of set to that call id and a short retry_reason - "
                                "that rerun is recorded. Otherwise ask a different request, or "
                                "conclude from what you already have.")
                        original_view = self._view(row)
                        self._append("refusal", refusal=self._safe({
                            "reason_code": "LEAN_CALL_ALREADY_RAN",
                            "detail": "this exact request already ran as %s" % previous,
                            "already_ran": [{"call_id": previous,
                                             "status": row.get("status"),
                                             "command_rc": row.get("command_rc"),
                                             **{name: original_view[name][:800]
                                                for name in ("stdout", "stderr")},
                                             **{name + "_chars": len(original_view[name])
                                                for name in ("stdout", "stderr")}}],
                            "note": note,
                            "resend": resend,
                        }))
                        return original_view
                else:
                    _error("LEAN_CALL_UNRESOLVED", previous)
            directory = self.root / "calls" / call_id
            deadline_at = (resumed.get("deadline_at") if resumed
                           else time.time() + float(self.timeout))
            if not isinstance(deadline_at, (int, float)) or deadline_at <= time.time():
                _error("LEAN_ACTION_DEADLINE")
            if resumed:
                self._append("recovery", call_id=call_id, state="not_executed")
            else:
                directory.mkdir(parents=True, exist_ok=False)
                self._append("intent", call_id=call_id, request_digest=fingerprint,
                             request_record_digest=record_digest, request=safe_request,
                             original_request=self._safe(logical_request), marker=marker,
                             scope=self._safe(self.scope), effect="potential_change",
                             deadline_at=deadline_at,
                             framed_required=not (bool(action) and action.get("completion") is None))
                self._append("commit", call_id=call_id, phase="before_commit")

            def transport(tokens, timeout):
                #: web 位置的那一发由**控制端**跑（入口客户端就在控制端），其余绑定的位置走控制台通道。
                asset = isinstance(action, dict) and action.get("operation") == "asset"
                if stage_argv is not None:
                    action["text"] = self._stage_body(stage_argv, marker, call_id, deadline_at)
                remaining = deadline_at - time.time()
                if remaining <= 0:
                    _error("LEAN_ACTION_DEADLINE")
                self._append("commit", call_id=call_id, phase="committing")
                outcome = (self.executor(tokens, remaining) if asset or self.session is None
                           else channels.console_call(self.session, action, remaining))
                self._append("commit", call_id=call_id, phase="after_commit")
                raw = {"stdout": outcome.stdout, "stderr": outcome.stderr}
                discovered = [value for text in (*raw.values(), outcome.tool_error or "")
                              for value in observation_secrets(text, self.card.get("secret_patterns", ()))]
                #: **原地增长**，不是重新绑定：`execute()` 拿的是这个列表对象的引用，而它在调用
                #: 返回**之后**才按它写产物 —— 重新绑定的话，产物用的还是旧表，这一发里**第一次**
                #: 出现的秘密就会被明文落盘（外部评审 2026-10-08 点出的缺口）。
                self.secrets[:] = list(collect_secrets(raw, (*self.secrets, *discovered)))
                if self.card.get("materials"):
                    self.observations[call_id] = raw
                return ExecOutcome(outcome.returncode, self._safe(outcome.stdout), self._safe(outcome.stderr),
                                   outcome.timed_out, self._safe(outcome.tool_error), outcome.read_stop)

            if tool in ("http", "stage"):
                #: 只有引擎自带客户端那条路，argv 里装的才是 JSON 请求；别的工具记**真发出的 argv**。
                #: （2026-10-07 实测：这条以前无条件设，于是每条回执都把 `cmd` 记成 http 形式 ——
                #: 账本在"我到底发了什么"这件事上说了假话，排查时被它带偏过一次。）
                transport.audit_argv = lambda _: ["lean-http-client",
                                                  json.dumps(safe_request, ensure_ascii=False)]
            transport.label = lambda: self._safe(self.executor_label)
            try:
                result = execute(argv, run_dir=self.root / "calls", skill_id=self._safe(self.card["id"]),
                                 executor=transport, call_id=call_id, timeout=deadline_at - time.time(),
                                 redactions=self.secrets)
                native = bool(action) and action.get("completion") is None
                return self._publish_receipt(call_id, marker, result, framed_required=not native)
            except Exception as error:
                # The durable intent survives even if execution or receipt publication fails.
                self._append("dispatch_error", call_id=call_id,
                             error=self._safe(type(error).__name__ + ": " + str(error)))
                return {"run_id": self.run_id, "call_id": call_id, "status": "unknown",
                        "effect": "not_verified", "reason": "LEAN_DISPATCH_UNCONFIRMED"}

