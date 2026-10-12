"""Bounded model observations and control feedback."""
from __future__ import annotations

import json

from runtime.redact import project_secrets




#: How much of one call's output the model reads. A single observation can dwarf everything else
#: it has to read - measured 2026-10-05: a step whose first action dumped the mount table and the
#: disk list answered with an *empty* completion on the next turn, twice in a row, because the
#: prompt had grown past what the provider would process. The full text stays in the call artifact,
#: so a quotation can still be checked; what the model reads is a bounded excerpt that says so.
OBSERVATION_LIMIT = 6000


#: Refusals the model may correct in-run: they say "this deployment does not offer that" (a tool the
#: card never declared, an address outside the frozen scope, a material the card does not declare).
#: They are not target results, so the model gets them back and picks again instead of losing the
#: node on its first turn.
REFUSABLE = frozenset({"LEAN_TOOL_UNDECLARED", "LEAN_TOOL_UNSUPPORTED", "LEAN_SCOPE_UNSUPPORTED",
                       #: 一次回答多个动作：默认拒收并说明形状（爷爷 2026-10-07 口径）。
                       "LEAN_ONE_ACTION_PER_ANSWER",
                       "LEAN_MATERIALS_UNDECLARED", "LEAN_MATERIAL_VALUE_UNDECLARED",
                       #: The same request twice: the model has to see what it already got.
                       "LEAN_CALL_UNRESOLVED", "LEAN_UNRESOLVED_CALL",
                       #: A secret placeholder the model glued into a longer string. Measured
                       #: 2026-10-06 (node 2): the model wrote "/password:<token> process call
                       #: create ..." as one argv item and lost the whole step; the shape is
                       #: wrong, not the plan, so it comes back with the rule spelled out.
                       "LEAN_SECRET_TOKEN_COMPOSITE", "LEAN_SECRET_TOKEN_UNKNOWN",
                       "LEAN_SECRET_TOKEN_KEY_UNSUPPORTED",
                       #: A request whose *shape* is wrong (an un-encoded request target, a body
                       #: the card's fixed step cannot carry). Measured 2026-10-06 (node 7): the
                       #: model put raw { } and " in the query string, the runtime refused the target,
                       #: and the step ended instead of the model re-asking percent-encoded.
                       "LEAN_HTTP_PATH_INVALID", "LEAN_HTTP_METHOD_UNSUPPORTED",
                       "LEAN_HTTP_REQUEST_INVALID", "LEAN_HTTP_NEEDS_ENDPOINT",
                       #: 想自己设传输层拥有的头（Host/Content-Length/…）：这是"这一问写歪了"，
                       #: 不是目标结果 —— 2026-10-06 walk-59 node 7 就死在这条上（回喂让它去掉即可）。
                       "LEAN_HTTP_HEADER_FORBIDDEN",
                       "LEAN_STAGE_REQUEST_INVALID", "LEAN_STAGE_HEADERS_INVALID",
                       "LEAN_STAGE_COOKIE_INVALID", "LEAN_STAGE_PAYLOAD_MISSING",
                       #: shell 请求的**形状**错（多塞了键、argv 不合规）：和 http/stage 那几条一样，
                       #: 是"这一问写歪了"而不是"目标怎么样"，回喂让模型改，不能整节点停掉。
                       #: 2026-10-06 walk-50/56 两次 node 2 都是被这条停住的（模型塞了 session_ref 之类的键）。
                       "LEAN_SHELL_REQUEST_INVALID", "LEAN_SHELL_ARGV_INVALID",
                       #: 扁平形状写歪了（cmd 不是非空字符串 / 太长）：回喂，别停节点。
                       "LEAN_SHELL_CMD_INVALID",
                       #: 新契约（五类）自己的代码：写歪了都回喂，别停节点。
                       "LEAN_COMMAND_MISSING", "LEAN_COMMAND_TOO_LONG", "LEAN_REQUEST_INVALID",
                       "LEAN_PWS_NEEDS_WINDOWS", "LEAN_TOOL_NAME_INVALID", "LEAN_TOOL_ARGS_INVALID",
                       "LEAN_CODE_LANG_UNSUPPORTED", "LEAN_CODE_MISSING", "LEAN_CODE_TOO_LONG",
                       #: 类与载体不一致（meterpreter 会话里发 cmd / 普通 shell 里发 msf 动词）：
                       #: 这是"选错了类"，回喂并说明该用哪一个。
                       "LEAN_TOOL_NEEDS_METERPRETER", "LEAN_MSF_NEEDS_METERPRETER_SESSION",
                       #: `via`（在哪执行）与本步绑定的位置不符：回喂并告诉它这一步在哪台机上。
                       "LEAN_VIA_MISMATCH",
                       #: 答复整个不是四种形状之一（例如少了 tool、或多了不相干的键）：
                       #: 这仍然是"这一问写歪了"，回喂并列出可用的形状，别把整节点停掉。
                       "LEAN_ACTION_UNSUPPORTED",
                      #: 输出撞满卡给的上限：这是「写太多」而不是「目标怎么样」，回喂让它只输出那个 JSON。
                       "LEAN_OUTPUT_OVER_BUDGET",
                       #: 走入口位置的一步只能一次一条命令行：`http`/`stage` 是**控制端**的工具，
                       #: 在这里发不出去 —— 回喂让它改用该侧自己的 curl/python，别把整格停掉
                       #: （2026-10-08 walk-162 node 19 实测：当成致命错误 → 首轮就死了）。
                       "LEAN_ENTRY_POSITION_COMMAND_ONLY"})
REFUSAL_LIMIT = 3

def trim_observation(event, limit=OBSERVATION_LIMIT):
    """Bound what one observation contributes to the prompt; the artifact keeps the whole thing."""
    receipt = event.get("receipt") if isinstance(event, dict) else None
    if not isinstance(receipt, dict):
        return event
    trimmed = dict(receipt)
    for name in ("stdout", "stderr"):
        text = str(trimmed.get(name) or "")
        if len(text) > limit:
            trimmed[name] = (text[:limit] +
                             "\n<truncated %d chars; the whole text is in this call's artifact>"
                             % (len(text) - limit))
    out = dict(event)
    out["receipt"] = trimmed
    return out


def call_index(events):
    """Keep every top-level call visible even when its receipt is outside the window."""
    intents = {event["call_id"]: event for event in events
               if event.get("kind") == "intent" and not event.get("parent_call_id")}
    receipts = {event["call_id"]: event["receipt"] for event in events
                if event.get("kind") == "receipt"}
    rows = []
    for call_id, intent in intents.items():
        receipt = receipts.get(call_id) or {}
        request = intent.get("original_request") or intent.get("request") or {}
        rows.append({"call_id": call_id,
                     "request": json.dumps(request, ensure_ascii=False)[:80],
                     "status": receipt.get("status", "unknown"),
                     "command_rc": receipt.get("command_rc"),
                     "read_stop": receipt.get("read_stop")})
    return rows


def fit_context(view, *, compact):
    """Spend the bounded runtime context on the ledger and selected evidence first."""
    budget = 18000 if compact else 24000
    keys = ("calls", "history", "evidence", "correction", "feedback")

    def size():
        return len(json.dumps({key: view[key] for key in keys},
                              ensure_ascii=False).encode("utf-8"))

    history, reads = view["history"], view["evidence"]
    while history and size() > budget:
        history.pop(0)
    while len(reads) > 1 and size() > budget:
        reads.pop(0)
    repair = view["correction"] or {}
    rows = repair.get("quotable_calls") or []
    while len(rows) > 1 and size() > budget:
        rows.pop(0)  # All calls remain in the ledger and are locally readable.
    for width in (40, 0):
        if size() <= budget:
            break
        for row in view["calls"]:
            row["request"] = row["request"][:width]


def show_run(card, task, run, system, *, KEEP, limit):
    """The three things one turn needs: the prompt to send, and the mapping its answer comes back in.

    The card is the knowledge and the last few observations are the context, so the same turn is
    shown at two sizes: the normal one, and - only when the provider answered nothing - a smaller
    one. Everything else about the turn (the card, the task, the scope) is identical, which is what
    makes the smaller prompt a *retry* rather than a different task.
    """
    full = [event for event in run.model_history() if event.get("kind") != "decision"]
    history = full[-KEEP:] if len(full) > KEEP else full
    if len(full) > KEEP:
        history = [{"kind": "history_trimmed", "omitted_events": len(full) - KEEP}] + history
    #: One oversized observation is enough to break the channel (see trim_observation).
    history = [trim_observation(event, limit) for event in history]
    reads = [event["evidence"] for event in full if event.get("kind") == "receipt_read"]
    refusals = [event["refusal"] for event in full if event.get("kind") == "refusal"]
    corrections = [event["feedback"] for event in full if event.get("kind") == "correction"]
    history = [event for event in history if event.get("kind") not in {"receipt_read", "correction"}]
    view, mapping = project_secrets(
        {"card": card, "task": task, "history": history, "calls": call_index(full),
         "evidence": reads[-4:] if limit > 1200 else reads[-2:],
         "correction": corrections[-1] if corrections else None,
         "feedback": refusals[-1] if refusals else None},
        secrets=run.secrets)
    fit_context(view, compact=limit <= 1200)
    return view, mapping, {"system": system, "user": json.dumps(view, ensure_ascii=False)}


def refusal_record(code, detail, card, scope):
    """Build control feedback without treating it as target evidence."""
    reason = str(code)
    note = (
        "this is control feedback, not a target result - "
        "pick a request the current card and deployment allow"
    )

    if reason == "LEAN_TOOL_UNDECLARED":
        note = (
            "the requested tool surface is not declared by the current card. "
            "Choose only from available_tools and follow the route fixed by "
            "this card, if present. Correct the offending request before "
            "submitting another action; do not resend it unchanged."
        )

    if reason.startswith("LEAN_SECRET_TOKEN"):
        # A placeholder must occupy one whole argument.
        note = (
            "a secret placeholder must be one whole argument - never glued "
            "to a prefix or to other text. Among routes allowed by the current "
            "card, pick one that takes the secret as its own argument "
            "(e.g. net use <share> /user:<user> <secret>, "
            "schtasks ... /u <user> /p <secret>, an impacket tool), "
            "or put the placeholder alone in the item."
        )

    if reason == "LEAN_HTTP_PATH_INVALID":
        note = (
            "the request target must be a relative path with the query "
            "percent-encoded - spaces, braces and quotes belong in the body, "
            "or must be encoded (e.g. %7B for {, %22 for \", "
            "%2F for a slash inside a value). Submit the corrected encoded "
            "request, not the unchanged rejected request."
        )

    if reason == "LEAN_HTTP_HEADER_FORBIDDEN":
        note = (
            "the transport owns Host / Content-Length / Transfer-Encoding / "
            "proxy-* : remove the forbidden header before resubmitting. "
            "If the service needs a particular name, put it in the URL the "
            "card gave you - never hand-set Host."
        )

    if reason == "LEAN_ACTION_UNSUPPORTED":
        # These are syntax examples, not additional tool permissions.
        note = (
            "the following examples describe syntax only. Select only a "
            "tool surface allowed by the current card; for a card-fixed "
            "stage, use its separately supplied action shape. "
            'answer with exactly one of: '
            '{"tool":"cmd","via":"<position>","cmd":"<one command>"}, '
            '{"tool":"msf","via":"<position>","cmd":"<meterpreter verb>"}, '
            '{"tool":"pws","via":"<position>","cmd":"<powershell>"}, '
            '{"tool":"tool","name":"<program>","via":"<position>","args":[…]} '
            '(or "cmd":"<arguments>"), '
            '{"tool":"code","name":"python","via":"<position>",'
            '"code":"<program>"}, '
            '{"tool":"http","method":"GET","path":"/x",'
            '"headers":{},"body":""}, '
            '{"tool":"finish","claim":"<conclusion>",'
            '"verdict":"pass|unsatisfied|uncertain",'
            '"citations":[{"call_id":"…","quote":"…","stream":"stdout"}]}. '
            "No other keys, no prose."
        )

    if reason == "LEAN_CALL_ALREADY_RAN":
        note = (
            "a duplicate submission was intercepted. Do not submit this "
            "unchanged request again. Inspect the referenced original call "
            "and its recorded state: if rejected before dispatch, correct "
            "the refusal according to the current card; if completed, use "
            "the recorded result; if unresolved, no further dispatch or "
            "retry is allowed. This code alone does not establish that "
            "the target action executed or completed."
        )

    if reason in {"LEAN_CALL_UNRESOLVED", "LEAN_UNRESOLVED_CALL"}:
        note = (
            "a call's outcome is unknown; no further dispatch or retry is "
            "allowed. abandon only records local stop-waiting; it does "
            "not settle the call. Finish with uncertain or unsatisfied; "
            "pending calls remain in the result."
        )

    contract_note = (
        "Tool examples describe syntax only; they never expand "
        "available_tools. Use only the current card's declared tool "
        "surfaces and assets bound to this step. Follow any route fixed "
        "by this card; do not substitute another card's route or an "
        "undeclared script surface. Do not resubmit an unchanged rejected "
        "request. This feedback is not target evidence: do not infer "
        "unsatisfied solely from a refusal or duplicate interception."
    )

    return {
        "reason_code": code,
        "detail": str(detail)[:220],
        "available_tools": list(card.get("tools") or []),
        "scope": {
            "vantage": scope.get("vantage"),
            "host": scope.get("host"),
        },
        "note": note + " " + contract_note,
    }
