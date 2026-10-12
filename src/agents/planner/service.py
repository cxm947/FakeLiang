"""Planning: pick the next node from the graph, the done ledger and the last outcome."""
from __future__ import annotations

import json

from orchestration.graph_view import graph_nodes
from orchestration.verification.assessment import _fact_assessment


def next_node(document, state, *, decided=()):
    """Compatibility entry point: choosing a node requires the model planner."""
    raise PlannerFailure("PLANNER_MODEL_REQUIRED")


#: What the planner is asked for. It reads the graph and the walk's own records; the program never
#: hands it a shortlist, because computing one is how the graph's own OR/AND meaning got re-written
#: in code and read differently from the graph.
from .prompts import WALK_SYSTEM as PLANNER_SYSTEM


class PlannerFailure(ValueError):
    """A named planning failure; it never requests a graph-order fallback."""

    def __init__(self, reason_code, detail="", *, refusals=()):
        self.reason_code = str(reason_code)
        self.detail = str(detail)
        self.refusals = [dict(row) for row in refusals]
        super().__init__(self.reason_code + (": " + self.detail if self.detail else ""))


def choice_refusal(document, node_id, state, *, host_map=None):
    """Check the requested attempt without computing a list of selectable nodes."""
    from graph import criteria as graph_criteria

    text = str(node_id or "").strip()
    node = next((item for item in graph_nodes(document)
                 if str(item.get("id")) == text), None)
    if node is None:
        return {"reason_code": "node_unknown",
                "detail": "no execution node " + (text or "<empty>")}
    if text in state:
        return {"reason_code": "node_already_decided",
                "detail": "node %s was already dispatched" % text}

    missing = []
    for fact in graph_criteria.node_criteria(document, text):
        assessment = _fact_assessment(document, fact["ref"], state, host_map=host_map)
        verdict = assessment["verdict"]
        if fact["type"] == "OR" and verdict != "TRUE":
            missing.append({"ref": fact["ref"], "verdict": verdict,
                            #: **这个缺口由谁产出**：调度要知道"换谁做"，不然它会连着提几个
                            #: 前提都不满足的节点、把尝试耗光（2026-10-08 walk-167：48 之后
                            #: 模型连提 28/22/19，却没人告诉它 29 是节点 30 产的）。
                            "producible_by": [str(item) for item in fact.get("produced_by") or []],
                            "fact": str(fact.get("fact") or "")})
        elif verdict in ("FALSE", "UNRESOLVED_CONFLICT"):
            missing.append({"ref": fact["ref"], "verdict": verdict,
                            "producible_by": [str(item) for item in fact.get("produced_by") or []],
                            "fact": str(fact.get("fact") or "")})
    if missing:
        return {"reason_code": "fact_unavailable",
                "detail": "the requested attempt has an unavailable dependency",
                "facts": missing}
    return None


def planner_handoffs(state, order):
    """Report dispatched steps that did not finish."""
    out = []
    for node_id in order:
        row = state.get(str(node_id)) or {}
        if row.get("status") == "proved":
            continue
        reason = str(row.get("reason") or row.get("status") or "did not finish")
        out.append({"node_id": str(node_id), "status": str(row.get("status") or ""),
                    "reason_codes": [reason[:120]], "summary": reason[:300]})
    return out


def planner_board(document, state, *, run_id, order, handoffs=(), host_map=None):
    """Five-field planner input; done means successful steps only (bridge patch, applied verbatim)."""
    from graph import criteria as graph_criteria

    #: 爷爷 2026-10-08："已完成节点 + 成败情况"。所以 done 收的是**已尝试过**的步骤及结果，
    #: 不只是成功的那几个 —— 否则模型看不见历史失败，会反复提同一个已经做过的步骤。
    done = []
    for node_id in sorted(str(key) for key in state):
        row = state.get(node_id) or {}
        status = row.get("status")
        if status == "proved":
            done.append({"node_id": node_id, "status": "success"})
        elif status in ("blocked", "blocked_upstream"):
            done.append({"node_id": node_id, "status": "blocked",
                         "reason": str(row.get("reason") or "").strip() or "the step was blocked"})
        else:   # failed / unconfirmed / stopped / selected：派发过但没成功，如实记失败
            done.append({"node_id": node_id, "status": "failed",
                         "reason": str(row.get("reason") or "").strip() or "the step was not confirmed"})
    if order and str(order[-1]) not in {item["node_id"] for item in done}:
        #: 派发过、运行态却没落行的步骤：如实记一次未确认，别让输入自相矛盾。
        done.append({"node_id": str(order[-1]), "status": "failed",
                     "reason": "the step was not confirmed"})
    last_id = str(order[-1]) if order else None
    last_step = None
    if last_id is not None:
        last = state.get(last_id) or {}
        status = ("success" if last.get("status") == "proved" else
                  "blocked" if last.get("status") == "blocked" else "failed")
        last_step = {"node_id": last_id, "status": status}
        if status != "success":
            last_step["reason"] = str(last.get("reason") or "").strip() or (
                "the step was blocked" if status == "blocked"
                else "the step was not confirmed")

    goal = [str(item) for item in (document.get("final_goal") or [])]
    steps = []
    for node in graph_nodes(document):
        node_id = str(node["id"])
        needs = [str(item.get("ref")) for item in (node.get("dependencies") or [])]
        try:
            produces = [str(item.get("ref", item)) if isinstance(item, dict) else str(item)
                        for item in graph_criteria.to_produce(document, node_id)]
        except Exception:  # noqa: BLE001 - 缺产出声明时如实留空，不编造
            produces = []
        steps.append({"node_id": node_id, "needs": needs, "produces": produces})
    return {"graph": {"goal": goal, "steps": steps},
            "run_id": str(run_id), "done": done, "last_step": last_step,
            "handoffs": [dict(item) for item in handoffs]}


def _planner_user(parsed_input, refusals):
    """Include named refusals without inventing replacement choices."""
    text = json.dumps(parsed_input, ensure_ascii=False)
    if refusals:
        text += ("\n\nThe program refused your previous answer(s):\n"
                 + json.dumps(refusals, ensure_ascii=False) + "\nChoose again or stop.")
    return text


def plan_next(*, document, state, order, run_id, client=None, attempts=3,
              handoffs=(), timeout=90.0, trace=None, host_map=None,
              graph_state=None, save_state=None):
    """Ask the model, validate its answer, and fail explicitly when planning fails."""
    from . import io as planner_io

    available = getattr(client, "available", False)
    try:
        available = available() if callable(available) else bool(available)
    except Exception as error:
        raise PlannerFailure("PLANNER_MODEL_UNAVAILABLE", str(error)) from error
    if not available or not callable(getattr(client, "complete", None)):
        raise PlannerFailure("PLANNER_MODEL_UNAVAILABLE")
    if type(attempts) is not int or attempts < 1:
        raise PlannerFailure("PLANNER_ATTEMPTS_INVALID")
    # Legacy nudge threshold; faults/refusals share at most four calls.
    attempts = min(attempts, 3)

    try:
        parsed = planner_io.parse_plan_input(
            planner_board(document, state, run_id=run_id, order=order,
                          handoffs=handoffs, host_map=host_map))
    except ValueError as error:
        raise PlannerFailure("PLANNER_INPUT_REFUSED", str(error)) from error

    scenario, payload = parsed["scenario"], parsed["input"]
    refusals = []
    nudged = False
    controlled = graph_state is not None
    graph_state = graph_state if controlled else {}
    graph_state['cell'] = 'planner'
    counts = graph_state.setdefault('attempts', {}).setdefault('planner', {})
    key = str(len(order))
    counts.setdefault(key, 0)
    saved = graph_state.get("planner_pending") or {}
    same_call = saved.get("dispatch") == key and bool(saved.get("counted"))
    if saved.get("dispatch") == key:
        refusals = list(saved.get("refusals") or [])
        nudged = bool(saved.get("nudged"))
    _bonus = int(saved.get("bonus") or 0) if saved.get("dispatch") == key else 0

    def persist(counted):
        graph_state["planner_pending"] = {
            "dispatch": key, "counted": counted, "refusals": refusals,
            "nudged": nudged, "bonus": _bonus}
        if save_state is not None:
            save_state(graph_state)

    if counts[key] >= attempts + 1:
        #: 该派发点的提案机会已经用尽：恢复入口不能刷新额度，第二次进来同样报死。
        raise PlannerFailure("PLANNER_ATTEMPTS_EXHAUSTED")
    while same_call or counts[key] < attempts + 1:
        if not same_call and counts[key] >= attempts:
            #: 合同（爷爷 2026-10-08）：模型连着提"前置没满足"的步骤时，把"现在就能做的"
            #: 明确回喂一次，只有真的没有可执行的才允许把整轮判死。
            if _bonus:
                break
            executable = [str(item.get("id")) for item in graph_nodes(document)
                          if str(item.get("id")) not in state
                          and choice_refusal(document, str(item.get("id")), state,
                                             host_map=host_map) is None]
            if not executable:
                break
            _bonus = 1
            nudged = True
            refusals.append({
                "reason_code": "PLANNER_RETRY_EXECUTABLE",
                "detail": "the answers named steps whose premises are not satisfied yet",
                "executable_now": executable,
                "note": "these steps have every premise satisfied and were never attempted: "
                        "choose one of them, or stop only if none of them is the right move."})
        if not same_call:
            counts[key] += 1
        same_call = False
        persist(True)
        try:
            reply = client.complete(
                task="pick_next_node", system=PLANNER_SYSTEM,
                user=_planner_user(payload, refusals), timeout=timeout)
        except (ValueError, OSError, RuntimeError) as error:
            if str(error).startswith("MODEL_CALL_UNKNOWN"):
                raise PlannerFailure("PLANNER_CALL_UNKNOWN") from error
            refusals.append({"reason_code": "PLANNER_CALL_FAILED", "detail": str(error)})
            persist(False)
            continue
        if trace is not None:
            serialise = getattr(reply, "to_json", None)
            trace({"task": "pick_next_node",
                   "reply": serialise() if callable(serialise) else {
                       "ok": bool(getattr(reply, "ok", False)),
                       "payload": getattr(reply, "payload", None),
                       "error": str(getattr(reply, "error", "") or "")},
                   "refused": list(refusals[-1:])})

        if not getattr(reply, "ok", False) or not isinstance(getattr(reply, "payload", None), dict):
            refusals.append({"reason_code": "planner_unreadable",
                             "detail": str(getattr(reply, "error", "") or
                                           "the answer was not one JSON object")})
            continue
        try:
            answer = planner_io.parse_plan_output(reply.payload, scenario=scenario)
        except planner_io.PlannerIOError as error:
            refusals.append({"reason_code": "planner_shape_invalid", "detail": str(error)})
            continue

        if answer["decision"] == "done":
            #: 合同检查：还有"可执行且从未尝试"的必做步骤时不许收线（回喂一次剩余清单）；
            #: 模型坚持要停就接受，但如实记为"模型放弃"，而不是"没有可执行的"。
            remaining = [str(item.get("id")) for item in graph_nodes(document)
                         if str(item.get("id")) not in state
                         and choice_refusal(document, str(item.get("id")), state,
                                            host_map=host_map) is None]
            if remaining and (controlled or not nudged):
                nudged = True
                refusals.append({
                    "reason_code": "WALK_NOT_EXHAUSTED",
                    "detail": "stopping while steps are still executable and never attempted",
                    "remaining": remaining,
                    "note": "done means nothing is executable any more. Attempt one of these steps "
                            "first, then decide."})
                continue
            return None, {"source": "model", "chosen": "",
                          "stop_reason": "model_gave_up" if remaining else "no_executable_work",
                          "note": answer.get("change_note") or "the model stopped scheduling",
                          "refusals": list(refusals)}

        chosen = answer["next_node_id"]
        refusal = choice_refusal(document, chosen, state, host_map=host_map)
        if refusal is not None:
            refusals.append(dict(refusal, node_id=chosen))
            continue
        node = next(item for item in graph_nodes(document)
                    if str(item.get("id")) == chosen)
        return node, {"source": "model", "chosen": chosen,
                      "note": answer.get("change_note") or "",
                      "refusals": list(refusals)}

    raise PlannerFailure("PLANNER_ATTEMPTS_EXHAUSTED",
                         "the model did not provide an acceptable answer",
                         refusals=refusals)
