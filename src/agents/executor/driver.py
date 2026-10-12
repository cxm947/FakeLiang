"""The single-task action and conclusion loop."""
from __future__ import annotations

from pathlib import Path

from agents._model.contract import EMPTY_CONTENT_ERROR, TRUNCATED_ERROR
from runtime import artifacts, model_log
from runtime.lean import LeanRun, collect_secrets, mask_secrets
from skills import lean as card_reader
from agents.executor.action import flat_action, restore_action
from agents.executor.input import validate_task
from agents.executor.observation import (
    OBSERVATION_LIMIT, REFUSABLE, REFUSAL_LIMIT, refusal_record, show_run,
)
from agents.executor.prompts import (
    SYSTEM, STAGE_HINT, CORRECTION_HINT, UNRESOLVED_HINT, SHORT_KEEP,
    SHORT_OBSERVATION_LIMIT, COMPACT_AFTER_TRUNCATION, budget_hint,
)



def drive(card, task, scope, executor, *, actions=None, client=None, run_dir, python="python3",
          timeout=30, max_steps=8, model_timeout=60, secrets=(), channel=None, private_result=False,
          proxy=(), feedback=None, recover=False):
    """One frozen lean run: scripted actions or the model, then the model's own report.

    The node entry (`scripts/run_node.py`) calls this with the card and the scope
    it already selected, so the two entries cannot drift apart. The planner requests a
    private result to interpret control values before masking its persisted summary.
    """
    # Only the run's own inputs are secret sources; the card is documentation (see LeanRun).
    secrets = collect_secrets({"task": task, "actions": actions, "channel": channel,
                               "scope": scope}, secrets)
    native_session = None
    result = {"status": "uncertain", "reason": "LEAN_ACTIONS_EXHAUSTED"}
    try:
        if (actions is None and getattr(client, "backend", "legacy") != "native"
                and (Path(run_dir) / "native_tools.jsonl").exists()):
            raise ValueError("MODEL_BACKEND_CHANGED")
        validate_task(card, task)
        run = LeanRun(run_dir=Path(run_dir), card=card, task=task, scope=scope, executor=executor,
                      python=python, timeout=timeout, secrets=secrets, proxy=proxy,
                      session=channel)
        recovered_conclusion = None
        if recover:
            facts = run.recover_calls()
            if any(item["state"] == "unknown" for item in facts):
                raise ValueError("LEAN_RECOVERY_UNKNOWN")
            from runtime.lean_journal import _bytes, _sha
            intents, _receipts = run._calls(run._read())
            for item in facts:
                if item["state"] != "not_executed" or item.get("parent_call_id"):
                    continue
                intent = intents[item["call_id"]]
                original = intent.get("original_request")
                if not isinstance(original, dict) or _sha(_bytes(original)) != intent["request_digest"]:
                    raise ValueError("LEAN_RECOVERY_ASSOCIATION_LOST")
                view = run.call(original, resume_call=item["call_id"])
                if view.get("status") != "completed_transport":
                    raise ValueError("LEAN_RECOVERY_UNKNOWN")
            history = run._read()
            conclusions = [item for item in history if item.get("kind") == "conclusion"]
            if conclusions:
                candidate = conclusions[-1]
                later = [item for item in history if item["seq"] > candidate["seq"]
                         and item.get("kind") in {"intent", "decision"}]
                value = candidate.get("result") or {}
                if not later and value.get("status") == "model_reported" and not (
                        value.get("pending_calls") or value.get("rejections")):
                    recovered_conclusion = value
        if feedback:
            run.record_refusal(dict(feedback))
        if actions is None and getattr(client, "backend", "legacy") == "native":
            from agents.executor.native_tools import NativeSession
            native_session = NativeSession(client, run)
            client = native_session
        correction = None
        corrections = {}
        refusals = 0
        #: 撞满一次之后就一直用小视图：见 COMPACT_AFTER_TRUNCATION。
        compact = False
        #: 回合预算：全局上限与卡的预算取小的那个 —— 卡说这张最多几回合是产品约束，
        #: 借 H-mmer/pentest-agents 的 maxTurns 思路（2026-10-06 查过）。
        turns = min(int(max_steps), card_reader.max_turns_of(card))
        if recovered_conclusion is not None:
            result = recovered_conclusion
            turns = 0
        step, action_index, evidence_reads = -1, 0, 0
        while step + 1 < turns:
            step += 1
            if actions is not None:
                if action_index >= len(actions):
                    break
                action = actions[action_index]
                run.record_decision({"source": "actions", "index": action_index}, action)
                action_index += 1
                action = flat_action(restore_action(action, {}), scope)
            else:
                # Recent history only: the card is the knowledge, the last few observations are the
                # context. Sending the whole run every turn grew the prompt past 45 KB and the
                # provider started answering with empty completions; the receipts stay on disk for
                # citation checking, so nothing verifiable is lost by trimming what is *shown*.
                secrets = run.secrets
                system = SYSTEM + ("\n" + STAGE_HINT if card.get("stage") else "")
                system = system + budget_hint(step, turns)
                system += "\nLocal saved-evidence reads may precede the required conclusion without using an action turn.\nSaved receipt reads remaining: %d of 8." % (8 - evidence_reads)
                if correction is not None:
                    system = system + "\n" + (UNRESOLVED_HINT
                                              if correction.get("reason") == "LEAN_UNRESOLVED_CALL"
                                              else CORRECTION_HINT)
                view, mapping, prompt = show_run(
                    card, task, run, system,
                    KEEP=SHORT_KEEP if compact else 12,
                    limit=SHORT_OBSERVATION_LIMIT if compact else OBSERVATION_LIMIT)
                #: 输出上限（爷爷 2026-10-06 口径：用 effort=none、**别掐 token 量**）。
                #: 只有卡**显式**声明 output_budget 时才带上限；没声明就一个字段都不发，
                #: 交给供应商自己的默认/硬上限 —— 这条线上思考关不掉，且推理与正文共享同一个上限，
                #: 掐上限的结果是"思考吃光预算、正文 0 字节"（walk-58 node 7/19）。
                ceiling = int(card.get("output_budget") or 0) or None
                if client is None or not client.available():
                    raise ValueError("LEAN_MODEL_UNAVAILABLE")
                reply = client.complete(task="lean_action", **prompt, timeout=model_timeout,
                                        #: 一次重试只能修「供应商回空」或传输错误；答案写错不会因为重试而变对。
                                        retries=4, max_tokens=ceiling)
                if not reply.ok and str(reply.error or "").startswith(EMPTY_CONTENT_ERROR):
                    # The same prompt answered nothing (measured 2026-10-06: one node lost five
                    # minutes to five identical empty completions). The provider is spending its
                    # budget on *this* question, so the retry asks a smaller one: fewer events,
                    # shorter observations. A different prompt is the only retry that can change
                    # the answer; the first failure stays in the model log, not hidden.
                    model_log.record(run_dir, task="lean_action", source="lean_deform",
                                     metadata=mask_secrets(reply.to_json(), secrets))
                    view, mapping, prompt = show_run(card, task, run, system, KEEP=SHORT_KEEP,
                                                     limit=SHORT_OBSERVATION_LIMIT)
                    reply = client.complete(task="lean_action", **prompt, timeout=model_timeout,
                                            retries=2)
                #: 原地增长（同 `LeanRun.call`）：执行器与后续写产物都按同一个列表对象取值。
                run.secrets[:] = list(collect_secrets(reply.payload, run.secrets))
                secrets = run.secrets
                model_log.record(run_dir, task="lean_action", source="lean",
                                 metadata=mask_secrets(reply.to_json(), secrets))
                run.record_decision(prompt, {"text": reply.text, "ok": reply.ok,
                                             "error": reply.error})
                if (not reply.ok and str(reply.error or '').startswith(TRUNCATED_ERROR)
                        and refusals < REFUSAL_LIMIT):
                    #: 撞满卡给的输出上限 = 写太多（大部分是解释），不是目标结果：回喂一次，让它只输出那个 JSON。
                    #: 同一上限重试，**不自动加倍** —— 上限是产品约束，不是「再问一次也许能写完」的起点。
                    refusals += 1
                    refusal = refusal_record('LEAN_OUTPUT_OVER_BUDGET',
                                             'answer hit the deployment output ceiling (%s tokens)'
                                             % (int(reply.max_tokens) if reply.max_tokens else "provider's own"),
                                             card, scope)
                    refusal['hint'] = ('Output ONLY the one JSON object, under 1000 characters: no '
                                       'prose, no plan, no notes. If the command needs a long '
                                       'program, upload it as a file (the card\'s stage step, or a '
                                       'short upload command) and let the command line name that '
                                       'file - never inline it.')
                    run.record_refusal(refusal)
                    if COMPACT_AFTER_TRUNCATION:
                        compact = True
                    continue
                if not reply.ok or not isinstance(reply.payload, dict):
                    #: 撞满三次仍写不完时，别用「答复不可用」收场 —— 那句话读起来像"模型没答"，
                    #: 真相是"它一直在写超预算的东西"。具名给读者看（walk-58 node 7 实测）。
                    if not reply.ok and str(reply.error or '').startswith(TRUNCATED_ERROR):
                        raise ValueError(
                            'LEAN_OUTPUT_OVER_BUDGET: the answer stayed over the card budget '
                            '(%s) after %d tries'
                            % (int(reply.max_tokens) if reply.max_tokens else "provider's own",
                               refusals))
                    raise ValueError('LEAN_MODEL_REPLY_UNAVAILABLE')
                try:
                    #: 先翻译扁平形状，再还原秘密占位符：`restore_action` 对 `finish` 的引文有
                    #: 专门的处理（引文里可以整段包含占位符），而扁平 `finish` 只有在翻译之后
                    #: 才认得出来。顺序反了会把一句合法引文判成"占位符拼进了别的字串"。
                    action = restore_action(
                        native_session.native_action(reply) if native_session is not None
                        else flat_action(reply.payload, scope), mapping)
                    if native_session is not None:
                        native_session.accept(action)
                except ValueError as error:
                    # A mangled secret placeholder is a *shape* mistake, not a plan: the model
                    # glued the token into a longer argument and lost the whole step (measured
                    # 2026-10-06, node 2). Hand it back with the rule, exactly like a refused tool.
                    code = str(error).split(":", 1)[0].strip()
                    if code in REFUSABLE and refusals < REFUSAL_LIMIT:
                        refusals += 1
                        run.record_refusal(refusal_record(code, str(error), card, scope))
                        continue
                    raise
            if action.get("kind") == "evidence":
                if evidence_reads >= 8:
                    run.record_refusal({"reason_code": "LEAN_EVIDENCE_READ_LIMIT",
                                        "note": "No more local reads; finish from supplied text or report uncertain."})
                    continue
                evidence_reads += 1
                step -= 1
                try:
                    if set(action) - {"kind", "call_id", "stream", "start", "limit", "contains"}:
                        raise ValueError("LEAN_EVIDENCE_REQUEST_INVALID")
                    run.read_evidence(**{key: value for key, value in action.items() if key != "kind"})
                except (ValueError, OSError, TypeError) as error:
                    run.record_refusal({"reason_code": "LEAN_EVIDENCE_READ_REFUSED",
                                        "detail": mask_secrets(str(error), run.secrets),
                                        "note": "No target action was sent. Finish honestly if evidence is unavailable."})
                continue
            if action.get("kind") == "abandon":
                # Extra actions are ignored; abandonment cannot authorize their dispatch.
                extra = sorted(set(action) - {"kind", "call_id", "reason"})
                if extra:
                    run.record_refusal({
                        "reason_code": "LEAN_ABANDON_HAS_EXTRA_KEYS",
                        "detail": "local stop-waiting for %s; ignored keys: %s"
                                  % (action.get("call_id"), ", ".join(extra)),
                        "available_tools": list(card.get("tools") or []),
                        "note": "no extra action was sent; abandonment does not settle an unknown call."})
                run.record_abandon(action.get("call_id"), action.get("reason"))
                result = {"status": "uncertain", "reason": "LEAN_TASK_NOT_CONCLUDED"}
                continue
            if (action.get("kind") == "call" and set(action) == {"kind", "request"}) or (
                    action.get("kind") == "call_batch"
                    and set(action) <= {"kind", "requests", "gap", "abandons"}
                    and isinstance(action.get("requests"), list) and action["requests"]):
                if correction is not None:
                    # "Only the claim and the citations may change" is enforced, not just stated:
                    # letting this turn touch the target would make the sentence untrue.
                    run.record_decision({"source": "correction", "note": "call refused"},
                                        {"text": "a call is not available in a correction turn",
                                         "ok": False})
                    if native_session is not None:
                        run.record_refusal({
                            "reason_code": "LEAN_ACTION_UNSUPPORTED",
                            "note": "No target call is allowed in a correction turn."})
                    continue
                try:
                    if action.get("kind") == "call":
                        #: 单块照旧走原来那条路（一块的行为一点没变）。
                        requests = [action["request"]]
                        receipt_views = [run.call(action["request"])]
                    else:
                        # Record local stop-waiting; unresolved calls still block this batch.
                        for item in action.get("abandons") or []:
                            run.record_abandon(item.get("call_id"), item.get("reason"))
                        #: 动作批次：一块一条调用，中间由引擎歇一下（`gap` 可由模型给）。
                        requests = list(action["requests"])
                        receipt_views = run.call_many(requests, gap=action.get("gap"))
                    receipt = receipt_views[-1]
                    #: 这一条已执行：它改过场子的话，记进产物表（模型下发的动作只能"声明"级记录，
                    #: 回收时仍会列给人看）。认不出的动词不写行，不假装记全了。
                    for sent, view in zip(requests, receipt_views):
                        try:
                            artifacts.declare_from_call(
                                run_dir, sent, node=str(task.get("node_id") or ""),
                                host=str((scope or {}).get("host") or ""),
                                evidence=str(view.get("call_id") or ""))
                        except (ValueError, OSError):
                            pass
                except ValueError as error:
                    # "You asked for something this deployment does not offer" is a *refusal*, not a
                    # target failure: hand it back with what is allowed and let the model pick again,
                    # instead of ending the node on its first turn (measured 2026-10-06, node 5).
                    code = str(error).split(":", 1)[0].strip()
                    if code in REFUSABLE and refusals < REFUSAL_LIMIT:
                        refusals += 1
                        refusal = refusal_record(code, mask_secrets(str(error), run.secrets),
                                                 card, scope)
                        if code == "LEAN_CALL_UNRESOLVED":
                            # The note is in refusal_record; what only this site knows is *which*
                            # observations to hand over.
                            receipts = [event["receipt"] for event in run.model_history()
                                        if event.get("kind") == "receipt"][-3:]
                            refusal["already_ran"] = [
                                {"call_id": r.get("call_id"),
                                 "stdout": str(r.get("stdout") or "")[:240]} for r in receipts]
                        if code == "LEAN_UNRESOLVED_CALL":
                            pending = [part for part in
                                       str(error).split(":", 1)[-1].strip().split(",") if part]
                            refusal["unresolved"] = pending
                        run.record_refusal(refusal)
                        continue
                    raise
                secrets = run.secrets
                result = {"status": "uncertain", "reason": "LEAN_TASK_NOT_CONCLUDED",
                          "last_receipt": receipt, "receipts": receipt_views}
            elif action.get("kind") == "finish" and not set(action) - {"kind", "claim",
                                                                         "citations",
                                                                         "claimed_verdict", "materials"}:
                # Honest non-success may end locally without requesting further actions.
                handover_owed = (action.get("claimed_verdict") == "pass"
                                 and callable(getattr(run, "delivery_pending", None))
                                 and run.delivery_pending())
                if handover_owed and refusals < REFUSAL_LIMIT:
                    refusals += 1
                    run.record_refusal({
                        "reason_code": "LEAN_DELIVERY_NOT_ISSUED",
                        "detail": "this step declares a session hand-over and its delivery has not been run",
                        "available_tools": list(card.get("tools") or []),
                        "note": "run the delivery command this step was handed (it plants and starts "
                                "the stager), then report the delivery receipts honestly. The "
                                "runtime receives and registers the session after your report."})
                    continue
                try:
                    result = run.conclude(action.get("claim"), action.get("citations"),
                                          action.get("claimed_verdict"), action.get("materials"))
                except ValueError as error:
                    code = str(error).split(":", 1)[0].strip()
                    if code != "LEAN_TOOL_UNDECLARED" or refusals >= REFUSAL_LIMIT:
                        raise
                    refusals += 1
                    run.record_refusal(refusal_record(
                        code, mask_secrets(str(error), run.secrets), card, scope))
                    continue
                if (result.get("reason") == "LEAN_UNRESOLVED_CALL"
                        and action.get("claimed_verdict") in {"uncertain", "unsatisfied"}):
                    break
                if str(result.get("reason") or "") in {
                        "LEAN_CITATION_INVALID", "LEAN_MARKER_MISSING",
                        "LEAN_UNRESOLVED_CALL"}:
                    reason = str(result.get("reason"))
                    #: ??????????**"??????"????** ?? ????????
                    #: ????????????????2026-10-08 walk-165 node 2????????
                    #: ???????????????????????
                    allowance = 3 if reason == "LEAN_UNRESOLVED_CALL" else 1
                    if corrections.get(reason, 0) < allowance:
                        corrections[reason] = corrections.get(reason, 0) + 1
                        correction = {"reason": reason,
                                      "rejected": list(result.get("rejections") or []),
                                      "quotable_calls": run.citation_index()}
                        run.request_correction(correction)
                        continue
                break
            else:
                #: 答复不是那四种形状之一：回喂一次并**把形状列出来**，别整节点停住
                #: （2026-10-06 walk-61 node 14/30：命令跑成了，结论写歪一次，节点就没了）。
                if refusals < REFUSAL_LIMIT:
                    refusals += 1
                    run.record_refusal(refusal_record(
                        "LEAN_ACTION_UNSUPPORTED",
                        "the answer was not one of the accepted shapes", card, scope))
                    continue
                raise ValueError("LEAN_ACTION_UNSUPPORTED")
        else:
            if recovered_conclusion is None:
                result = {"status": "uncertain", "reason": "LEAN_STEP_LIMIT"}
    except (ValueError, OSError, RuntimeError) as error:
        result = {"status": "uncertain", "reason": mask_secrets(str(error), secrets)}
        #: An aborted execution has to say why on disk: the fact gate downstream overwrites the
        #: status, so an exception that only lives in the result looks like a plain
        #: "unconfirmed" (measured 2026-10-08, walk-122/123 node 7: the stage dispatch
        #: aborted with nothing recorded anywhere).
        try:
            if "run" in locals():
                run._append("lane_error", reason=result["reason"])
        except Exception:  # noqa: BLE001 - reporting why must never break execution
            pass
    if native_session is not None:
        try:
            native_session.close()
        except (ValueError, OSError, RuntimeError) as error:
            result = {"status": "uncertain",
                      "reason": mask_secrets(str(error), secrets)}
    if private_result:
        settled = False
        if "run" in locals():
            try:
                settled = not run._pending(run._read())
            except (AttributeError, ValueError, OSError, RuntimeError):
                pass
        code = str(result.get("reason") or "").split(":", 1)[0]
        correctable = (settled and not result.get("pending_calls") and not result.get("rejections") and
                       (code in {"LEAN_MODEL_REPLY_UNAVAILABLE", "LEAN_TASK_NOT_CONCLUDED",
                                 "LEAN_STEP_LIMIT"} or
                        (result.get("status") == "model_reported" and
                         result.get("claimed_verdict") in {"pass", "uncertain"})))
        return dict(result, correctable=bool(correctable))
    return mask_secrets(result, secrets)
