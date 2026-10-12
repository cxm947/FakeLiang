"""The walk: one step holds one attempt, the loop holds the round."""
from __future__ import annotations

import json
import time
from uuid import uuid4
from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from typing import Callable

from runtime import credentials as credential_ledger
from runtime import assets, msfservice, session_registry, sessions, tunnel
from graph import criteria as graph_criteria
from runtime.lean import collect_secrets, mask_secrets
from runtime import recovery
from runtime.recovery import digest, safe_data, parent_binding, restore_parent, recover_relay
from runtime.session_delivery import (
    cancel_session_delivery,
    undo_relay_delivery,
)
from skills import bind

from . import delivery_setup, positions, preparation
from agents.planner import service as planning
from . import reporting, session_flow
from .contracts import (
    CredentialInputs,
    DeliveryState,
    ReasonEvent,
    StepLimits,
    StepResult,
    WalkResult,
)
from .graph_view import graph_nodes
from .verification import assessment
from agents.verifier import service as checking




ATTEMPT_LIMIT = 4
CELLS = ("planner", "precheck", "execute", "reconcile", "verify", "session", "wrapup")


def enter_cell(state, cell, node_id):
    state["cell"] = cell
    if cell in {"precheck", "execute", "verify", "session"}:
        counts = state.setdefault("attempts", {}).setdefault(cell, {})
        counts[node_id] = counts.get(node_id, 0) + 1


def execute_count(state, node_id):
    return state.get("attempts", {}).get("execute", {}).get(node_id, 0)


def exhausted(state, node_id):
    rows = state.setdefault("exhausted_nodes", [])
    if node_id not in rows:
        rows.append(node_id)


def run_step(
    *,
    node: dict,
    document: dict,
    root: Path,
    repository: Path,
    host_map: dict,
    host_environments: dict,
    executor,
    executor_host: str,
    client,
    control: str,
    rpc_conf: dict,
    credentials: CredentialInputs,
    limits: StepLimits,
    secrets: list[str],
    prepare_task: Callable,
    drive: Callable,
    record_step: Callable[[StepResult], None],
    graph_state: dict | None = None,
    save_state=None,
) -> StepResult:
    state = graph_state if graph_state is not None else {}
    node_id = str(node.get("id"))
    durable = save_state is not None
    active = state.get("active_step") if durable else None
    recovering = bool(active and active.get("node_id") == node_id)
    if not recovering:
        active = {"node_id": node_id, "phase": "", "entered": [], "done": []}
    if durable:
        state["active_step"] = active
    run_dir = root / ("node" + node_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    reasons: list[ReasonEvent] = []

    def remember(stage, reason, detail=""):
        if reason:
            reasons.append(
                ReasonEvent(stage, str(reason), str(detail or ""))
            )

    def finish(row):
        # 只在这里提交本步；兼容 reason 与完整原因轨迹分别保存。
        trace = tuple(reasons)
        row = dict(row, reason_trace=[asdict(item) for item in trace])
        step = StepResult(node_id, row, selection, trace)
        return step

    def commit(step):
        record_step(step)
        return step

    # 绑定是七阶段的前置步骤，保持先绑定、后解析承载。
    # 恢复时重放已冻结的卡选择：绑定边界的形状（含回执落盘）保持不变。
    client = recovery.binding_client(client, active)
    card, gap, binding_selection = bind.bind(
        node, bind.faces(repository), client=client, timeout=limits.model_timeout)
    selection = mask_secrets(
        {
            "node_id": node_id,
            "status": "selected" if card is not None else "blocked",
            "binding_selection": binding_selection,
            "reason": gap,
        },
        secrets,
    )
    (run_dir / "card_selection.json").write_text(
        json.dumps(selection, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    recovery.verify_recovered_card(card, active)
    if card is not None:
        active.update(card_id=card["id"], card_digest=digest(card),
                      binding_selection=safe_data(binding_selection, secrets))
        if durable:
            save_state(state)
    if card is None:
        remember("binding", gap)
        return commit(finish({"status": "blocked", "reason": gap}))

    # 1. 解析会话。prepare 必须晚于承载解析和探活。
    reuse, why, probe_note = None, "", ""
    task, scope, delivery = None, None, None
    delivery_spec, delivery_target = {}, None
    plan_session, proxy = None, ()
    result, proved, delivered = {}, False, None
    verification, acceptance = {}, {}
    credential_rows, credential_error, migration, row = [], "", None, {}
    can_correct, execute_reason, retry_feedback = False, "", None

    def persist(done=None):
        secrets[:] = list(collect_secrets({"task": task, "result": result,
                                          "carrier": reuse}, secrets))
        if done and done not in active["done"]:
            active["done"].append(done)
        values = {"task": task, "scope": scope,
                  "delivery": asdict(delivery) if delivery else None,
                  "delivery_spec": delivery_spec, "delivery_target": delivery_target,
                  "plan_session": plan_session, "proxy": proxy, "why": why,
                  "probe_note": probe_note, "result": result, "proved": proved,
                  "delivered": delivered, "verification": verification,
                  "acceptance": acceptance, "can_correct": can_correct,
                  "execute_reason": execute_reason, "retry_feedback": retry_feedback,
                  "credential_rows": credential_rows, "credential_error": credential_error,
                  "migration": migration, "row": row,
                  "reasons": [asdict(item) for item in reasons]}
        active["values"] = safe_data(values, secrets)
        active["result_digest"] = digest(result)
        if durable:
            save_state(state)

    def mark(name):
        active["phase"] = name
        if name not in active["entered"]:
            enter_cell(state, name, node_id)
            active["entered"].append(name)
        persist()

    def run_cell(name, function):
        if name in active["done"]:
            return None
        value = function()
        persist(name)
        return value

    def frozen_parent():
        label = getattr(executor, "label", None)
        return parent_binding(reuse, executor_host,
                              str(label() if callable(label) else "local"))

    def observed():
        # Only the inputs this precheck actually consumes are compared.
        carriers = []
        premises = positions.exec_preconditions(document, node_id)
        if premises:
            logicals = {str(item[0]) for item in premises}
            carriers = [item for item in session_registry.snapshot(root)
                        if str(item.get("logical") or "") in logicals]
            carriers.sort(key=lambda item: str(item.get("channel_id") or ""))
        files, ledger, ledger_error, asset_error = {}, [], "", ""
        paths = []
        inputs = card.get("inputs") or {}
        if {"credential_ref", "credential_candidates"} & inputs.keys():
            try:
                ledger = credential_ledger.read(root)
            except (OSError, ValueError) as error:
                ledger_error = str(error).split(":", 1)[0]
            if (credentials.source or {}).get("path"):
                paths.append(credentials.source["path"])
            for item in ((task or {}).get("inputs") or {}).get("credential_candidates", []):
                if isinstance(item, dict) and item.get("source_path"):
                    paths.append(item["source_path"])
        try:
            for _destination, path in assets.declared(card, repository):
                paths.append(path)
        except (OSError, ValueError) as error:
            asset_error = str(error).split(":", 1)[0]
        for raw_path in paths:
            path = Path(raw_path)
            try:
                files[str(path)] = sha256(path.read_bytes()).hexdigest()
            except OSError:
                files[str(path)] = "unavailable"
        return deepcopy({"node": node, "card": card, "hosts": host_map,
                         "carriers": carriers, "files": files, "ledger": ledger,
                         "ledger_error": ledger_error, "asset_error": asset_error})

    def correction_feedback():
        # This flag is produced by the driver, never by the planner wire.
        if proved or not can_correct or result.get("pending_calls") or result.get("rejections"):
            return None
        if plan_session and (delivered is not None or
                             session_flow.delivery_was_issued(plan_session, run_dir)):
            return None
        if execute_reason in {"LEAN_MODEL_REPLY_UNAVAILABLE", "LEAN_TASK_NOT_CONCLUDED",
                              "LEAN_STEP_LIMIT"}:
            return {"reason_code": execute_reason,
                    "note": "Continue from the recorded calls; do not replay a completed call."}
        if not plan_session and acceptance.get("denied"):
            outputs = {str(item["ref"]) for item in graph_criteria.to_produce(document, node_id)}
            if not set(acceptance["denied"]) <= outputs or verification.get("receipt_issues"):
                return None
            if any(item.get("verdict") == "UNRESOLVED_CONFLICT"
                   for item in (verification.get("assessments") or {}).values()):
                return None
            return {"reason_code": "VERIFICATION_DENIED",
                    "denied": list(acceptance["denied"]),
                    "note": "Correct the failed action using the recorded evidence, then conclude."}
        return None

    def precheck():
        nonlocal delivery, delivery_spec, delivery_target, plan_session, probe_note, proxy, reuse, row, scope, task, why
        mark("precheck")
        reuse, why, probe_note = None, "", ""
        try:
            if positions.exec_preconditions(document, node_id):
                reuse, why = positions.resolve_carrier_for_node(
                    document,
                    node_id,
                    session_registry.snapshot(root),
                    host_map=host_map,
                )
                if reuse is None:
                    raise ValueError("CARRIER_UNAVAILABLE: " + str(why))
                alive, probe_note = sessions.probe(reuse, executor)
                if not alive:
                    raise ValueError(
                        "SESSION_POSITION_UNCONFIRMED: " + probe_note
                    )

            # 2. 准备任务、制品、凭据与交付资源。
            active["parent"] = safe_data(frozen_parent(), secrets)
            persist()
            task, scope = preparation.prepare_inputs(
                node=node,
                card=card,
                document=document,
                root=root,
                repository=repository,
                host_map=host_map,
                carrier=reuse,
                executor=executor,
                credentials=credentials,
                prepare_task=prepare_task,
            )
        except ValueError as error:
            remember("prepare", error)
            return finish(
                {
                    "status": "blocked",
                    "reason": str(error),
                    "card": card["id"],
                }
            )

        delivery = DeliveryState()
        delivery_spec = card.get("session") or {}
        delivery_target = session_flow.delivery_target_host(
            task=task,
            document=document,
            node_id=node_id,
            host_map=host_map,
            scope=scope,
        )

        if delivery_spec.get("driver"):
            try:
                delivery_setup.begin_delivery(
                    spec=delivery_spec,
                    target_host=delivery_target,
                    scope=scope,
                    carrier=reuse,
                    executor=executor,
                    control=control,
                    rpc_conf=rpc_conf,
                    root=root,
                    node_id=node_id,
                    run_dir=run_dir,
                    task=task,
                    delivery=delivery,
                )
            except (
                ValueError,
                OSError,
                RuntimeError,
                msfservice.MsfUnreachable,
            ) as error:
                remember("delivery_prepare", error)
                if delivery.relay_facts is not None and reuse is not None:
                    try:
                        delivery.relay_facts["undo"] = undo_relay_delivery(
                            reuse, delivery.relay_facts
                        )
                    except (OSError, ValueError, RuntimeError) as undo_error:
                        delivery.relay_facts["undo"] = [
                            {
                                "step": "undo",
                                "confirmed": False,
                                "note": type(undo_error).__name__,
                            }
                        ]
                row = {
                    "status": "blocked",
                    "reason": str(error),
                    "card": card["id"],
                }
                if delivery.relay_facts is not None:
                    row["relay_undo"] = delivery.relay_facts.get("undo", [])
                return finish(row)

            # 保持原异常边界：输入装配原本在交付准备的 try 之外。
            delivery_setup.add_delivery_inputs(
                task=task,
                delivery=delivery,
                executor=executor,
            )

        plan_session = delivery.plan
        proxy = ()
        if reuse is None:
            covered = tunnel.live(root, str((scope or {}).get("host") or ""))
            if covered:
                proxy = tunnel.proxy_prefix(covered.get("listen_port"))


    def execute():
        nonlocal can_correct, execute_reason, result
        mark("execute")
        # 3. 执行动作。
        try:
            result = drive(
                card,
                task,
                scope,
                executor,
                client=client,
                run_dir=run_dir,
                python=limits.python,
                timeout=limits.timeout,
                max_steps=limits.max_steps,
                channel=reuse,
                model_timeout=limits.model_timeout,
                secrets=secrets,
                private_result=True,
                proxy=proxy,
                **({'feedback': retry_feedback} if retry_feedback else {}),
                **({'recover': True} if recovering else {}),
            )
        except (ValueError, OSError, RuntimeError) as error:
            remember("driver_exception", error)
            step = commit(finish(
                {
                    "status": "blocked",
                    "reason": str(error),
                    "card": card["id"],
                }
            ))
            # 原路径是先记录 blocked，再取消交付；不顺便新增 relay undo。
            if plan_session:
                cancel_session_delivery(
                    executor=executor,
                    plan=plan_session,
                    rpc_conf=rpc_conf,
                    root=root,
                )
            return step

        secrets.extend(collect_secrets(result))
        if not isinstance(result, dict):
            result = {
                "status": "unconfirmed",
                "reason": "DRIVER_RESULT_INVALID",
            }
        result = dict(result)
        can_correct = result.pop("correctable", False) is True
        execute_reason = str(result.get("reason") or "").split(":", 1)[0]
        remember("driver", result.get("reason"))


    def reconcile():
        nonlocal delivered, proved, result
        mark("reconcile")
        # 4. 接收交付。真实会话登记由 finish_session_delivery 完成。
        proved = assessment.proof_of(node, result)
        delivered = None
        proved, gate_reason = session_flow.delivery_gate(
            proved=proved,
            declares_session=bool(delivery_spec.get("driver")),
            prepared=bool(plan_session),
            rpc_ready=bool(rpc_conf and control),
        )
        if gate_reason:
            remember(
                "delivery_gate",
                "SESSION_DELIVERY_NOT_PREPARED",
                gate_reason,
            )
            result = dict(
                result,
                reason="SESSION_DELIVERY_NOT_PREPARED",
                delivery={"state": "unknown", "reason": gate_reason},
            )

        if plan_session and (
            proved or session_flow.delivery_was_issued(plan_session, run_dir)
        ):
            delivered = session_flow._finish_produced_session(
                executor=executor,
                plan=plan_session,
                rpc_conf=rpc_conf,
                root=root,
                node_id=node_id,
                document=document,
                host_map=host_map,
            )
            print(
                "session delivery: "
                + json.dumps(delivered, ensure_ascii=False)
            )
            if str((delivered or {}).get("state") or "") != "completed":
                proved = False
                remember(
                    "delivery",
                    "SESSION_DELIVERY_FAILED",
                    (delivered or {}).get("reason"),
                )
                result = dict(
                    result,
                    reason="SESSION_DELIVERY_FAILED",
                    delivery=delivered,
                )
            if str((delivered or {}).get("state") or "") == "completed":
                if not durable:
                    relay_state = session_flow.activate_relay(
                        executor=executor, delivered=delivered, root=root, node_id=node_id,
                        document=document, host_map=host_map, control=control,
                        run_dir=run_dir, timeout=limits.timeout)
                elif active.get("relay_phase") == "committing":
                    relay_state = recover_relay(
                        root=root, run_dir=run_dir, frozen=active.get("relay_parent") or {},
                        owner=active.get("relay_owner", ""), before=active.get("relay_before", []),
                        targets=active.get("relay_targets", []))
                elif active.get("relay_phase") == "finished":
                    relay_state = active["relay_receipt"]
                else:
                    try:
                        if active.get("relay_phase") != "before_commit":
                            retained = [item for item in session_registry.snapshot(root)
                                        if item.get("channel_id") == delivered.get("carrier")]
                            if len(retained) != 1:
                                raise ValueError("RECOVERY_RELAY_PARENT_UNCONFIRMED")
                            from runtime import harvest
                            recorded = harvest.read(run_dir, row_type="tunnel", strict=True)
                            active.update(
                                relay_parent=parent_binding(retained[0]),
                                relay_targets=[list(item) for item in tunnel.targets_for(document, host_map)],
                                relay_before=[item.get("channel_id") for item in recorded],
                                relay_owner="relay-" + uuid4().hex,
                                relay_deadline_at=time.time() + min(60.0, float(limits.timeout)),
                                relay_phase="before_commit")
                            persist()
                        remaining = active["relay_deadline_at"] - time.time()
                        if remaining <= 0:
                            raise ValueError("RECOVERY_RELAY_DEADLINE")
                        frozen = active["relay_parent"]
                        active["relay_phase"] = "committing"
                        persist()
                        relay_state = session_flow.activate_relay(
                            executor=executor, delivered=delivered, root=root, node_id=node_id,
                            document=document, host_map=host_map, control=control,
                            run_dir=run_dir, timeout=remaining, owner=active["relay_owner"],
                            frozen_parent=dict(frozen["refs"], endpoint=frozen["endpoint"]),
                            frozen_targets=active["relay_targets"])
                    except (ValueError, OSError, RuntimeError, msfservice.MsfUnreachable) as error:
                        relay_state = {"state": "unknown", "reason": type(error).__name__ + ": " + str(error)}
                active["relay_phase"] = "finished"
                active["relay_receipt"] = safe_data(relay_state, secrets)
                persist()
                result = dict(result, relay=relay_state)
                print("relay: " + json.dumps(relay_state, ensure_ascii=False)[:400])


    def verify():
        nonlocal acceptance, proved, result, verification
        mark("verify")
        # 5. 无条件机器验收：这里没有 if proved / if handover。
        # 保留原异常语义；接收或验证本身抛错时仍向上抛出。
        try:
            positions.record_in_place_observation(
                document=document,
                node_id=node_id,
                host_map=host_map,
                root=root,
                row=(reuse or {}),
            )
        except (
            ValueError,
            OSError,
            RuntimeError,
            msfservice.MsfUnreachable,
        ):
            pass

        source_bindings = checking._verification_sources(
            document,
            node_id,
            scope,
            host_map=host_map,
            position_host=(
                (reuse or {}).get("host") if reuse else executor_host
            ),
            carrier=reuse,
            proxy=proxy,
        )
        verification = checking.verify_node(
            client=client,
            document=document,
            node_id=node_id,
            run_dir=run_dir,
            root=root,
            executor=executor,
            host_map=host_map,
            secrets=secrets,
            source_bindings=source_bindings,
            environments=host_environments,
            role_accounts=credentials.role_accounts,
            delivery=delivered,
            expected_delivery_owner=(
                str(plan_session.get("owner") or "")
                if plan_session is not None
                else None
            ),
        )
        acceptance = assessment._fact_gate(
            document=document,
            node_id=node_id,
            verification=verification,
            host_map=host_map,
        )
        remember("fact_gate", acceptance.get("reason"))

        # 时点和公式均保持原样；尤其 refused 读取交付处理后的 reason。
        hedged = (
            str(result.get("claimed_verdict") or "uncertain") == "uncertain"
        )
        refused = str(result.get("reason") or "") in {
            "LEAN_CITATION_INVALID",
            "LEAN_UNRESOLVED_CALL",
            "LEAN_MODEL_REPLY_UNAVAILABLE",
        }
        handover = (
            bool(str((delivered or {}).get("state") or "") == "completed")
            if plan_session
            else False
        )
        proved = bool(acceptance["proved"]) and (
            proved or handover or (hedged and not refused)
        )
        result = dict(result, verification=verification)
        if not acceptance["proved"]:
            result = dict(
                result,
                claimed_reason=result.get("reason"),
                reason=acceptance["reason"],
                verification_denied=acceptance["denied"],
                verification_unconfirmed=acceptance["unconfirmed"],
            )

        # 验收之后才撤销失败交付，避免提前销毁验收所需现场。

    def session():
        nonlocal credential_error, credential_rows, migration, result, row
        mark("session")
        if plan_session and not proved and retry_feedback is None:
            cancel_session_delivery(
                executor=executor,
                plan=plan_session,
                rpc_conf=rpc_conf,
                root=root,
            )
            if delivery.relay_facts is not None and reuse is not None:
                try:
                    delivery.relay_facts["undo"] = undo_relay_delivery(
                        reuse, delivery.relay_facts
                    )
                except (OSError, ValueError, RuntimeError) as undo_error:
                    delivery.relay_facts["undo"] = [
                        {
                            "step": "undo",
                            "confirmed": False,
                            "note": type(undo_error).__name__,
                        }
                    ]
                result = dict(
                    result, relay_undo=delivery.relay_facts["undo"]
                )

        # 6. 发布已证明材料与节点关联。
        credential_rows, credential_error = [], ""
        migration = None
        if proved:
            try:
                credential_rows = credential_ledger.record_proved(
                    root,
                    document=document,
                    node_id=node_id,
                    proved=True,
                    source=credentials.source,
                    host_map=host_map,
                    source_call=acceptance["source_call"],
                    materials=result.get("materials", []),
                    materials_dir=credentials.materials_dir,
                    run_dirs=credentials.run_dirs,
                    secrets=secrets,
                )
            except (ValueError, OSError) as error:
                credential_error = str(error)

        if proved and (card.get("delivers") or []):
            channel_delivery = delivered if plan_session else None
            if (
                isinstance(channel_delivery, dict)
                and channel_delivery.get("delivery_owner")
                != str((plan_session or {}).get("owner") or "")
            ):
                channel_delivery = dict(
                    channel_delivery,
                    state="unknown",
                    reason="SESSION_DELIVERY_OWNER_MISMATCH",
                )
            recorded, entry_note = session_flow.record_channels(
                node_id=node_id,
                document=document,
                host_map=host_map,
                root=root,
                delivery=channel_delivery,
            )
            migration = reporting.migration_note(recorded=recorded)
            if entry_note:
                migration = dict(migration or {}, entry=entry_note)

        # 保留 node_row 与两个位置函数的原调用顺序；此时尚未提交整轮状态。
        row = reporting.node_row(
            proved=proved,
            card=card,
            reuse=reuse,
            why=why,
            result=result,
            run_dir=run_dir,
            migration=migration,
            probe_note=probe_note,
        )
        position_row = (
            positions.register_declared_position(
                card=card,
                node_id=node_id,
                document=document,
                host_map=host_map,
                scope=scope,
                root=root,
                executor=executor,
                source_call=acceptance["source_call"],
            )
            if proved
            else None
        )
        if position_row:
            if str(position_row.get("state") or "") == "failed":
                row["position_error"] = position_row
                print(
                    "position refused: "
                    + json.dumps(position_row, ensure_ascii=False)
                )
            else:
                row["position"] = {
                    "channel_id": position_row["channel_id"],
                    "kind": str(position_row.get("position_kind") or "web"),
                    "logical": position_row["logical"],
                    "host": position_row["host"],
                }
                print(
                    "web position: "
                    + json.dumps(row["position"], ensure_ascii=False)
                )

        entry_row = (
            positions.build_entry_position(
                card=card,
                node_id=node_id,
                document=document,
                host_map=host_map,
                root=root,
                carrier=reuse,
                executor=executor,
                source_call=acceptance["source_call"],
            )
            if proved and card.get("entry_setup")
            else None
        )
        if entry_row:
            row["entry_setup"] = entry_row
            print(
                "entry position: "
                + json.dumps(entry_row, ensure_ascii=False)
            )


    def wrapup():
        mark("wrapup")
        # 7. 汇总并且仅提交一次本步结果。
        row["verification"] = verification
        if not acceptance["proved"]:
            row["status"] = acceptance["status"]
            row["reason"] = acceptance["reason"]
        if credential_rows:
            row["credential"] = [
                item["credential_id"] for item in credential_rows
            ]
        if credential_error:
            row["credential_error"] = credential_error
        return finish(row)

    cached = None
    if recovering:
        saved = active.get("values") or {}
        if active.get("phase") == "precheck" and "precheck" not in active["done"]:
            remember("recovery", "RECOVERY_PRECHECK_UNKNOWN")
            return commit(finish({"status": "unconfirmed", "reason": "RECOVERY_PRECHECK_UNKNOWN",
                                  "card": card["id"]}))
        try:
            label = getattr(executor, "label", None)
            reuse = restore_parent(
                active.get("parent") or {}, session_registry.snapshot(root), executor,
                executor_host=executor_host,
                executor_label=str(label() if callable(label) else "local"))
            if "precheck" not in active["done"]:
                raise ValueError("RECOVERY_PRECHECK_UNKNOWN")
            task, scope = preparation.prepare_inputs(
                node=node, card=card, document=document, root=root, repository=repository,
                host_map=host_map, carrier=reuse, executor=executor, credentials=credentials,
                prepare_task=prepare_task,
                prepared_assets=((saved.get("task") or {}).get("inputs") or {})
                                .get("placed_assets", {}))
            delivery = DeliveryState(**(saved.get("delivery") or {}))
            delivery_spec = saved.get("delivery_spec") or {}
            delivery_target = saved.get("delivery_target")
            plan_session = delivery.plan
            if plan_session is not None:
                owner = str(plan_session.get("owner") or "")
                import re
                if not re.fullmatch(r"delivery-[0-9a-f]{32}", owner):
                    raise ValueError("RECOVERY_DELIVERY_ASSOCIATION_LOST")
                original = json.loads((root / "delivery" / owner / "plan.json")
                                      .read_text(encoding="utf-8"))
                if original.get("owner") != owner or original.get("node") != plan_session.get("node"):
                    raise ValueError("RECOVERY_DELIVERY_ASSOCIATION_LOST")
                delivery.plan = plan_session = original
                delivery_setup.add_delivery_inputs(task=task, delivery=delivery, executor=executor)
                if delivery.relay_facts:
                    task["inputs"]["delivery_pivot_stager"] = delivery.relay_facts.get("remote_stager", "")
            if digest(task) != active.get("task_digest") or digest(scope) != active.get("scope_digest"):
                raise ValueError("RECOVERY_INPUT_CHANGED")
            if digest(saved.get("result") or {}) != active.get("result_digest"):
                raise ValueError("RECOVERY_PRIVATE_RESULT_UNAVAILABLE")
            proxy, why = saved.get("proxy") or (), str(saved.get("why") or "")
            probe_note = str(saved.get("probe_note") or "")
            result, proved = saved.get("result") or {}, bool(saved.get("proved"))
            delivered = saved.get("delivered")
            verification, acceptance = saved.get("verification") or {}, saved.get("acceptance") or {}
            can_correct, execute_reason = bool(saved.get("can_correct")), saved.get("execute_reason") or ""
            retry_feedback = saved.get("retry_feedback")
            credential_rows = saved.get("credential_rows") or []
            credential_error, migration, row = saved.get("credential_error") or "", saved.get("migration"), saved.get("row") or {}
            reasons[:] = [ReasonEvent(**item) for item in saved.get("reasons") or []]
            cached = observed()
            if cached["files"] != active.get("consumed_files", {}):
                raise ValueError("RECOVERY_INPUT_CHANGED")
        except (ValueError, OSError, RuntimeError) as error:
            remember("recovery", str(error))
            return commit(finish({"status": "unconfirmed", "reason": str(error),
                                  "card": card["id"]}))
    if execute_count(state, node_id) >= ATTEMPT_LIMIT and not (recovering and "execute" in active["entered"]):
        exhausted(state, node_id)
        state["cell"] = "wrapup"
        return commit(finish({"status": "blocked",
                              "reason": "ATTEMPT_BUDGET_EXHAUSTED", "card": card["id"]}))
    while True:
        if cached is None or observed() != cached:
            early = run_cell("precheck", precheck)
            if early is not None:
                state["cell"] = "wrapup"
                return commit(early)
            cached = observed()
            active["consumed_files"] = safe_data(cached["files"], secrets)
            active["task_digest"], active["scope_digest"] = digest(task), digest(scope)
            persist()
        early = run_cell("execute", execute)
        if early is not None:
            state["cell"] = "wrapup"
            return early
        run_cell("reconcile", reconcile)
        run_cell("verify", verify)
        retry_feedback = correction_feedback()
        if retry_feedback and execute_count(state, node_id) >= ATTEMPT_LIMIT:
            exhausted(state, node_id)
            retry_feedback = None
        run_cell("session", session)
        # wrapup only builds a row; committing it remains idempotent at the walk boundary.
        step = wrapup()
        persist("wrapup")
        if retry_feedback is None:
            return commit(step)
        # A correction is a new attempt; restart above keeps this attempt's identity.
        recovering = False
        active["entered"], active["done"] = [], ["precheck"]
        active["phase"] = ""
        active.pop("parent", None)
        active["parent"] = safe_data(frozen_parent(), secrets)
        if observed() != cached:
            active["done"] = []
        persist()
