"""The walk: one step holds one attempt, the loop holds the round."""
from __future__ import annotations

import json
from dataclasses import asdict
from runtime.recovery import RecoveryModel, digest
from pathlib import Path
from typing import Callable

from graph.rehydrate import GraphContractError
from runtime import credentials as credential_ledger
from runtime import msfservice, session_registry, sessions, tunnel
from runtime.lean import collect_secrets, mask_secrets
from runtime.session_delivery import (
    cancel_session_delivery,
    undo_relay_delivery,
)
from skills import bind

from . import delivery_setup, positions, preparation
from agents.planner import service as planning
from . import reporting, session_flow
from . import langgraph_runner
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


from .walk_step import run_step

def run_walk(
    *,
    document: dict,
    graph_label: str,
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
    max_nodes: int,
    secrets: list[str],
    prepare_task: Callable,
    drive: Callable,
    resume=False,
) -> WalkResult:
    from agents._model.backend import freeze_backend
    freeze_backend(root, getattr(client, "backend", "legacy"))
    walk = WalkResult()
    recovery = {}
    client = RecoveryModel(client, recovery, secrets, limits.model_timeout)
    run_binding = digest({"document": document, "host_map": host_map,
                          "host_environments": host_environments,
                          "graph_label": graph_label, "max_nodes": max_nodes,
                          "executor_host": executor_host, "control": control,
                          "limits": asdict(limits),
                          "model": {key: getattr(client, key, None) for key in
                                    ("name", "base_url", "wire", "temperature",
                                     "reasoning_effort", "max_tokens")},
                          **({"backend": "native", "protocol": "native-tools-v1"}
                             if getattr(client, "backend", "legacy") == "native"
                             else {})})
    run_id = str(root.name or "run")

    pending = {}

    def restore_walk(saved):
        values = saved.get("walk", {})
        for name in WalkResult.__dataclass_fields__:
            if name in values:
                setattr(walk, name, values[name])
        recovery["resume_models"] = True
        node_id = str(saved.get("selected_node_id") or "")
        if not node_id:
            return
        node = next((item for item in graph_nodes(document)
                     if str(item["id"]) == node_id), None)
        if node is None:
            raise ValueError("WALK_RESUME_NODE_MISSING")
        note = next((item for item in reversed(walk.planner_notes)
                     if str(item.get("node") or "") == node_id), None)
        if note is None:
            raise ValueError("WALK_RESUME_ASSOCIATION_LOST")
        pending.update(node=node, planner_note=note)

    def planner_node(graph_state):
        recovery["state"] = graph_state
        try:
            node, planner_note = planning.plan_next(
                document=document,
                state=walk.state,
                order=walk.order,
                run_id=run_id,
                client=client,
                handoffs=planning.planner_handoffs(
                    walk.state, walk.order
                ),
                host_map=host_map,
                timeout=limits.model_timeout,
                trace=walk.planner_trace.append,
                graph_state=graph_state,
                save_state=recovery.get("save"),
            )
        except planning.PlannerFailure as error:
            failure = {
                "reason_code": error.reason_code,
                "detail": error.detail,
                "refusals": error.refusals,
            }
            walk.planner_error = failure
            text = mask_secrets(
                json.dumps(failure, ensure_ascii=False),
                list(secrets),
            )
            (root / "planner_error.json").write_text(
                text, encoding="utf-8"
            )
            print("[planner] " + text, flush=True)

            # 保留原 partial 结算，不转入普通完整结算。
            partial = {
                "order": walk.order,
                "nodes": walk.state,
                "proved": sorted(
                    key for key, row in walk.state.items()
                    if row.get("status") == "proved"
                ),
                "stopped": sorted(
                    key for key, row in walk.state.items()
                    if row.get("status") == "stopped"
                ),
                "blocked": sorted(
                    key for key, row in walk.state.items()
                    if row.get("status") == "blocked"
                ),
                "not_attempted": sorted(
                    str(item["id"]) for item in graph_nodes(document)
                    if str(item["id"]) not in walk.state
                ),
                "planner_error": failure,
                "passed": False,
                "undecided": reporting.undecided_rows(
                    walk.state, root
                ),
                "note": "scheduling stopped: not a pass",
            }
            (root / "plan_result.json").write_text(
                mask_secrets(
                    json.dumps(partial, ensure_ascii=False, indent=2),
                    list(secrets),
                ) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            return False

        planner_note["node"] = str((node or {}).get("id") or "")
        walk.planner_notes.append(planner_note)
        if node is None:
            print(
                "[planner] model stopped scheduling; "
                "goals require separate evidence",
                flush=True,
            )
            return False

        print(
            "[planner] next node %s: %s"
            % (
                node.get("id"),
                str(planner_note.get("note") or "")[:120],
            ),
            flush=True,
        )

        pending["node"] = node
        pending["planner_note"] = planner_note
        return True

    def step_node(graph_state):
        recovery["state"] = graph_state
        node = pending["node"]
        if str(node["id"]) in walk.state:
            return
        planner_note = pending["planner_note"]
        def record_step(step: StepResult) -> None:
            if step.node_id in walk.state:
                return
            planner_note["binding_selection"] = step.binding_selection
            walk.state[step.node_id] = step.row
            walk.order.append(step.node_id)
            reporting.walk_node(
                root,
                step.node_id,
                state=walk.state,
                planner_notes=walk.planner_notes,
                order=walk.order,
                document=document,
                graph_label=graph_label,
                secrets=secrets,
            )

        run_step(
            node=node,
            document=document,
            root=root,
            repository=repository,
            host_map=host_map,
            host_environments=host_environments,
            executor=executor,
            executor_host=executor_host,
            client=client,
            control=control,
            rpc_conf=rpc_conf,
            credentials=credentials,
            limits=limits,
            secrets=secrets,
            prepare_task=prepare_task,
            drive=drive,
            record_step=record_step,
            graph_state=graph_state,
            save_state=recovery.get("save"),
        )


    def stop_reason(graph_state):
        try:
            summary = {
                "plan": reporting.plan_identity(document, walk.state),
                "final_goal": assessment.final_goal_rows(
                    document, walk.state, host_map=host_map
                ),
                "planner_error": walk.planner_error,
            }
        except GraphContractError:
            # ponytail: a document that cannot be read cannot claim convergence.
            # Fall through to the blocked / budget_exhausted branches instead of
            # turning a reporting detail into a crash.
            summary = {"plan": {}, "final_goal": [], "planner_error": walk.planner_error}
        if reporting.plan_passed(summary):
            return "converged"
        if (walk.planner_error or {}).get("reason_code") == "PLANNER_ATTEMPTS_EXHAUSTED":
            return "budget_exhausted"
        if graph_state.get("exhausted_nodes"):
            return "budget_exhausted"
        if len(walk.order) >= max_nodes:
            for item in graph_nodes(document):
                node_id = str(item["id"])
                if planning.choice_refusal(document, node_id, walk.state, host_map=host_map) is None:
                    return "budget_exhausted"
        return "blocked"

    return langgraph_runner.run_walk_graph(
        root=root, repository=repository,
        materials_dir=credentials.materials_dir, max_nodes=max_nodes,
        walk=walk, secrets=secrets, planner=planner_node, step=step_node,
        stop_reason=stop_reason,
        selected_node=lambda: str((pending.get("node") or {}).get("id") or ""),
        resume=resume, attach_save=lambda save: recovery.update(save=save),
        restore_walk=restore_walk, run_binding=run_binding,
    )
