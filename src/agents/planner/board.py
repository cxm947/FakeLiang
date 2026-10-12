"""Planner inventory and dependency evaluation."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .errors import PlannerIOError, _text



@dataclass(frozen=True)
class PlannerBoard:
    """A public inventory and a separate snapshot supplied by trusted runtime code."""

    input: dict
    _context: dict


_FACT_VERDICTS = ("TRUE", "FALSE", "UNKNOWN", "UNRESOLVED_CONFLICT")
_STEP_STATUSES = ("pending", "running", "completed", "failed", "blocked", "unknown")


def _json_data(value):
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise PlannerIOError("PLANNER_DATA_INVALID", str(error)) from error


def _snapshot(value):
    return json.loads(_json_data(value))


def _identifier(value):
    return _text(value) and value == value.strip()


def _board_digest(public, private):
    payload = {
        "contract": "planner-inventory-v1",
        "input": {key: item for key, item in public.items() if key != "board_id"},
        "context": private,
    }
    return hashlib.sha256(_json_data(payload).encode("utf-8")).hexdigest()


def dependency_state(expression, facts):
    """Evaluate checker verdicts only; graph declarations supply no truth values."""
    if not isinstance(expression, dict) or not isinstance(facts, dict):
        raise PlannerIOError("GRAPH_DEPENDENCY_INVALID")

    if set(expression) == {"fact"}:
        ref = expression["fact"]
        if not _identifier(ref):
            raise PlannerIOError("GRAPH_DEPENDENCY_INVALID")
        value = facts.get(ref, "UNKNOWN")
        if value not in _FACT_VERDICTS:
            raise PlannerIOError("FACT_STATE_INVALID", ref)
        return value

    if (
        set(expression) != {"op", "items"}
        or expression["op"] not in ("all", "any")
        or not isinstance(expression["items"], list)
    ):
        raise PlannerIOError("GRAPH_DEPENDENCY_INVALID")

    values = [dependency_state(item, facts) for item in expression["items"]]
    if expression["op"] == "all":
        if "FALSE" in values:
            return "FALSE"
        if all(value == "TRUE" for value in values):
            return "TRUE"
    else:
        if "TRUE" in values:
            return "TRUE"
        if all(value == "FALSE" for value in values):
            return "FALSE"

    return "UNRESOLVED_CONFLICT" if "UNRESOLVED_CONFLICT" in values else "UNKNOWN"


def _node_mapping(value, node_ids, code):
    if (
        not isinstance(value, dict)
        or any(not _identifier(key) or key not in node_ids for key in value)
    ):
        raise PlannerIOError(code)
    return value


def _route_snapshot(value, node_ids, code):
    value = _node_mapping(value, node_ids, code)
    for routes in value.values():
        if not isinstance(routes, dict):
            raise PlannerIOError(code)
        for route_id, binding in routes.items():
            if not _identifier(route_id) or not isinstance(binding, dict) or not binding:
                raise PlannerIOError(code)
    return _snapshot(value)


def _event_snapshot(value, node_ids, code):
    value = _node_mapping(value, node_ids, code)
    for events in value.values():
        if (
            not isinstance(events, list)
            or any(not _identifier(item) for item in events)
            or len(events) != len(set(events))
        ):
            raise PlannerIOError(code)
    return _snapshot(value)


def build_plan_board(
        document, *, run_id, node_states, last_result, handoffs,
        assessments, positions, probes, unsettled, resource_conflicts,
        remaining_budget, binding_epoch, claimed_verdicts=None):
    """Build an inventory, not a schedule.

    Assessments must come from evidence checkers. Positions and probes must be
    concrete, currently usable bindings supplied by the execution layer.
    Never populate these trusted arguments from a planner reply.
    """
    from graph.criteria import fact_row
    from graph.parser import digest, id_key
    from graph.rehydrate import document_payload, ensure_view

    if not _identifier(run_id):
        raise PlannerIOError("PLANNER_RUN_ID_INVALID")
    if not _identifier(binding_epoch):
        raise PlannerIOError("PLANNER_BINDING_EPOCH_INVALID")
    if type(remaining_budget) is not int or remaining_budget < 0:
        raise PlannerIOError("PLANNER_BUDGET_INVALID")

    view = ensure_view(document)
    graph = view.graph
    actions = sorted(
        (ref for ref, node in graph.nodes.items() if node.type == "AND"),
        key=id_key,
    )
    action_ids = set(actions)
    fact_ids = {ref for ref, node in graph.nodes.items() if node.type != "AND"}
    graph_hash = view["source_graph"]["graph_hash"]

    supplied_states = _node_mapping(
        node_states, action_ids, "PLANNER_NODE_STATES_INVALID",
    )
    states = {}
    for ref in actions:
        raw = supplied_states.get(ref, {"status": "pending"})
        if not isinstance(raw, dict) or not {"status"} <= set(raw) <= {"status", "reason"}:
            raise PlannerIOError("PLANNER_NODE_STATES_INVALID", ref)
        status = "completed" if raw["status"] == "success" else raw["status"]
        reason = raw.get("reason")
        if status not in _STEP_STATUSES or (reason is not None and not _text(reason)):
            raise PlannerIOError("PLANNER_NODE_STATES_INVALID", ref)
        states[ref] = {
            "status": status,
            "reason": reason.strip() if reason else None,
        }

    if last_result is not None:
        keys = {"node_id", "status", "call_ids", "failure_reason"}
        if not isinstance(last_result, dict) or set(last_result) != keys:
            raise PlannerIOError("PLANNER_LAST_RESULT_INVALID")

        ref = last_result["node_id"]
        status = last_result["status"]
        calls = last_result["call_ids"]
        failure = last_result["failure_reason"]
        if (
            not _identifier(ref)
            or ref not in action_ids
            or status not in ("success", "failed", "blocked", "unknown", "running")
            or not isinstance(calls, list)
            or any(not _identifier(item) for item in calls)
            or len(calls) != len(set(calls))
            or (failure is not None and not _text(failure))
        ):
            raise PlannerIOError("PLANNER_LAST_RESULT_INVALID")

        if (
            status == "success" and states[ref]["status"] != "completed"
        ) or (
            status in ("failed", "blocked")
            and (failure is None or states[ref]["status"] == "completed")
        ):
            raise PlannerIOError("PLANNER_LAST_RESULT_CONFLICT", ref)

    if not isinstance(handoffs, list):
        raise PlannerIOError("PLANNER_HANDOFF_INVALID")
    for row in handoffs:
        if (
            not isinstance(row, dict)
            or not _identifier(row.get("node_id"))
            or row["node_id"] not in action_ids
            or not isinstance(row.get("reason_codes"), list)
            or any(not _text(code) for code in row["reason_codes"])
        ):
            raise PlannerIOError("PLANNER_HANDOFF_INVALID")

    assessments = _node_mapping(
        assessments, fact_ids, "PLANNER_ASSESSMENT_INVALID",
    )
    claims = {} if claimed_verdicts is None else claimed_verdicts
    claims = _node_mapping(claims, fact_ids, "PLANNER_CLAIM_INVALID")
    if any(value not in _FACT_VERDICTS for value in claims.values()):
        raise PlannerIOError("PLANNER_CLAIM_INVALID")

    checked = {}
    for ref in sorted(fact_ids, key=id_key):
        raw = assessments.get(ref, {
            "verdict": "UNKNOWN",
            "checker": None,
            "evidence": [],
            "binding_epoch": None,
        })
        if (
            not isinstance(raw, dict)
            or set(raw) != {"verdict", "checker", "evidence", "binding_epoch"}
        ):
            raise PlannerIOError("PLANNER_ASSESSMENT_INVALID", ref)

        verdict, checker = raw["verdict"], raw["checker"]
        evidence, epoch = raw["evidence"], raw["binding_epoch"]
        if (
            verdict not in _FACT_VERDICTS
            or not isinstance(evidence, list)
            or (checker is not None and not _identifier(checker))
        ):
            raise PlannerIOError("PLANNER_ASSESSMENT_INVALID", ref)
        if epoch is not None and epoch != binding_epoch:
            raise PlannerIOError("PLANNER_ASSESSMENT_STALE", ref)
        if (verdict != "UNKNOWN" or evidence) and (
            checker is None or not evidence or epoch != binding_epoch
        ):
            raise PlannerIOError("PLANNER_ASSESSMENT_UNGROUNDED", ref)
        checked[ref] = _snapshot(raw)

    facts = {}
    for ref in sorted(fact_ids, key=id_key):
        row = fact_row(view, ref)
        facts[ref] = {
            "declaration": {
                "graph_hash": graph_hash,
                "fact_ref": ref,
                "kind": row["declaration_kind"],
                "type": row["type"],
                "fact": row["fact"],
                "predicate": row["predicate"],
                "arguments": row["arguments"],
                "signature": row["signature"],
                "producer_refs": row["produced_by"],
                "consumer_refs": row["consumed_by"],
                "validation_kind": row["validation_kind"],
                "validation_fields": row["validation_fields"],
            },
            "assessment": checked[ref],
            "claimed_verdict": claims.get(ref),
        }

    requirements = {
        ref: {
            "op": "all",
            "items": [
                {"fact": parent}
                for parent in sorted(graph.parents[ref], key=id_key)
            ],
        }
        for ref in actions
    }
    for ref in actions:
        if any(parent not in fact_ids for parent in graph.parents[ref]):
            raise PlannerIOError("GRAPH_DEPENDENCY_INVALID", ref)

    public = {
        "run_id": run_id,
        "graph_hash": graph_hash,
        "binding_epoch": binding_epoch,
        "unfinished": [
            ref for ref in actions if states[ref]["status"] != "completed"
        ],
        "steps": {
            row["id"]: {
                key: value
                for key, value in row.items()
                if key not in ("dependencies", "semantics")
            }
            for row in view["nodes"] if row["type"] == "AND"
        },
        "node_states": states,
        "last_result": last_result,
        "dependencies": {
            ref: [
                facts[parent]
                for parent in sorted(graph.parents[ref], key=id_key)
            ]
            for ref in actions
        },
        "goal_facts": [
            facts[ref] for ref in sorted(graph.terminals, key=id_key)
        ],
        "handoffs": handoffs,
        "remaining_budget": remaining_budget,
    }
    private = {
        "document_digest": digest(document_payload(view)),
        "requirements": requirements,
        "assessments": checked,
        "claimed_verdicts": claims,
        "positions": _route_snapshot(
            positions, action_ids, "PLANNER_POSITIONS_INVALID",
        ),
        "probes": _route_snapshot(
            probes, action_ids, "PLANNER_PROBES_INVALID",
        ),
        "unsettled": _event_snapshot(
            unsettled, action_ids, "PLANNER_UNSETTLED_INVALID",
        ),
        "resource_conflicts": _event_snapshot(
            resource_conflicts, action_ids, "PLANNER_RESOURCE_CONFLICTS_INVALID",
        ),
    }

    public, private = _snapshot(public), _snapshot(private)
    public["board_id"] = _board_digest(public, private)
    return PlannerBoard(public, private)
