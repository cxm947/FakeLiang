"""Validate a reply against its bound planner inventory."""
from __future__ import annotations

from .errors import PlannerIOError, _text
from .board import (
    PlannerBoard, _board_digest, _identifier, dependency_state,
)

_BOARD_OUTPUT_KEYS = ("decision", "board_id", "node_id", "phase", "candidate_id", "reason")


def _parse_board_output(value, board):
    if not isinstance(board, PlannerBoard):
        raise PlannerIOError("PLANNER_BOARD_INVALID")
    if board.input.get("board_id") != _board_digest(board.input, board._context):
        raise PlannerIOError("PLANNER_BOARD_CHANGED")

    if not isinstance(value, dict) or set(value) != set(_BOARD_OUTPUT_KEYS):
        raise PlannerIOError("PLANNER_OUTPUT_INVALID")
    if value["board_id"] != board.input["board_id"]:
        raise PlannerIOError("PLANNER_BOARD_STALE")
    if not _text(value["reason"]):
        raise PlannerIOError("PLANNER_REASON_MISSING")

    if value["decision"] == "stop":
        if any(value[key] is not None for key in ("node_id", "phase", "candidate_id")):
            raise PlannerIOError("PLANNER_STOP_INVALID")
        return {**value, "reason": value["reason"].strip()}
    if value["decision"] != "choose":
        raise PlannerIOError("PLANNER_DECISION_INVALID")

    node_id, phase = value["node_id"], value["phase"]
    states, context = board.input["node_states"], board._context
    if not _identifier(node_id) or node_id not in states:
        raise PlannerIOError("PLANNER_NODE_UNKNOWN")
    if phase not in ("execute", "observe"):
        raise PlannerIOError("PLANNER_PHASE_INVALID")

    selected = value["candidate_id"]
    if selected is not None and not _identifier(selected):
        raise PlannerIOError("PLANNER_CANDIDATE_INVALID")
    if board.input["remaining_budget"] == 0:
        raise PlannerIOError("PLANNER_BUDGET_EXHAUSTED")

    status = states[node_id]["status"]
    if status == "running":
        raise PlannerIOError("NODE_ALREADY_RUNNING", node_id)
    if context["unsettled"].get(node_id):
        raise PlannerIOError("NODE_CALL_UNRESOLVED", node_id)
    if context["resource_conflicts"].get(node_id):
        raise PlannerIOError("RESOURCE_CONFLICT", node_id)

    if phase == "execute":
        if status == "completed":
            raise PlannerIOError("NODE_ALREADY_COMPLETED", node_id)

        verdicts = {
            ref: row["verdict"] for ref, row in context["assessments"].items()
        }
        requirement = context["requirements"][node_id]
        verdict = dependency_state(requirement, verdicts)
        if verdict != "TRUE":
            missing = [
                {"fact_ref": item["fact"], "verdict": verdicts[item["fact"]]}
                for item in requirement["items"]
                if verdicts[item["fact"]] != "TRUE"
            ]
            raise PlannerIOError(
                "PRECONDITIONS_UNCONFIRMED", verdict, facts=missing,
            )

        routes = context["positions"].get(node_id, {})
        unavailable = "NO_EXECUTION_POSITION"
    else:
        routes = context["probes"].get(node_id, {})
        unavailable = "NO_OBSERVATION_ROUTE"

    if not routes:
        raise PlannerIOError(unavailable, node_id)
    if selected is None:
        if len(routes) != 1:
            raise PlannerIOError("PLANNER_CANDIDATE_REQUIRED", node_id)
        selected = next(iter(routes))
    if selected not in routes:
        raise PlannerIOError("PLANNER_CANDIDATE_NOT_ELIGIBLE", node_id)

    return {
        **value,
        "candidate_id": selected,
        "reason": value["reason"].strip(),
    }
