"""Planner IO with separate declarations, assessments, and execution bindings.

The legacy parse_plan_input and scenario-based parse_plan_output entry points
retain their existing message-shape contract.

New scheduling uses build_plan_board, sends only board.input to the model, and
validates the reply with parse_plan_output(..., board=board). The public input
is an inventory of all steps, their states, and their dependency facts. It
contains no eligible-step list.

Execution bindings and checker assessments must come from trusted runtime
code. A graph declaration or model claim cannot create an assessment.

A valid stop request does not establish the graph goal. Model failure never
selects a fallback step.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

#: The eight input fields, flat at the top level.
INPUT_KEYS = ("graph", "run_id", "done", "last_step", "handoffs")

#: One row of ``node_states``: which node, and how that step came out.
NODE_STATE_KEYS = ("node_id", "status")

#: What one hand-off row must carry to be readable (the executor writes the rest).
HANDOFF_REQUIRED = ("node_id", "reason_codes")

#: The result values a set ``last_step_result`` may carry (null means "no previous step").
RESULT_VALUES = ("success", "failed", "blocked")

#: The four scenarios, read off the input values.
SCENARIO_FIRST = "first"
SCENARIO_SUCCESS = "success"
SCENARIO_FAILED = "failed"
SCENARIO_BLOCKED = "blocked"
SCENARIOS = (SCENARIO_FIRST, SCENARIO_SUCCESS, SCENARIO_FAILED, SCENARIO_BLOCKED)

#: The three output fields.
OUTPUT_KEYS = ("decision", "next_node_id", "change_note")

#: The decisions the planner may return.
DECISIONS = ("continue", "done")


from .prompts import IO_SYSTEM
from .errors import PlannerIOError, _text
from .board import (
    PlannerBoard, _FACT_VERDICTS, _STEP_STATUSES, _json_data, _snapshot,
    _identifier, _board_digest, dependency_state, _node_mapping,
    _route_snapshot, _event_snapshot, build_plan_board,
)
from .board_output import _BOARD_OUTPUT_KEYS, _parse_board_output



def parse_plan_input(value, *, where="planner input"):
    """Five wire fields -> {"scenario": ..., "input": ...} (bridge patch, applied verbatim)."""
    from copy import deepcopy

    def fail(detail):
        raise PlannerIOError("PLANNER_INPUT_INVALID", where + ": " + detail)

    def exact(obj, keys, label):
        if not isinstance(obj, dict) or set(obj) != set(keys):
            fail(label + " must contain exactly " + ", ".join(keys))

    def texts(items, label):
        if not isinstance(items, list) or any(not _text(item) for item in items):
            fail(label + " must be a list of nonempty strings")
        return items

    exact(value, INPUT_KEYS, "input")
    if not _text(value["run_id"]):
        fail("run_id must be a nonempty string")

    graph = value["graph"]
    #: 爷爷 2026-10-08 口径：planner 只要"单纯的图数据 + 成败"，不要任何描述信息。
    exact(graph, ("goal", "steps"), "graph")
    texts(graph["goal"], "graph.goal")
    if not isinstance(graph["steps"], list):
        fail("graph.steps must be a list")

    node_ids = set()
    for step in graph["steps"]:
        exact(step, ("node_id", "needs", "produces"), "step")
        node_id = step["node_id"]
        if not _text(node_id) or node_id in node_ids:
            fail("step node_id must be nonempty and unique")
        node_ids.add(node_id)
        texts(step["needs"], "step.needs")
        texts(step["produces"], "step.produces")

    if not isinstance(value["done"], list):
        fail("done must be a list")
    done = {}
    for row in value["done"]:
        status = row.get("status") if isinstance(row, dict) else None
        keys = ("node_id", "status") if status == "success" else (
            "node_id", "status", "reason")
        exact(row, keys, "done row")
        node_id = row["node_id"]
        if not _text(node_id) or node_id not in node_ids or node_id in done:
            fail("done node_id must name a unique declared step")
        if status not in RESULT_VALUES:
            fail("done row status must be success, failed or blocked")
        if status != "success" and not _text(row["reason"]):
            fail("a failed or blocked done row needs a nonempty reason")
        done[node_id] = status

    last = value["last_step"]
    if last is None:
        if done:
            fail("first requires done=[]")
        scenario = SCENARIO_FIRST
    else:
        if not isinstance(last, dict) or last.get("status") not in RESULT_VALUES:
            fail("last_step.status must be success, failed or blocked")
        status = last["status"]
        keys = ("node_id", "status") if status == "success" else (
            "node_id", "status", "reason")
        exact(last, keys, "last_step")
        node_id = last["node_id"]
        if not _text(node_id) or node_id not in node_ids:
            fail("last_step.node_id must name a declared step")

        if node_id not in done:
            fail("last_step must be one of the attempted steps in done")
        if done[node_id] != status:
            fail("last_step.status must match its done row")
        if status == "success":
            scenario = SCENARIO_SUCCESS
        else:
            if not _text(last["reason"]):
                fail("failed or blocked last_step requires a nonempty reason")
            scenario = SCENARIO_FAILED if status == "failed" else SCENARIO_BLOCKED

    if not isinstance(value["handoffs"], list):
        fail("handoffs must be a list")
    for row in value["handoffs"]:
        #: 原契约允许执行器附加字段，保留这个扩展点。
        if not isinstance(row, dict) or not set(HANDOFF_REQUIRED) <= row.keys():
            fail("handoff requires node_id and reason_codes")
        if not _text(row["node_id"]):
            fail("handoff.node_id must be a nonempty string")
        texts(row["reason_codes"], "handoff.reason_codes")

    normalised = deepcopy(value)
    normalised["run_id"] = value["run_id"].strip()
    if last is not None and last["status"] != "success":
        normalised["last_step"]["reason"] = last["reason"].strip()
    return {"scenario": scenario, "input": normalised}


def parse_plan_output(value, *, scenario=None, board=None,
                      where: str = "planner output") -> dict:
    """Validate a board-bound proposal, or explicitly parse a legacy message."""
    if board is not None:
        return _parse_board_output(value, board)

    if scenario not in SCENARIOS:
        raise PlannerIOError(where + ": unknown scenario " + repr(scenario))
    if not isinstance(value, dict):
        raise PlannerIOError(where + " is not an object")
    if set(value) != set(OUTPUT_KEYS):
        raise PlannerIOError(where + " carries exactly decision, next_node_id and change_note")

    decision = value.get("decision")
    if decision not in DECISIONS:
        raise PlannerIOError(where + ": decision must be one of " + " / ".join(DECISIONS))
    node_id = value.get("next_node_id")
    note = value.get("change_note")

    if decision == "continue":
        if not _text(node_id):
            raise PlannerIOError(where + ": continue needs a non-empty next_node_id")
    elif node_id is not None:
        raise PlannerIOError(where + ": done carries next_node_id=null")

    if note is not None and not _text(note):
        raise PlannerIOError(where + ": change_note is a short non-empty string or null")
    if scenario in (SCENARIO_FAILED, SCENARIO_BLOCKED) and note is None:
        raise PlannerIOError(where + ": P2 change_note must say what changed")

    # Preserve legacy P1 compatibility without using it as a scheduling fallback.
    return {
        "decision": decision,
        "next_node_id": node_id.strip() if decision == "continue" else None,
        "change_note": note.strip() if isinstance(note, str) else None,
    }




def plan_next(*, client, board, timeout):
    """Ask the model once and validate its proposal; never choose a fallback step."""
    if not isinstance(board, PlannerBoard):
        raise PlannerIOError("PLANNER_BOARD_INVALID")
    if board.input.get("board_id") != _board_digest(board.input, board._context):
        raise PlannerIOError("PLANNER_BOARD_CHANGED")
    if client is None or not getattr(client, "available", False):
        raise PlannerIOError("PLANNER_MODEL_UNAVAILABLE")

    reply = client.complete(
        task="pick_next_node",
        system=IO_SYSTEM,
        user=_json_data(board.input),
        timeout=timeout,
    )
    if not getattr(reply, "ok", False):
        raise PlannerIOError("PLANNER_REPLY_UNCONFIRMED")

    payload = getattr(reply, "payload", None)
    if not isinstance(payload, dict):
        try:
            payload = json.loads(reply.text)
        except (AttributeError, TypeError, ValueError) as error:
            raise PlannerIOError("PLANNER_OUTPUT_INVALID") from error
    return parse_plan_output(payload, board=board)
