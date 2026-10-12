"""Offline walk tests use model choices and keep fact evidence separate from step reports."""

import sys
from pathlib import Path
import json
from copy import deepcopy
from uuid import uuid4

import pytest
from unittest.mock import create_autospec


from orchestration import delivery_setup  # noqa: E402
from agents.planner import service as planning  # noqa: E402
from orchestration import positions  # noqa: E402
from agents.verifier import service  # noqa: E402
from orchestration import session_flow  # noqa: E402
from orchestration import walk as walk_mod  # noqa: E402
from tests.test_run_plan_support import ROOT
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import run_plan                                              # noqa: E402
import run_lean_task                                         # noqa: E402
from tests.support import stub_callers                       # noqa: E402
from agents._model import client as model_mod                        # noqa: E402
from graph import rehydrate                                  # noqa: E402
from orchestration import graph_view, evidence
from agents.planner import service as planning     # noqa: E402
from orchestration import positions as positions_mod  # noqa: E402
from orchestration import preparation, reporting  # noqa: E402
from orchestration import session_flow                       # noqa: E402
from orchestration.graph_view import graph_nodes, needs      # noqa: E402
from agents.planner.service import (                         # noqa: E402
    choice_refusal,
    next_node,
    plan_next,
)
from orchestration.verification import assessment
from agents.verifier import backstops, service  # noqa: E402
from runtime import delivery_commands, dispatch               # noqa: E402
from runtime import session_delivery, session_registry        # noqa: E402
from runtime import credentials                              # noqa: E402
from runtime import session_io                               # noqa: E402
from runtime import session_resources, sessions               # noqa: E402
from skills import bind                                       # noqa: E402

from tests.test_run_plan_support import (
    CONSUMER_ID, FIXTURE_CALL_ID, GOAL_FACT_ID, InventoryPlanner, PRODUCER_ID,
    _reachability_receipts, _reachability_row, checked_observations, credential_graph,
    plan_args, plan_harness, private_source, proved_result,
)


def test_one_bad_quote_does_not_throw_the_rest_of_the_verification_away():
    """A quote taken from the command text is that fact's problem, not the whole turn's.

    walk-158 node 26: the produced fact cited a real receipt line (`uid=0(root)`), two premises
    cited the command text instead of its output, the turn was refused wholesale, and the step that
    had worked was reported as having no evidence at all.
    """
    by_call = {"call-a": {"call_id": "call-a", "stdout": "uid=0(root) gid=0(root)\n", "stderr": ""}}
    claims, dropped = service._credit_verify_claims([
        {"ref": "25", "verdict": "TRUE", "proof": "sufficient", "verifier": "model",
         "call_id": "call-a", "quote": "uid=0(root)"},
        {"ref": "34", "verdict": "TRUE", "proof": "sufficient", "verifier": "model",
         "call_id": "call-a", "quote": "id -u > /tmp/agv_proof.txt"},
        {"ref": "35", "verdict": "UNKNOWN", "proof": "partial", "verifier": "model",
         "call_id": "", "quote": ""},
        {"ref": "36", "verdict": "TRUE", "proof": "sufficient", "verifier": "model",
         "call_id": "call-gone", "quote": "anything"},
    ], by_call)
    assert sorted(claims) == ["25", "35"] and dropped == ["34", "36"]
    assert claims["25"]["verifier"] == "model" and claims["25"]["claimed_verifier"] == "model"

def test_verify_facts_runs_a_verification_round_for_every_proved_node(tmp_path, monkeypatch):
    """The verifier still runs once and preserves UNKNOWN as unconfirmed with a usable source session."""
    from graph import criteria

    document = credential_graph(producer_only=True)
    source, _ = private_source(tmp_path)
    run_root = tmp_path / "run"
    client = InventoryPlanner()
    dispatched = []
    real_verify = service.verify_node

    def driver(card, task, scope, executor, **kwargs):
        dispatched.append(task["node_id"])
        return proved_result()

    plan_harness(monkeypatch, document, driver, client=client)
    stub_callers(monkeypatch, "verify_node", real_verify, callers=(service,))
    assert run_plan.main(plan_args(run_root, source)) == 2
    plan = json.loads((run_root / "plan_result.json").read_text(encoding="utf-8"))

    assert dispatched == [PRODUCER_ID]
    assert [task for task, _ in client.calls] == ["pick_next_node", "verify", "pick_next_node"]
    requested = next(payload for task, payload in client.calls if task == "verify")
    expected = {row["ref"] for row in criteria.node_criteria(document, PRODUCER_ID)}
    expected.update(row["ref"] for row in criteria.to_produce(document, PRODUCER_ID))
    assert expected
    assert {row["ref"] for row in requested["facts"]} == expected

    node = plan["nodes"][PRODUCER_ID]
    block = node["verification"]
    assert block["state"] == "verified"
    assert {row["ref"] for row in block["facts"]} == expected
    assert all(row["verdict"] == "UNKNOWN" for row in block["facts"])
    assert all(row["verdict"] == "UNKNOWN" for row in block["assessments"].values())
    assert node["status"] == "unconfirmed"
    assert plan["proved"] == []
    assert plan["final_goal"] and all(not row["established"] for row in plan["final_goal"])
    assert credentials.read(run_root) == []


def test_the_terminal_facts_are_adjudicated_instead_of_left_to_the_reader():
    """Terminal truth still requires adjudication, now from bound fact evidence rather than status or sessions."""
    document = credential_graph()
    host_map = {"worker": "192.168.93.30"}
    session = {"row_type": "session", "kind": "console_session",
               "logical": "worker", "channel_id": "h-1"}
    for status in ("stopped", "proved"):
        for sessions in ([], [session], [dict(session, kind="closed")]):
            goals = assessment.final_goal_rows(
                document, {CONSUMER_ID: {"status": status}},
                rows=sessions, host_map=host_map)
            assert len(goals) == 1
            assert goals[0]["node_id"] == GOAL_FACT_ID
            assert goals[0]["established"] is False
            assert goals[0]["assessment"]["verdict"] == "UNKNOWN"

    verification = checked_observations(
        document, CONSUMER_ID, {GOAL_FACT_ID: "TRUE"}, host_map=host_map)
    state = {CONSUMER_ID: {"status": "unconfirmed", "verification": verification}}
    for sessions in ([], [session], [dict(session, kind="closed")]):
        goals = assessment.final_goal_rows(document, state, rows=sessions, host_map=host_map)
        assert goals[0]["established"] is True
        assert goals[0]["assessment"]["evidence"][0]["fact_ref"] == GOAL_FACT_ID

    stale = deepcopy(verification)
    stale["binding_epoch"] = "stale"
    goals = assessment.final_goal_rows(
        document, {CONSUMER_ID: {"status": "proved", "verification": stale}},
        rows=[session], host_map=host_map)
    assert goals[0]["established"] is False


def test_a_graph_without_a_declared_goal_says_nothing_rather_than_guessing():
    """图没写 final_goal 就不编：这一条只在图自己声明了终点时才出声。"""
    assert assessment.final_goal_rows({"nodes": [{"id": "1", "type": "AND"}]}, {}) == []


def test_the_reachability_backstop_checks_registered_graph_vantage(tmp_path):
    """Source and target checks remain required, now through registered receipts rather than a new probe."""
    def executor(*args, **kwargs):
        pytest.fail("the receipt checker must not execute a probe")

    calls, issues = _reachability_receipts(tmp_path / "open")
    assert len(calls) == 1 and not issues
    context = {"row": _reachability_row(), "executor": executor,
               "host_map": {"dc": "192.168.93.30"},
               "source_bindings": {"position-pc1": "pc1"}}
    checked = backstops.backstop_reachability(**context, receipts=calls)
    assert checked["state"] == "connected" and checked["verdict"] == "TRUE"
    assert checked["vantage"] == "position-pc1"
    assert checked["evidence"][0]["call_id"] == FIXTURE_CALL_ID
    assert checked["evidence"][0]["source_binding"]["source_host"] == "pc1"

    carrier = {"kind": "ssh", "logical": "pc1", "host": "192.168.52.30", "alive": True}
    missing_binding = backstops.backstop_reachability(
        row=_reachability_row(), executor=executor, receipts=calls, rows=[carrier],
        host_map={"dc": "192.168.93.30"})
    assert missing_binding["verdict"] == "UNKNOWN"
    assert missing_binding["reason"] == "SOURCE_BINDING_UNAVAILABLE"

    for label, options in (
        ("closed", {"port_state": "closed"}),
        ("other-target", {"address": "192.168.93.31"}),
        ("malformed", {"xml": "garbage"}),
    ):
        calls, issues = _reachability_receipts(tmp_path / label, **options)
        assert calls and not issues
        checked = backstops.backstop_reachability(**context, receipts=calls)
        assert checked["state"] == "unknown"
        assert checked["verdict"] == "UNKNOWN"

    calls, issues = _reachability_receipts(tmp_path / "unfinished", read_stop="deadline")
    assert calls == [] and issues
    assert backstops.backstop_reachability(**context, receipts=calls)["verdict"] == "UNKNOWN"


def test_a_native_receipt_offers_its_answer_without_demanding_a_frame():
    """`creds_all` has no frame to show; its captured answer is still the step's evidence."""
    native = {"argv": ["console", "native", "creds_all"]}
    answer = "Username  Domain  Password\nAdministrator WHOAMIANONY <redacted>\n"
    assert evidence._receipt_output(native, "agvm1", answer) == answer
    with pytest.raises(ValueError, match="^RECEIPT_OUTPUT_EMPTY"):
        evidence._receipt_output(native, "agvm1", "   \n")
    with pytest.raises(ValueError, match="^RECEIPT_FRAME_UNCONFIRMED"):
        evidence._receipt_output({"argv": ["console", "shell", "echo hi"]}, "agvm1", "no frame\n")


def test_a_recorded_http_request_is_matched_as_an_object_not_as_text():
    """The journal writes sorted keys, so re-dumping the request must not reject the row.

    walk-138 node 7: every http row was dropped with RECEIPT_REQUEST_UNCONFIRMED because the
    expectation was rebuilt as a string and the key order no longer matched. No http call could
    be evidence, and the delivery check that reads the same rows said "never issued".
    """
    request = {"tool": "http", "method": "GET", "path": "/", "headers": {}, "body": ""}
    natural = ["lean-http-client", json.dumps(request, ensure_ascii=False)]
    assert evidence._receipt_request_matches({"argv": natural}, request, "agvm", {}) is True
    sorted_argv = ["lean-http-client", json.dumps(request, sort_keys=True, ensure_ascii=False)]
    assert evidence._receipt_request_matches({"argv": sorted_argv}, request, "agvm", {}) is True
    assert evidence._receipt_request_matches(
        {"argv": ["lean-http-client", "{}"]}, request, "agvm", {}) is False
    assert evidence._receipt_request_matches({"argv": "not a list"}, request, "agvm", {}) is False


def test_each_node_records_which_upstream_node_made_its_premises_this_round(tmp_path, monkeypatch):
    """Dependency linkage has to be in the record: a premise's producer is named per step."""
    source, _material = private_source(tmp_path)
    run_root = tmp_path / "run"
    document = credential_graph()
    plan_harness(monkeypatch, document, lambda *args, **kwargs: proved_result())
    assert run_plan.main(plan_args(run_root, source)) == 0
    summary = json.loads((run_root / "plan_result.json").read_text(encoding="utf-8"))
    rows = summary["nodes"][CONSUMER_ID]["linkage"]
    assert rows, "a node with premises has to say where they came from"
    assert any(row["proved_by"] == [PRODUCER_ID] for row in rows)
    assert all(isinstance(row["producers"], list) for row in rows)
