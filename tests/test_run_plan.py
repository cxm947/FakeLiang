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
    ACCOUNT_FACT_ID, CONSUMER_ID, FIXTURE_CALL_ID, GOAL_FACT_ID, InventoryPlanner,
    PRODUCER_ID, StubPlanner, _loaded_test_graph, _reachability_receipts, _reachability_row,
    checked_observations, credential_graph, delivery_fixture, graph, plan_args, plan_harness,
    private_source, proved_result, walk,
)


def test_order_follows_the_graph_producers():
    """Dependency ordering still holds when a fixture model chooses every step."""
    observations = {"6": "TRUE", "4": "TRUE", "3": "TRUE", "1": "TRUE", "9": "TRUE"}
    assert walk(graph(), {}, observations=observations) == ["14", "12", "7", "5", "2"]


def test_a_stopped_producer_keeps_its_consumers_unoffered():
    """Downstream blocking still holds when the stopped producer has no output evidence."""
    observations = {"6": "TRUE", "4": "UNKNOWN", "3": "TRUE", "1": "TRUE", "9": "TRUE"}
    assert walk(graph(), {"12": "stopped"}, observations=observations) == ["14", "12"]


def test_the_lab_graph_covers_every_execution_node_in_dependency_order():
    """The lab graph still covers every action through model choices checked against fixture evidence."""
    from graph import criteria

    document = rehydrate.load_file(ROOT / "tests/fixtures/hongri7/reference.action_graph.json")
    observations = {fact["ref"]: "TRUE" for node in graph_nodes(document)
                    for fact in criteria.to_produce(document, node["id"])}
    order = walk(document, {}, observations=observations)
    assert len(order) == len(set(order))
    assert sorted(order) == sorted(str(node["id"]) for node in graph_nodes(document))


def test_the_walk_contract_states_when_stopping_is_allowed():
    """爷爷 2026-10-08 口径：每条路径都要被真正尝试；只有"没有可执行的"才能停。"""
    contract = planning.PLANNER_SYSTEM
    assert "nothing is executable" in contract
    assert "has never been attempted" in contract
    assert "does not retire its other producers" in contract


def test_a_stop_with_a_step_still_executable_is_refused_once():
    """一个目标成立不会让它的其他路径变成可选：要么继续走，要么如实说明为什么停。"""
    from tests.graph_fixtures import loaded_graph

    document = loaded_graph([("1", "RULE 1 (fixture)", "AND")], [])
    answer = {"decision": "done", "next_node_id": None, "change_note": "goal established"}
    reply = model_mod.ModelReply(ok=True, payload=answer, text=json.dumps(answer))

    class Stops:
        def available(self):
            return True

        def complete(self, **kwargs):
            return reply

    node, row = plan_next(document=document, state={}, order=[], run_id="offline",
                          client=Stops(), attempts=3)
    assert node is None
    assert [item["reason_code"] for item in row["refusals"]] == ["WALK_NOT_EXHAUSTED"]
    assert row["stop_reason"] == "model_gave_up"


# --------------------------------------------------------------- the pick, checked one node at a time

def test_any_one_producer_satisfies_a_fact():
    """Either producer still suffices when it supplies evidence for the shared fact."""
    document = _loaded_test_graph(
        [("5", "RULE 1 (consumer)", "AND"), ("7", "RULE 2 (producer)", "AND"),
         ("19", "RULE 3 (alternative)", "AND"),
         ("6", "netAccess(target,tcp,443)", "OR"),
         ("1", "execCode(target,admin)", "OR"),
         ("8", "attackerLocated(origin_a)", "LEAF"),
         ("20", "attackerLocated(origin_b)", "LEAF")],
        [("8", "7"), ("20", "19"), ("7", "6"), ("19", "6"), ("6", "5"), ("5", "1")])
    for producer in ("7", "19"):
        verification = checked_observations(document, producer, {"6": "TRUE"})
        assert choice_refusal(document, "5", {
            producer: {"status": "unconfirmed", "verification": verification}}) is None
    refused = choice_refusal(
        document, "5", {"7": {"status": "proved"}, "19": {"status": "proved"}})
    assert refused["reason_code"] == "fact_unavailable"
    assert [{k: r[k] for k in ("ref", "verdict")} for r in refused["facts"]] == [
        {"ref": "6", "verdict": "UNKNOWN"}]


def test_a_pick_is_checked_by_name_and_never_by_a_candidate_list():
    """A requested node still receives a named refusal without a program-generated shortlist."""
    document = graph()
    assert choice_refusal(document, "9", {})["reason_code"] == "node_unknown"
    assert choice_refusal(document, "5", {"5": {"status": "proved"}})[
        "reason_code"] == "node_already_decided"
    refused = choice_refusal(document, "5", {})
    assert refused["reason_code"] == "fact_unavailable"
    assert [{k: r[k] for k in ("ref", "verdict")} for r in refused["facts"]] == [
        {"ref": "3", "verdict": "UNKNOWN"}]
    board = planning.planner_board(document, {}, run_id="offline", order=[])
    assert "choices" not in board
    assert "choices" not in board["graph"]
    #: 给模型的只有这三样：图（步骤+事实含义）、已完成成败、上一步成败。
    assert set(board["graph"]) == {"goal", "steps"}
    assert board["graph"]["steps"][0]["node_id"] == "2"
    assert "needs" in board["graph"]["steps"][0] and "produces" in board["graph"]["steps"][0]


def test_a_refused_pick_goes_back_to_the_planner_with_the_reason():
    """An illegal choice still reaches the model as a named refusal before a valid choice is accepted."""
    document = graph()
    observations = {"6": "TRUE", "4": "TRUE", "3": "TRUE"}
    order = ["14", "12", "7"]
    state = {node_id: {"status": "proved",
                      "verification": checked_observations(document, node_id, observations)}
             for node_id in order}
    planner = StubPlanner([
        {"decision": "continue", "next_node_id": "2", "change_note": None},
        {"decision": "continue", "next_node_id": "5", "change_note": None},
    ])
    node, note = plan_next(document=document, state=state, order=order,
                           run_id="offline", client=planner)
    assert str(node["id"]) == "5"
    assert note["source"] == "model" and note["chosen"] == "5"
    assert len(planner.seen) == 2
    assert note["refusals"][0]["reason_code"] == "fact_unavailable"
    assert [{k: r[k] for k in ("ref", "verdict")}
            for r in note["refusals"][0]["facts"]] == [{"ref": "1", "verdict": "UNKNOWN"}]
    assert "fact_unavailable" in planner.seen[1]
    assert '"ref": "1"' in planner.seen[1]


def test_an_unavailable_model_is_reported_without_graph_order_fallback(monkeypatch):
    """Replace the retired fallback expectation with an explicit model-unavailable failure."""
    document = graph()
    state = {"14": {"status": "proved",
                    "verification": checked_observations(document, "14", {"6": "TRUE"})}}
    original = deepcopy(state)
    stub_callers(monkeypatch, "next_node",
                        lambda *args, **kwargs: pytest.fail("graph-order fallback was called"), callers=(planning,))
    with pytest.raises(planning.PlannerFailure) as caught:
        plan_next(document=document, state=state, order=["14"], run_id="offline",
                  client=model_mod.NoModel())
    assert caught.value.reason_code == "PLANNER_MODEL_UNAVAILABLE"
    assert state == original


def test_the_walk_builds_the_model_client_with_the_wire_it_was_given(tmp_path, monkeypatch):
    """--model-wire 必须真的接到客户端上。

    2026-10-06 第一次正规端到端跑到这一条：参数收下了、没人用，于是 planner 走 /chat/completions
    撞上 router 的 404，整轮每个节点都停在 LEAN_MODEL_REPLY_UNAVAILABLE —— 参数收下不用比不写更坏。
    """
    source, _material = private_source(tmp_path)
    run_root = tmp_path / "run"
    seen = {}

    def fake_client_from_env(**kwargs):
        seen.update(kwargs)
        return model_mod.NoModel()

    # 先让 harness 把它自己那份假客户端装上，再换成会记账的这一份（顺序反过来会被 harness 盖掉）。
    plan_harness(monkeypatch, credential_graph(), lambda *a, **k: proved_result())
    monkeypatch.setattr(model_mod, "client_from_env", fake_client_from_env)
    run_plan.main(plan_args(run_root, source) + ["--model-wire", "responses"])
    assert seen.get("wire") == "responses"
    assert seen.get("name") == "offline"


def test_a_planner_that_gives_up_reports_what_was_done_without_a_cleanup_ledger(tmp_path,
                                                                                monkeypatch):
    """Scheduling stopping is not the same as nothing having happened: report what was done.

    The engine keeps no end-of-round cleanup ledger any more (the lab snapshot rolls back), so
    the stop report carries the plan identity and the undecided list, not a settlement table.
    """
    from types import SimpleNamespace

    class DeadPlanner:
        """A fixture model that never gives the scheduler an answer it can use."""

        def available(self):
            return True

        def complete(self, *, task, system, user, timeout=None, **kwargs):
            return SimpleNamespace(ok=False, error="fixture: no answer", payload=None, text="")

    run_root = tmp_path / "run"
    plan_harness(monkeypatch, credential_graph(), lambda *args, **kwargs: proved_result(),
                 client=DeadPlanner())
    assert run_plan.main(plan_args(run_root, private_source(tmp_path)[0])) == 2
    summary = json.loads((run_root / "plan_result.json").read_text(encoding="utf-8"))
    assert summary["planner_error"]["reason_code"]
    assert "settlement" not in summary
    assert "not a pass" in summary["note"]
    assert summary["proved"] == []
    assert (run_root / "planner_error.json").is_file()

def test_a_blocked_attempt_says_which_node_could_unblock_it():
    """A refusal has to name the producer, or the scheduler keeps proposing what cannot run."""
    document = credential_graph()
    node = next(item for item in document["nodes"] if str(item["id"]) == CONSUMER_ID)
    refusal = planning.choice_refusal(document, CONSUMER_ID, {}, host_map=None)
    assert refusal and refusal["reason_code"] == "fact_unavailable"
    rows = refusal["facts"]
    assert rows and all("producible_by" in row for row in rows)
    assert any(PRODUCER_ID in row["producible_by"] for row in rows)


def test_repeating_unavailable_picks_are_nudged_with_what_is_executable_now():
    """模型连着提"前置没满足"的步骤时：回喂一次"现在就能做的"，而不是把整轮判死。"""
    document = graph()
    observations = {"6": "TRUE", "4": "TRUE", "3": "TRUE"}
    order = ["14", "12", "7"]
    state = {node_id: {"status": "proved",
                       "verification": checked_observations(document, node_id, observations)}
             for node_id in order}
    planner = StubPlanner([
        {"decision": "continue", "next_node_id": "2", "change_note": None},
        {"decision": "continue", "next_node_id": "2", "change_note": None},
        {"decision": "continue", "next_node_id": "2", "change_note": None},
        {"decision": "continue", "next_node_id": "5", "change_note": None},
    ])
    node, note = plan_next(document=document, state=state, order=order,
                           run_id="offline", client=planner)
    assert str(node["id"]) == "5"
    assert len(planner.seen) == 4, "三次越权提案之后必须多给一次回喂"
    assert "PLANNER_RETRY_EXECUTABLE" in planner.seen[3]
    assert "\"5\"" in planner.seen[3], "回喂要点名现在就能做的步骤"
    assert [row["reason_code"] for row in note["refusals"][:3]] == ["fact_unavailable"] * 3
    assert note["refusals"][3]["executable_now"] == ["5"]
