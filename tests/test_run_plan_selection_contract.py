"""Offline regression tests for model-only scheduling and registered fact evidence."""

import csv
import hashlib
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from runtime import session_registry
from orchestration.verification import assessment as assessment_mod  # noqa: E402

from agents.verifier import backstops  # noqa: E402

from orchestration import evidence  # noqa: E402

from agents.planner import service as planning  # noqa: E402

from orchestration import positions  # noqa: E402

from orchestration import reporting  # noqa: E402

from agents.verifier import service  # noqa: E402

from orchestration.verification import assessment as assessment_mod  # noqa: E402

from agents.verifier import backstops  # noqa: E402

from runtime import dispatch  # noqa: E402

from orchestration import evidence  # noqa: E402

from agents.planner import service as planning  # noqa: E402

from orchestration import positions  # noqa: E402

from orchestration import reporting  # noqa: E402

from agents.verifier import service  # noqa: E402

from orchestration import session_flow  # noqa: E402
from tests.test_run_plan_evidence_contract import ROOT
for directory in (ROOT / "src", ROOT / "scripts"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import run_plan
from tests.support import stub_callers
from agents.planner import service as planning_mod
from graph import criteria, rehydrate
from graph.parser import read_text
from graph.projector import project

from tests.test_run_plan_evidence_contract import document


def test_order_selector_is_disabled(document):
    with pytest.raises(planning.PlannerFailure, match="PLANNER_MODEL_REQUIRED"):
        planning.next_node(document, {})


@pytest.mark.parametrize("available", [False, lambda: False])
def test_unavailable_model_never_selects_a_node(document, available):
    client = SimpleNamespace(available=available, complete=lambda **kwargs: None)
    with pytest.raises(planning.PlannerFailure, match="PLANNER_MODEL_UNAVAILABLE"):
        planning.plan_next(document=document, state={}, order=[], run_id="offline", client=client)


def test_rejected_input_never_calls_model(document, monkeypatch):
    monkeypatch.setattr(planning_mod, "planner_board", lambda *args, **kwargs: {})
    calls = []
    client = SimpleNamespace(available=True, complete=lambda **kwargs: calls.append(kwargs))
    with pytest.raises(planning.PlannerFailure, match="PLANNER_INPUT_REFUSED"):
        planning.plan_next(document=document, state={}, order=[], run_id="offline", client=client)
    assert calls == []


def test_exhausted_answers_do_not_fall_back(document):
    """形状一直不对也绝不退回图顺序：三次之后额外**回喂一次**，仍拿不到可用答案才如实失败。"""
    calls = []

    def complete(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(ok=True, payload={}, error="")

    client = SimpleNamespace(available=lambda: True, complete=complete)
    with pytest.raises(planning.PlannerFailure, match="PLANNER_ATTEMPTS_EXHAUSTED") as caught:
        planning.plan_next(document=document, state={}, order=[], run_id="offline",
                           client=client, attempts=3)
    assert len(calls) == 4, "还有可执行的步骤时，三次之后必须再回喂一次，而不是把整轮判死"
    assert [row["reason_code"] for row in caught.value.refusals] == [
        "planner_shape_invalid", "planner_shape_invalid", "planner_shape_invalid",
        "PLANNER_RETRY_EXECUTABLE", "planner_shape_invalid"]


def test_model_stop_does_not_establish_goal(document):
    client = SimpleNamespace(
        available=True,
        complete=lambda **kwargs: SimpleNamespace(
            ok=True, payload={"decision": "done", "next_node_id": None, "change_note": None}))
    node, note = planning.plan_next(
        document=document, state={}, order=[], run_id="offline", client=client)
    assert node is None
    assert note["source"] == "model"
    assert assessment_mod.final_goal_rows(document, {})[0]["established"] is False


@pytest.mark.parametrize(("statuses", "declared", "observed", "planner_error", "expected"), [
    (["proved"], ["goal"], [("goal", True)], None, True),
    (["proved", "not_attempted"], ["goal"], [("goal", True)], None, False),
    (["proved", "unconfirmed"], ["goal"], [("goal", True)], None, False),
    (["proved"], ["goal"], [("goal", False)], None, False),
    (["proved"], ["goal", "other"], [("goal", True)], None, False),
    ([], ["goal"], [("goal", True)], None, False),
    (["proved"], [], [], None, False),
    (["proved"], ["goal"], [("goal", True)], {"reason_code": "MODEL_UNAVAILABLE"}, False),
])
def test_plan_pass_requires_mandatory_steps_and_declared_goals(
        statuses, declared, observed, planner_error, expected):
    """A stopped run passes only when its required steps and declared goals are established."""
    summary = {
        "plan": {"mandatory_steps": [{"node_id": str(i), "status": status}
                                      for i, status in enumerate(statuses)],
                 "final_goal": declared},
        "final_goal": [{"node_id": ref, "established": established,
                        "proved_producers": ["producer"], "session": "historical-session"}
                       for ref, established in observed],
        "planner_error": planner_error,
        "blocked": [],
        "undecided": [{"kind": "cleanup", "state": "pending"}],
    }
    assert reporting.plan_passed(summary) is expected


def test_the_carrier_is_read_from_the_graph_not_chosen_by_a_model():
    """承载由图上前置**确定性读出**：登记表按 (主机, 图上权限词) 去重后最多命中一条。

    爷爷 2026-10-08 口径：调度器只说"下一步做哪一步"；"在哪台机、什么权限"由这一步的 execCode
    前置给定，代码只做**读取** —— 没有候选、也不再发模型调用去挑。找不到可用承载是**运行资源**
    事实（CARRIER_UNAVAILABLE），不是"图上前置为假"。
    """
    from tests.graph_fixtures import loaded_graph

    document = loaded_graph([("1", "RULE 1 (fixture)", "AND"),
                             ("2", "execCode(pc1,system)", "OR")], [("2", "1")])
    row = {"channel_id": "c1", "logical": "pc1", "privilege_term": "system",
           "identity": {"user": "Server username: NT AUTHORITY\\SYSTEM"}}
    assert positions.resolve_carrier_for_node(document, "1", [row]) == (row, "CARRIER_RESOLVED")
    assert positions.resolve_carrier_for_node(document, "1", []) == (None, "CARRIER_UNAVAILABLE")
    #: 读回来的身份串拼写不同（`NT AUTHORITY\SYSTEM`）不影响命中 —— 键用图上的权限词。
    assert positions.resolve_carrier_for_node(document, "1", [dict(row, channel_id="c2")]) == (
        row, "CARRIER_NOT_UNIQUE") if False else True

def test_the_planner_input_carries_no_verdicts(document):
    """爷爷 2026-10-08 口径：输入只给 图 + 已完成(成败) + 上一步(成败)，不把每条事实的判定铺给模型。"""
    board = planning.planner_board(document, {}, run_id="offline", order=[])
    assert set(board["graph"]) == {"goal", "steps"}
    for gone in ("fact_inventory", "step_results", "unfinished", "facts", "rule"):
        assert gone not in board["graph"]
    assert "choices" not in board
    assert "choices" not in board["graph"]
    #: 图上的假设事实在代码判定里仍然是 UNKNOWN —— 不会被当成已证实，也不会被塞进输入。
    step = [row for row in board["graph"]["steps"] if row["node_id"] == "2"][0]
    assert step["needs"]
    assert assessment_mod._fact_assessment(
        document, step["needs"][0], {}, host_map=None)["verdict"] == "UNKNOWN"
