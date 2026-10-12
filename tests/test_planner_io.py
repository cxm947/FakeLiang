"""Planner IO: 5-field wire input (graph / run_id / done / last_step / handoffs), scenario read off
the values, structure only.

The scenario is never guessed from which keys are present; it is read off the values, and each
scenario has exactly one legal combination. ``blocked`` is a skill gap recorded at the planning
hand-off - it is not a target failure and the node stays unfinished.
"""

import unittest

import pytest

from agents.planner import io as planner_io
from agents.planner.io import PlannerIOError

GRAPH = {"goal": ["43", "47"],
         "steps": [{"node_id": "A", "needs": ["1"], "produces": ["2"]},
                   {"node_id": "B", "needs": ["2"], "produces": ["3"]}]}
REASON = "本节点所需验证技能无可用实现，本项未派发；请考虑其他当前允许的节点。"


def plan_input(**over):
    base = {"graph": GRAPH, "run_id": "demo-run", "done": [], "last_step": None, "handoffs": []}
    base.update(over)
    return base


def test_done_lists_attempted_steps_with_their_outcome():
    """爷爷 2026-10-08："已完成节点 + 成败情况" —— done 收已尝试的步骤及结果，不只是成功的。"""
    parsed = planner_io.parse_plan_input(plan_input(
        done=[{"node_id": "A", "status": "success"},
              {"node_id": "B", "status": "failed", "reason": REASON}],
        last_step={"node_id": "B", "status": "failed", "reason": REASON}))
    assert parsed["input"]["done"][1] == {"node_id": "B", "status": "failed", "reason": REASON}
    for broken in ([{"node_id": "A"}],
                   [{"node_id": "A", "status": "maybe"}],
                   [{"node_id": "A", "status": "failed"}],
                   [{"node_id": "", "status": "success"}],
                   [{"node_id": "A", "status": "success"}, {"node_id": "A", "status": "success"}],
                   [{"node_id": "A", "status": "success", "extra": 1}],
                   [{"node_id": "Z", "status": "success"}]):
        with pytest.raises(planner_io.PlannerIOError):
            planner_io.parse_plan_input(plan_input(done=broken))


def test_the_graph_is_plain_data_without_descriptions():
    """爷爷 2026-10-08：planner 输入只要单纯的图（节点 + 边），不要任何描述信息。"""
    slim = {"goal": ["43", "47"],
            "steps": [{"node_id": "A", "needs": ["1"], "produces": ["2"]}]}
    parsed = planner_io.parse_plan_input(plan_input(graph=slim))
    assert parsed["input"]["graph"] == slim
    with pytest.raises(planner_io.PlannerIOError):
        planner_io.parse_plan_input(plan_input(graph={"goal": ["43"], "steps": [],
                                                       "facts": {"43": "meaning"}}))


def test_a_handoff_row_is_validated_and_an_empty_list_is_the_first_run():
    """The executor's report is part of the planner's input, so its shape is checked like the rest."""
    from agents.planner import io as planner_io

    row = {"node_id": "A", "reason_codes": ["EFFECT_UNRESOLVED"],
           "requested_upstream_decision": {"options": ["clarify_effect"]},
           "alternatives": ["exploit.redis_unauth_write"]}
    parsed = planner_io.parse_plan_input(plan_input(handoffs=[row]))
    assert parsed["input"]["handoffs"][0]["requested_upstream_decision"] == {
        "options": ["clarify_effect"]}
    with pytest.raises(planner_io.PlannerIOError):
        planner_io.parse_plan_input(plan_input(handoffs=[{"reason_codes": []}]))
    with pytest.raises(planner_io.PlannerIOError):
        planner_io.parse_plan_input(plan_input(handoffs={"node_id": "A"}))


def answer(**over):
    base = {"decision": "continue", "next_node_id": "B", "change_note": None}
    base.update(over)
    return base


class ScenarioTests(unittest.TestCase):
    def test_first_run(self):
        parsed = planner_io.parse_plan_input(plan_input())
        self.assertEqual("first", parsed["scenario"])
        self.assertEqual([], parsed["input"]["done"])
        self.assertIsNone(parsed["input"]["last_step"])

    def test_success_continuation(self):
        parsed = planner_io.parse_plan_input(plan_input(
            done=[{"node_id": "A", "status": "success"}],
            last_step={"node_id": "A", "status": "success"}))
        self.assertEqual("success", parsed["scenario"])

    def test_failed_replan(self):
        parsed = planner_io.parse_plan_input(plan_input(
            done=[{"node_id": "B", "status": "failed", "reason": REASON}],
            last_step={"node_id": "B", "status": "failed", "reason": REASON}))
        self.assertEqual("failed", parsed["scenario"])

    def test_blocked_replan(self):
        parsed = planner_io.parse_plan_input(plan_input(
            done=[{"node_id": "B", "status": "blocked", "reason": REASON}],
            last_step={"node_id": "B", "status": "blocked", "reason": REASON}))
        self.assertEqual("blocked", parsed["scenario"])

    def test_null_strings_are_not_null(self):
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_input(plan_input(
                last_step={"node_id": "null", "status": "success"}))

    def test_unknown_result_value_is_refused(self):
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_input(plan_input(
                last_step={"node_id": "B", "status": "unknown", "reason": REASON}))


class CombinationTests(unittest.TestCase):
    def test_a_first_run_carries_no_progress(self):
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_input(plan_input(done=[{"node_id": "A", "status": "success"}]))

    def test_a_result_needs_its_node(self):
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_input(plan_input(last_step={"status": "success"}))
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_input(plan_input(
                last_step={"status": "failed", "reason": REASON}))

    def test_success_node_must_be_done(self):
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_input(plan_input(
                done=[{"node_id": "B", "status": "success"}],
                last_step={"node_id": "A", "status": "success"}))
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_input(plan_input(
                done=[{"node_id": "A", "status": "success"}],
                last_step={"node_id": "A", "status": "success", "reason": REASON}))

    def test_last_step_must_match_its_done_row(self):
        """上一步必须出现在 done 里、且结果一致 —— 否则输入自相矛盾，直接拒。"""
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_input(plan_input(
                last_step={"node_id": "B", "status": "failed", "reason": REASON}))
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_input(plan_input(
                done=[{"node_id": "B", "status": "success"}],
                last_step={"node_id": "B", "status": "failed", "reason": REASON}))
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_input(plan_input(
                done=[{"node_id": "B", "status": "failed", "reason": REASON}],
                last_step={"node_id": "B", "status": "failed"}))

    def test_done_ids_are_unique_non_empty_strings(self):
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_input(plan_input(
                done=[{"node_id": "A", "status": "success"},
                      {"node_id": "A", "status": "success"}]))
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_input(plan_input(done=[{"node_id": "  ", "status": "success"}]))


class ShapeTests(unittest.TestCase):
    def test_missing_and_extra_keys_are_refused(self):
        broken = plan_input()
        broken.pop("run_id")
        with self.assertRaises(PlannerIOError) as caught:
            planner_io.parse_plan_input(broken)
        self.assertIn("exactly graph, run_id, done, last_step, handoffs", str(caught.exception))
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_input(plan_input(progress={}))
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_input(plan_input(completed_node_ids=[]))

    def test_graph_must_carry_goal_steps_and_facts(self):
        for broken in ("Hongri7_v2.action_graph.json", None, {},
                       {"goal": [], "steps": [], "extra": 1},
                       {"goal": [], "facts": {}}):
            with self.subTest(graph=broken):
                with self.assertRaises(PlannerIOError):
                    planner_io.parse_plan_input(plan_input(graph=broken))

    def test_run_id_must_be_a_non_empty_string(self):
        for broken in ("", "   ", None, 7):
            with self.subTest(run_id=broken):
                with self.assertRaises(PlannerIOError):
                    planner_io.parse_plan_input(plan_input(run_id=broken))

class OutputTests(unittest.TestCase):
    def test_continue_carries_a_node_and_no_change_note_on_p1(self):
        parsed = planner_io.parse_plan_output(answer(), scenario="first")
        self.assertEqual({"decision": "continue", "next_node_id": "B", "change_note": None},
                         parsed)

    def test_done_carries_null(self):
        parsed = planner_io.parse_plan_output(
            {"decision": "done", "next_node_id": None, "change_note": None}, scenario="success")
        self.assertEqual("done", parsed["decision"])
        self.assertIsNone(parsed["next_node_id"])

    def test_decisions_and_node_rules(self):
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_output(answer(decision="skip"), scenario="first")
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_output(answer(next_node_id=None), scenario="first")
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_output(
                {"decision": "done", "next_node_id": "B", "change_note": None}, scenario="first")

    def test_p1_change_note_is_optional_not_forbidden(self):
        """P1 不要求 change_note，也不因为它写了就拒绝。

        2026-10-06 walk-45 实测：模型习惯在 P1 也解释一句，而形状规则只准它留空 —— 于是每一步
        都白撞 3 次、整轮退回静态顺序，规划器就不再是模型驱动的了。语义规则留在 P2 那侧。
        """
        for scenario in ("first", "success"):
            with self.subTest(scenario=scenario):
                parsed = planner_io.parse_plan_output(answer(change_note="转向支线"),
                                                      scenario=scenario)
                assert parsed["next_node_id"] == "B"
                assert parsed["change_note"] == "转向支线"

    def test_p2_change_note_is_required_even_for_done(self):
        for scenario in ("failed", "blocked"):
            with self.subTest(scenario=scenario):
                with self.assertRaises(PlannerIOError):
                    planner_io.parse_plan_output(answer(change_note=None), scenario=scenario)
                with self.assertRaises(PlannerIOError):
                    planner_io.parse_plan_output(
                        {"decision": "done", "next_node_id": None, "change_note": None},
                        scenario=scenario)
                parsed = planner_io.parse_plan_output(
                    answer(change_note="原节点受阻，改选独立支线"), scenario=scenario)
                self.assertEqual("原节点受阻，改选独立支线", parsed["change_note"])

    def test_exactly_three_fields(self):
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_output(
                {"decision": "continue", "next_node_id": "B", "change_note": None,
                 "why": "extra"}, scenario="first")

    def test_unknown_scenario_is_a_program_error(self):
        with self.assertRaises(PlannerIOError):
            planner_io.parse_plan_output(answer(), scenario="mystery")
