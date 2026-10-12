from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

from tests.test_graph_planner_contract_round import _SRC
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from agents.planner import io as planner_io
from graph.criteria import fact_row, node_criteria, to_produce
from graph.parser import Graph, Node
from graph.projector import project
from graph.protocol import transport_protocol
from graph.rehydrate import GraphContractError, _fold_transport, load_document

from tests.test_graph_planner_contract_round import (
    assessment, chain_document,
)


class PlannerContractRoundTests(unittest.TestCase):
    def setUp(self):
        self.document, self.seed, self.pairs = chain_document(2)
        self.first = self.pairs[0][0]
        self.second = self.pairs[1][0]

    def settings(self):
        actions = [action for action, _ in self.pairs]
        return {
            "run_id": "run-1",
            "node_states": {},
            "last_result": None,
            "handoffs": [],
            "assessments": {},
            "positions": {
                action: {"position-" + action: {"host": "runner", "kind": "local"}}
                for action in actions
            },
            "probes": {
                action: {"probe-" + action: {"host": "runner", "kind": "fact-check"}}
                for action in actions
            },
            "unsettled": {},
            "resource_conflicts": {},
            "remaining_budget": 4,
            "binding_epoch": "binding-1",
        }

    def board(self, **changes):
        settings = self.settings()
        settings.update(changes)
        return planner_io.build_plan_board(self.document, **settings)

    def reply(self, board, **changes):
        value = {
            "decision": "choose",
            "board_id": board.input["board_id"],
            "node_id": self.first,
            "phase": "observe",
            "candidate_id": None,
            "reason": "Inspect the required fact",
        }
        value.update(changes)
        return value

    def refuse(self, code, board, **changes):
        with self.assertRaises(planner_io.PlannerIOError) as raised:
            planner_io.parse_plan_output(self.reply(board, **changes), board=board)
        self.assertEqual(raised.exception.reason_code, code)
        self.assertEqual(raised.exception.as_refusal()["reason_code"], code)
        return raised.exception

    def test_the_five_field_entry_point_remains_available(self):
        parsed = planner_io.parse_plan_input({
            "graph": {"goal": [], "steps": []},
            "run_id": "walk",
            "done": [],
            "last_step": None,
            "handoffs": [],
        })
        answer = planner_io.parse_plan_output(
            {"decision": "continue", "next_node_id": "2", "change_note": None},
            scenario=parsed["scenario"],
        )
        self.assertEqual(answer["next_node_id"], "2")

    def test_public_input_is_an_inventory_without_route_or_step_candidates(self):
        board = self.board()
        self.assertEqual(set(board.input["node_states"]), {self.first, self.second})
        self.assertEqual(set(board.input["unfinished"]), {self.first, self.second})
        self.assertEqual(board.input["node_states"][self.first]["status"], "pending")
        self.assertTrue({
            "choices", "eligible", "blocked", "candidate_ids", "positions", "probes",
        }.isdisjoint(board.input))
        encoded = json.dumps(board.input)
        self.assertNotIn("position-" + self.first, encoded)
        self.assertNotIn("probe-" + self.first, encoded)

    def test_model_claim_does_not_replace_an_assessment(self):
        board = self.board(claimed_verdicts={self.seed: "TRUE"})
        row = board.input["dependencies"][self.first][0]
        self.assertEqual(row["declaration"]["kind"], "assumption")
        self.assertEqual(row["claimed_verdict"], "TRUE")
        self.assertEqual(row["assessment"]["verdict"], "UNKNOWN")
        error = self.refuse("PRECONDITIONS_UNCONFIRMED", board, phase="execute")
        self.assertEqual(error.facts, [{"fact_ref": self.seed, "verdict": "UNKNOWN"}])

    def test_observation_does_not_erase_declaration_identity(self):
        board = self.board(assessments={self.seed: assessment()})
        row = board.input["dependencies"][self.first][0]
        self.assertEqual(row["declaration"]["kind"], "assumption")
        self.assertEqual(row["assessment"]["verdict"], "TRUE")
        answer = planner_io.parse_plan_output(
            self.reply(board, phase="execute"), board=board,
        )
        self.assertEqual(answer["candidate_id"], "position-" + self.first)

    def test_unknown_premises_allow_only_a_concrete_observation_route(self):
        board = self.board()
        answer = planner_io.parse_plan_output(self.reply(board), board=board)
        self.assertEqual(answer["candidate_id"], "probe-" + self.first)
        self.refuse("PRECONDITIONS_UNCONFIRMED", board, phase="execute")
        self.refuse("NO_OBSERVATION_ROUTE", self.board(probes={}))

    def test_completed_producer_is_not_fact_evidence(self):
        board = self.board(node_states={self.first: {"status": "completed"}})
        self.refuse(
            "PRECONDITIONS_UNCONFIRMED", board,
            node_id=self.second, phase="execute",
        )

    def test_one_proven_fact_does_not_require_every_alternative_producer(self):
        document, _, pairs = chain_document(2, alternate=True)
        settings = self.settings()
        settings["node_states"] = {pairs[0][0]: {"status": "completed"}}
        settings["assessments"] = {pairs[0][1]: assessment()}
        board = planner_io.build_plan_board(document, **settings)
        self.assertEqual(board.input["node_states"]["900"]["status"], "pending")
        answer = planner_io.parse_plan_output(
            self.reply(board, node_id=pairs[1][0], phase="execute"),
            board=board,
        )
        self.assertEqual(answer["node_id"], pairs[1][0])

    def test_selected_node_is_refused_without_substitution(self):
        self.refuse("PLANNER_NODE_UNKNOWN", self.board(), node_id="99999")
        board = self.board(node_states={self.first: {"status": "completed"}})
        self.refuse("NODE_ALREADY_COMPLETED", board, phase="execute")
        answer = planner_io.parse_plan_output(self.reply(board), board=board)
        self.assertEqual(answer["phase"], "observe")

    def test_operational_refusals_have_distinct_reasons(self):
        cases = (
            ("PLANNER_BUDGET_EXHAUSTED", {"remaining_budget": 0}),
            ("NODE_ALREADY_RUNNING", {
                "node_states": {self.first: {"status": "running"}},
            }),
            ("NODE_CALL_UNRESOLVED", {"unsettled": {self.first: ["call-1"]}}),
            ("RESOURCE_CONFLICT", {"resource_conflicts": {self.first: ["resource-1"]}}),
        )
        for code, changes in cases:
            with self.subTest(code=code):
                self.refuse(code, self.board(**changes))

    def test_missing_execution_position_is_refused(self):
        board = self.board(
            assessments={self.seed: assessment()},
            positions={},
        )
        self.refuse("NO_EXECUTION_POSITION", board, phase="execute")

    def test_ambiguous_bindings_are_not_chosen_by_order(self):
        board = self.board(probes={
            self.first: {
                "probe-a": {"host": "a", "kind": "fact-check"},
                "probe-b": {"host": "b", "kind": "fact-check"},
            },
        })
        self.refuse("PLANNER_CANDIDATE_REQUIRED", board)
        self.refuse("PLANNER_CANDIDATE_NOT_ELIGIBLE", board, candidate_id="invented")
        answer = planner_io.parse_plan_output(
            self.reply(board, candidate_id="probe-b"), board=board,
        )
        self.assertEqual(answer["candidate_id"], "probe-b")

    def test_stop_does_not_establish_completion(self):
        board = self.board()
        before = deepcopy(board.input)
        answer = planner_io.parse_plan_output(
            self.reply(
                board, decision="stop", node_id=None,
                phase=None, candidate_id=None,
            ),
            board=board,
        )
        self.assertEqual(answer["decision"], "stop")
        self.assertEqual(board.input, before)
        self.assertNotIn("goal_proved", answer)

    def test_snapshot_covers_evidence_bindings_and_budget(self):
        original = self.board()
        variants = (
            self.board(remaining_budget=3),
            self.board(assessments={self.seed: assessment()}),
            self.board(positions={
                self.first: {"position-" + self.first: {"host": "different"}},
            }),
            self.board(unsettled={self.first: ["call-1"]}),
            self.board(last_result={
                "node_id": self.first,
                "status": "unknown",
                "call_ids": ["call-1"],
                "failure_reason": "READ_DEADLINE",
            }),
        )
        for changed in variants:
            with self.subTest(board_id=changed.input["board_id"]):
                with self.assertRaises(planner_io.PlannerIOError) as raised:
                    planner_io.parse_plan_output(self.reply(original), board=changed)
                self.assertEqual(raised.exception.reason_code, "PLANNER_BOARD_STALE")

    def test_board_copies_inputs_and_detects_internal_mutation(self):
        settings = self.settings()
        board = planner_io.build_plan_board(self.document, **settings)
        settings["probes"][self.first].clear()
        answer = planner_io.parse_plan_output(self.reply(board), board=board)
        self.assertEqual(answer["candidate_id"], "probe-" + self.first)

        board.input["remaining_budget"] = 1
        self.refuse("PLANNER_BOARD_CHANGED", board)

    def test_invalid_or_stale_assessments_are_rejected(self):
        cases = (
            ("PLANNER_ASSESSMENT_STALE", assessment(epoch="old-binding")),
            ("PLANNER_ASSESSMENT_UNGROUNDED", {
                "verdict": "TRUE",
                "checker": None,
                "evidence": [],
                "binding_epoch": None,
            }),
        )
        for code, value in cases:
            with self.subTest(code=code):
                with self.assertRaises(planner_io.PlannerIOError) as raised:
                    self.board(assessments={self.seed: value})
                self.assertEqual(raised.exception.reason_code, code)

        with self.assertRaises(planner_io.PlannerIOError) as raised:
            self.board(remaining_budget=True)
        self.assertEqual(raised.exception.reason_code, "PLANNER_BUDGET_INVALID")

    def test_dependency_logic_uses_checker_verdicts(self):
        read = planner_io.dependency_state
        a, b = {"fact": "a"}, {"fact": "b"}
        self.assertEqual(read(a, {}), "UNKNOWN")
        self.assertEqual(
            read({"op": "all", "items": [a, b]}, {"a": "FALSE"}),
            "FALSE",
        )
        self.assertEqual(
            read({"op": "any", "items": [a, b]}, {"a": "TRUE"}),
            "TRUE",
        )
        self.assertEqual(
            read({"op": "all", "items": [a, b]}, {"a": "UNRESOLVED_CONFLICT"}),
            "UNRESOLVED_CONFLICT",
        )

    def test_model_failure_has_no_fallback(self):
        board = self.board()
        with self.assertRaises(planner_io.PlannerIOError) as raised:
            planner_io.plan_next(client=None, board=board, timeout=1)
        self.assertEqual(raised.exception.reason_code, "PLANNER_MODEL_UNAVAILABLE")

        calls = []

        def complete(**kwargs):
            calls.append(kwargs)
            return SimpleNamespace(ok=False)

        client = SimpleNamespace(available=True, complete=complete)
        with self.assertRaises(planner_io.PlannerIOError) as raised:
            planner_io.plan_next(client=client, board=board, timeout=1)
        self.assertEqual(raised.exception.reason_code, "PLANNER_REPLY_UNCONFIRMED")
        self.assertEqual(len(calls), 1)

    def test_model_receives_only_public_inventory(self):
        board = self.board()
        received = []

        def complete(**kwargs):
            received.append(json.loads(kwargs["user"]))
            return SimpleNamespace(ok=True, payload=self.reply(board))

        client = SimpleNamespace(available=True, complete=complete)
        answer = planner_io.plan_next(client=client, board=board, timeout=1)
        self.assertEqual(received, [board.input])
        self.assertEqual(answer["node_id"], self.first)
        self.assertNotIn("_context", received[0])
