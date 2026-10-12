from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

_SRC = str(Path(__file__).resolve().parents[1] / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from agents.planner import io as planner_io
from graph.criteria import fact_row, node_criteria, to_produce
from graph.parser import Graph, Node
from graph.projector import project
from graph.protocol import transport_protocol
from graph.rehydrate import GraphContractError, _fold_transport, load_document



def chain_document(count=12, *, offset=0, host="origin", decorated=False,
                   alternate=False):
    nodes = {}
    weights = {}
    seed = str(offset + 1)
    nodes[seed] = Node(seed, "seed(%s)" % host, "LEAF", "0")
    previous = seed
    pairs = []

    for index in range(count):
        action = str(offset + 2 + index * 2)
        effect = str(offset + 3 + index * 2)
        description = "RULE %d (synthetic transition)" % (index + 1)
        if decorated:
            description = "RULE %d (  renamed    transition  )" % (index + 101)

        nodes[action] = Node(action, description, "AND", "0")
        nodes[effect] = Node(effect, "state(%s,%d)" % (host, index), "OR", "0")
        weights[previous, action] = "1"
        weights[action, effect] = "1"
        pairs.append((action, effect))
        previous = effect

    if alternate:
        alternative = str(offset + 900)
        nodes[alternative] = Node(
            alternative, "RULE 900 (alternative transition)", "AND", "0",
        )
        weights[seed, alternative] = "1"
        weights[alternative, pairs[0][1]] = "1"

    return project(Graph(nodes, weights)), seed, pairs


def assessment(verdict="TRUE", *, evidence="receipt-1", epoch="binding-1"):
    return {
        "verdict": verdict,
        "checker": "test-checker",
        "evidence": [evidence],
        "binding_epoch": epoch,
    }


class GraphContractRoundTests(unittest.TestCase):
    def test_protocol_spellings(self):
        cases = (
            ("http", "tcp"),
            ("https", "tcp"),
            ("tcp", "tcp"),
            ("udp", "udp"),
            ("HTTP", "HTTP"),
            (" https ", " https "),
            ("custom", "custom"),
            (None, ""),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(transport_protocol(value), expected)

    def test_scheme_is_retained_without_mutating_the_document(self):
        for scheme in ("http", "https"):
            with self.subTest(scheme=scheme):
                raw = {"id": "step", "protocol": scheme, "port": "443"}
                before = deepcopy(raw)
                folded = _fold_transport(raw)
                self.assertEqual(folded["protocol"], "tcp")
                self.assertEqual(folded["scheme"], scheme)
                self.assertEqual(raw, before)

        raw = {"protocol": "tcp", "scheme": "https"}
        self.assertEqual(_fold_transport(raw), raw)
        self.assertNotIn("scheme", _fold_transport({"protocol": " HTTPS "}))

    def test_all_twelve_outputs_come_from_the_complete_graph(self):
        payload, seed, pairs = chain_document()
        before = deepcopy(payload)
        view = load_document(payload)
        self.assertEqual(payload, before)

        projected = {row["id"] for row in payload["nodes"]}
        self.assertTrue(any(effect not in projected for _, effect in pairs[:-1]))

        for index, (action, effect) in enumerate(pairs):
            with self.subTest(action=action):
                produced = to_produce(view, action)
                self.assertEqual([row["ref"] for row in produced], [effect])
                self.assertEqual(produced[0]["produced_by"], [action])
                self.assertEqual(produced[0]["declaration_kind"], "derived_fact")
                self.assertNotIn("machine_checkable", produced[0])

                parent = seed if index == 0 else pairs[index - 1][1]
                self.assertEqual(
                    [row["ref"] for row in node_criteria(view, action)],
                    [parent],
                )

        self.assertEqual(fact_row(view, seed)["declaration_kind"], "assumption")
        self.assertNotIn("assessment", fact_row(view, seed))

    def test_assumptions_are_not_fixed_truth(self):
        payload, seed, pairs = chain_document(1)
        view = load_document(payload)
        step = next(row for row in view["nodes"] if row["id"] == pairs[0][0])
        requirement = step["semantics"]["requires"][0]
        self.assertEqual(requirement["fact_ref"], seed)
        self.assertEqual(requirement["declaration_kind"], "assumption")
        self.assertNotIn("fixed", requirement)
        self.assertNotIn("any_of", requirement)

    def test_projection_mutations_are_rejected(self):
        mutations = (
            "target_host", "validation", "description",
            "summary", "delete", "duplicate", "final_goal",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                payload, seed, pairs = chain_document(2)
                action = next(
                    row for row in payload["nodes"] if row["id"] == pairs[0][0]
                )

                if mutation == "target_host":
                    action["target_host"] = "different-target"
                elif mutation == "validation":
                    dependency = next(
                        row for row in action["dependencies"] if row["ref"] == seed
                    )
                    dependency["validation"] = {"kind": "invented", "fields": {}}
                elif mutation == "description":
                    action["description"] += " changed"
                elif mutation == "summary":
                    payload["summary"]["unexpected_count"] = 1
                elif mutation == "delete":
                    payload["nodes"].remove(action)
                elif mutation == "duplicate":
                    payload["nodes"].append(deepcopy(action))
                else:
                    payload["final_goal"] = []

                with self.assertRaises(GraphContractError):
                    load_document(payload)

    def test_invalid_source_archives_are_rejected(self):
        mutations = (
            "digest", "duplicate_node", "duplicate_edge",
            "bad_metric", "dangling_edge", "extra_key", "bad_collection",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                payload, _, _ = chain_document(2)
                source = payload["source_graph"]

                if mutation == "digest":
                    source["graph_hash"] = "0" * 64
                elif mutation == "duplicate_node":
                    source["nodes"].append(deepcopy(source["nodes"][0]))
                elif mutation == "duplicate_edge":
                    source["edges"].append(deepcopy(source["edges"][0]))
                elif mutation == "bad_metric":
                    source["nodes"][0]["metric"] = 0
                elif mutation == "dangling_edge":
                    source["edges"][0]["source"] = "99999"
                elif mutation == "extra_key":
                    source["unexpected"] = True
                else:
                    source["nodes"] = {}

                with self.assertRaises(GraphContractError):
                    load_document(payload)

    def test_projection_and_archive_list_order_do_not_change_identity(self):
        payload, _, pairs = chain_document(3)
        payload["nodes"].reverse()
        payload["source_graph"]["nodes"].reverse()
        payload["source_graph"]["edges"].reverse()
        view = load_document(payload)
        self.assertEqual(
            [to_produce(view, action)[0]["ref"] for action, _ in pairs],
            [effect for _, effect in pairs],
        )

    def test_fact_index_survives_renaming_and_rule_text_formatting(self):
        left, _, left_pairs = chain_document()
        right, _, right_pairs = chain_document(
            offset=1000, host="renamed", decorated=True,
        )
        left_view, right_view = load_document(left), load_document(right)

        for left_pair, right_pair in zip(left_pairs, right_pairs):
            left_action, left_effect = left_pair
            right_action, right_effect = right_pair
            a = to_produce(left_view, left_action)[0]
            b = to_produce(right_view, right_action)[0]
            self.assertEqual(a["ref"], left_effect)
            self.assertEqual(b["ref"], right_effect)
            self.assertEqual(a["signature"], b["signature"])
            self.assertEqual(a["declaration_kind"], b["declaration_kind"])
            self.assertEqual(len(node_criteria(left_view, left_action)), 1)
            self.assertEqual(len(node_criteria(right_view, right_action)), 1)

    def test_criteria_reject_wrong_node_kinds(self):
        payload, seed, pairs = chain_document(1)
        for entry in (node_criteria, to_produce):
            with self.subTest(entry=entry.__name__):
                with self.assertRaisesRegex(ValueError, "CRITERIA_NODE_UNKNOWN"):
                    entry(payload, seed)
        with self.assertRaisesRegex(ValueError, "CRITERIA_FACT_UNKNOWN"):
            fact_row(payload, pairs[0][0])


if __name__ == "__main__":
    unittest.main()