"""Runtime fact selection reads the complete graph, not copied consumer dependencies."""

import sys
from pathlib import Path

import pytest
from runtime import session_registry
from orchestration import graph_view  # noqa: E402

from orchestration import positions  # noqa: E402

from orchestration import session_flow  # noqa: E402

from orchestration import graph_view  # noqa: E402

from orchestration import positions  # noqa: E402

from orchestration import session_flow  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import run_plan
from tests.support import stub_callers
from graph import criteria, rehydrate
from tests.graph_fixtures import loaded_graph


def fanout_graph():
    nodes = [
        ("7", "RULE 1 (producer)", "AND"),
        ("19", "RULE 2 (alternative)", "AND"),
        ("1", "attackerLocated(origin)", "LEAF"),
        ("2", "execCode('edge one',system)", "OR"),
    ]
    edges = [("1", "7"), ("1", "19"), ("7", "2"), ("19", "2")]
    for action in ("10", "20", "30", "40"):
        effect = str(int(action) + 1)
        nodes.extend([(action, "RULE 3 (consumer)", "AND"),
                      (effect, "netAccess(target,tcp,443)", "OR")])
        edges.extend([("2", action), (action, effect)])
    return loaded_graph(nodes, edges)


def test_intermediate_exec_output_is_not_multiplied_by_its_consumers():
    document = fanout_graph()
    assert "2" not in {row["id"] for row in document["nodes"]}
    assert len(document.graph.children["2"]) == 4
    for action in ("7", "19"):
        assert session_flow.produced_exec_facts(document, action) == [("edge one", "system")]
    assert session_flow.produced_exec_facts(document, "10") == []


def test_runtime_facts_do_not_read_mutated_display_dependencies():
    document = fanout_graph()
    for node in document["nodes"]:
        node["dependencies"] = []
    assert session_flow.produced_exec_facts(document, "7") == [("edge one", "system")]
    assert positions.exec_preconditions(document, "10") == [
        ("edge one", "system", ["7", "19"])]
    assert graph_view.needs(document, "10") == [["7", "19"]]
    assert graph_view.flat_producers(document, "10") == ["7", "19"]
    assert not graph_view.satisfied(document, "10", {
        "7": {"status": "proved"}, "19": {"status": "proved"}})


def test_all_lab_actions_use_the_same_output_index():
    document = rehydrate.load_file(
        ROOT / "tests/fixtures/hongri7/reference.action_graph.json")
    for action in document.graph.actions:
        expected = [(fact["arguments"][0], fact["arguments"][1])
                    for fact in criteria.to_produce(document, action)
                    if fact["type"] == "OR" and fact["signature"] == "execCode/2"]
        assert session_flow.produced_exec_facts(document, action) == expected
    for action, expected in (
        ("7", [("pc1", "system")]),
        ("19", [("pc1", "system")]),
        ("44", [("dc", "system")]),
        ("48", [("pc2", "system")]),
    ):
        assert session_flow.produced_exec_facts(document, action) == expected


def test_record_channels_registers_one_row_for_one_intermediate_fact(tmp_path, monkeypatch):
    """An intermediate output finds one observed session regardless of its consumer count."""
    document = fanout_graph()
    binding = {"channel_id": "session-a", "source_node": "7", "logical": "edge one",
               "host": "192.0.2.17", "session_id": "1"}
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [binding])
    delivery = {"node_id": "7", "state": "completed", "delivery_owner": "delivery-fixture",
                "reason": "SESSION_DELIVERY_MATCHED_REGISTERED_CARRIER_OBSERVED",
                "carrier": "session-a"}
    rows, note = session_flow.record_channels(
        node_id="7", document=document, host_map={"edge one": "192.0.2.17"}, root=tmp_path,
        delivery=delivery)
    assert rows == [binding]
    assert note["reason"] == "CONSOLE_SESSION_OBSERVED"


def test_missing_exec_output_never_uses_the_display_target(tmp_path, monkeypatch):
    """Missing complete-graph output cannot create a session from a display target."""
    document = fanout_graph()
    monkeypatch.setattr(session_registry, 'snapshot',
                        lambda *a, **k: pytest.fail("no output may query an output session"))
    rows, note = session_flow.record_channels(
        node_id="10", document=document, host_map={}, root=tmp_path, delivery=None)
    assert rows == []
    assert note["reason"] == "NO_EXEC_OUTPUT_FACT"


def test_session_delivery_uses_the_output_host_and_privilege(monkeypatch):
    from unittest.mock import create_autospec
    from runtime.session_delivery import (
        finish_session_delivery as real_finish_session_delivery,
    )

    document = fanout_graph()
    plan = {"fixture": True}
    rpc_conf = {}
    root = Path(".")

    output_facts = create_autospec(
        session_flow.produced_exec_facts,
        spec_set=True,
        return_value=[("edge one", "system")],
    )
    finish = create_autospec(
        real_finish_session_delivery,
        spec_set=True,
        return_value={"state": "completed"},
    )
    stub_callers(monkeypatch, "produced_exec_facts", output_facts, callers=(positions, session_flow))
    stub_callers(monkeypatch, "finish_session_delivery", finish, callers=(session_flow,))

    result = session_flow._finish_produced_session(
        document=document,
        node_id="7",
        host_map={"edge one": "192.0.2.17"},
        executor=None,
        plan=plan,
        rpc_conf=rpc_conf,
        root=root,
    )

    assert result == {"state": "completed"}
    output_facts.assert_called_once_with(document, "7")
    finish.assert_called_once_with(
        executor=None,
        plan=plan,
        rpc_conf=rpc_conf,
        root=root,
        node_id="7",
        host="192.0.2.17",
        logical="edge one",
        privilege="system",
        timeout=40.0,
    )






@pytest.mark.parametrize("outputs,reason", [
    ([], "SESSION_OUTPUT_FACT_MISSING"),
    (["execCode(alpha,root)", "execCode(beta,system)"], "SESSION_OUTPUT_FACT_AMBIGUOUS"),
])
def test_session_delivery_never_guesses_a_missing_or_ambiguous_output(
        monkeypatch, outputs, reason):
    from unittest.mock import create_autospec
    from runtime.session_delivery import (
        finish_session_delivery as real_finish_session_delivery,
    )

    rows = [("1", "RULE 1 (delivery)", "AND")]
    edges = []
    for index, fact in enumerate(outputs, start=2):
        rows.append((str(index), fact, "OR"))
        edges.append(("1", str(index)))
    if not outputs:
        rows.append(("2", "netAccess(alpha,tcp,443)", "OR"))
        edges.append(("1", "2"))

    document = loaded_graph(rows, edges)
    assert len(session_flow.produced_exec_facts(document, "1")) == len(outputs)

    finish = create_autospec(
        real_finish_session_delivery,
        spec_set=True,
        return_value={"state": "completed"},
    )
    stub_callers(monkeypatch, "finish_session_delivery", finish, callers=(session_flow,))

    result = session_flow._finish_produced_session(
        document=document,
        node_id="1",
        host_map={},
        executor=None,
        plan=None,
        rpc_conf={},
        root=Path("."),
    )

    finish.assert_not_called()
    assert result == {"state": "unknown", "reason": reason}
