"""The step's phase order: a confirmed handover builds its relay before the machine check.

These run the shipped ``run_step`` with its collaborators stubbed, so the invariant the split had
to preserve - "delivery, then relay, then verification, and a relay failure never skips
verification" - is proven by execution instead of by reading the source.
"""

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from orchestration import contracts, delivery_setup, preparation, session_flow, walk  # noqa: E402
from orchestration import positions, reporting                                        # noqa: E402
from orchestration.verification import assessment
from agents.verifier import service                            # noqa: E402
from orchestration import walk_step  # noqa: E402
from tests.support import stub_callers                                                # noqa: E402


CARD = {"id": "card-hands-over", "session": {"driver": "console"}, "delivers": []}


def step_arguments(monkeypatch, tmp_path, *, order, rows, relay_state, record_step):
    """Wire one step whose declared handover succeeds and whose driver claims success."""

    def begin_delivery(*, delivery, **kwargs):
        order.append("begin")
        delivery.plan = {"owner": "delivery-1", "command": "run it",
                         "declaration": {"materials": {}}}

    def finish_delivery(**kwargs):
        order.append("delivery")
        return {"state": "completed", "carrier": "session-1",
                "delivery_owner": "delivery-1"}

    def activate(**kwargs):
        order.append("relay")
        return relay_state

    def verify(**kwargs):
        order.append("verify")
        return {"facts": []}

    monkeypatch.setattr(walk_step.bind, "bind",
                        lambda *a, **k: (CARD, "", {"selected_id": CARD["id"]}))
    stub_callers(monkeypatch, "exec_preconditions", lambda *a, **k: False, callers=(positions,))
    stub_callers(monkeypatch, "prepare_inputs",
                 lambda **k: ({"inputs": {}}, {"host": "192.0.2.10", "port": "81"}),
                 callers=(preparation,))
    stub_callers(monkeypatch, "delivery_target_host", lambda **k: "192.0.2.10",
                 callers=(session_flow,))
    stub_callers(monkeypatch, "begin_delivery", begin_delivery, callers=(delivery_setup,))
    stub_callers(monkeypatch, "add_delivery_inputs", lambda **k: order.append("inputs"),
                 callers=(delivery_setup,))
    stub_callers(monkeypatch, "delivery_was_issued", lambda *a, **k: True,
                 callers=(session_flow,))
    stub_callers(monkeypatch, "_finish_produced_session", finish_delivery,
                 callers=(session_flow,))
    stub_callers(monkeypatch, "activate_relay", activate, callers=(session_flow,))
    stub_callers(monkeypatch, "proof_of", lambda node, result: True, callers=(assessment,))
    stub_callers(monkeypatch, "_fact_gate",
                 lambda **k: {"proved": True, "status": "proved", "reason": "",
                              "denied": [], "unconfirmed": [], "source_call": "call-1"},
                 callers=(assessment,))
    stub_callers(monkeypatch, "verify_node", verify, callers=(service,))
    stub_callers(monkeypatch, "_verification_sources", lambda *a, **k: {},
                 callers=(service,))
    stub_callers(monkeypatch, "record_in_place_observation", lambda **k: None, callers=(positions,))
    stub_callers(monkeypatch, "register_declared_position", lambda **k: None, callers=(positions,))
    stub_callers(monkeypatch, "build_entry_position", lambda **k: None, callers=(positions,))
    stub_callers(monkeypatch, "node_row", lambda **k: (rows.append(k), {})[1],
                 callers=(reporting,))
    monkeypatch.setattr(walk_step.credential_ledger, "record_proved", lambda *a, **k: [])
    return dict(
        node={"id": "12"},
        document={},
        root=tmp_path,
        repository=ROOT,
        host_map={},
        host_environments={},
        executor=lambda *a, **k: None,
        executor_host="192.0.2.1",
        client=None,
        control="192.0.2.1",
        rpc_conf={"rpc_password": "x"},
        credentials=contracts.CredentialInputs(
            source=None, run_dirs=[tmp_path], materials_dir=None, role_accounts={}),
        limits=contracts.StepLimits(python="python3", timeout=1.0, max_steps=2,
                                    model_timeout=1.0),
        secrets=[],
        prepare_task=lambda *a, **k: None,
        drive=lambda *a, **k: {"status": "model_reported", "claimed_verdict": "pass"},
        record_step=record_step,
    )


def test_a_confirmed_handover_builds_its_relay_before_the_machine_check(monkeypatch, tmp_path):
    """finish -> relay -> verify, and the step reports the relay it actually built."""
    order, steps, rows = [], [], []
    arguments = step_arguments(monkeypatch, tmp_path, order=order, rows=rows,
                               relay_state={"state": "live"}, record_step=steps.append)

    walk.run_step(**arguments)

    assert order == ["begin", "inputs", "delivery", "relay", "verify"]
    assert rows[-1]["result"]["relay"] == {"state": "live"}


def test_a_failed_relay_result_does_not_skip_the_machine_check(monkeypatch, tmp_path):
    """A relay that could not be built is recorded as such; verification still runs once."""
    order, steps, rows = [], [], []
    arguments = step_arguments(monkeypatch, tmp_path, order=order, rows=rows,
                               relay_state={"state": "unknown", "reason": "TUNNEL_UNBOUND"},
                               record_step=steps.append)

    walk.run_step(**arguments)

    assert order == ["begin", "inputs", "delivery", "relay", "verify"]
    assert rows[-1]["result"]["relay"] == {"state": "unknown", "reason": "TUNNEL_UNBOUND"}


def test_stub_callers_only_changes_the_modules_a_test_names(monkeypatch):
    """A seam is patched where the caller reads it, and a typo cannot silently patch nothing."""
    from types import SimpleNamespace

    import pytest

    original, replacement = object(), object()
    target = SimpleNamespace(dependency=original)
    unrelated = SimpleNamespace(dependency=original)

    stub_callers(monkeypatch, "dependency", replacement, callers=(target,))

    assert target.dependency is replacement
    assert unrelated.dependency is original
    with pytest.raises(AssertionError):
        stub_callers(monkeypatch, "missing", replacement, callers=(target,))
    with pytest.raises(TypeError):
        stub_callers(monkeypatch, "dependency", replacement)


def test_run_walk_commits_each_attempted_node_once_and_stops_with_the_planner(
        monkeypatch, tmp_path):
    """The loop holds the round: one row, one order entry, one report per attempted node."""
    from agents.planner import service as planning

    picks = iter([
        ({"id": "1"}, {"node": "1", "note": "first"}),
        ({"id": "2"}, {"node": "2", "note": "second"}),
        (None, {"node": "", "note": "nothing attemptable"}),
    ])
    monkeypatch.setattr(planning, "plan_next", lambda **kwargs: next(picks))
    monkeypatch.setattr(planning, "planner_handoffs", lambda *args, **kwargs: ())
    reported, dispatched = [], []

    def run_step(**kwargs):
        dispatched.append(kwargs["node"]["id"])
        step = contracts.StepResult(kwargs["node"]["id"], {"status": "proved"},
                                    {"selected_id": "card-" + kwargs["node"]["id"]}, ())
        kwargs["record_step"](step)
        return step

    monkeypatch.setattr(walk, "run_step", run_step)
    monkeypatch.setattr(walk.reporting, "walk_node",
                        lambda root, node_id, **kwargs: reported.append(node_id))

    result = walk.run_walk(
        document={}, graph_label="fixture", root=tmp_path, repository=ROOT,
        host_map={}, host_environments={}, executor=None, executor_host="192.0.2.1",
        client=None, control="", rpc_conf={},
        credentials=contracts.CredentialInputs(
            source=None, run_dirs=[tmp_path], materials_dir=None, role_accounts={}),
        limits=contracts.StepLimits(python="python3", timeout=1.0, max_steps=1,
                                    model_timeout=1.0),
        max_nodes=5, secrets=[], prepare_task=lambda *a, **k: None,
        drive=lambda *a, **k: {},
    )

    assert result.order == ["1", "2"]
    assert sorted(result.state) == ["1", "2"]
    assert dispatched == ["1", "2"]
    assert reported == ["1", "2"]
    assert [note["note"] for note in result.planner_notes] == [
        "first", "second", "nothing attemptable"]
    assert result.planner_notes[0]["binding_selection"] == {"selected_id": "card-1"}
    assert result.planner_error is None
