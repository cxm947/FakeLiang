"""New scenarios only; existing tests and assertions stay untouched."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest
from langgraph.checkpoint.sqlite import SqliteSaver
from agents._model.client import ModelReply
from agents.planner import service as planning
from agents.verifier import service as verifier
from orchestration import contracts, langgraph_runner, positions, preparation, reporting
from orchestration import session_flow, walk_step
from tests.test_orchestration_walk import CARD, step_arguments
from tests.test_run_plan_support import (
    ROOT, InventoryPlanner, checked_observations, credential_graph, graph,
    plan_args, plan_harness, private_source, proved_result)
import run_plan


def correction_arguments(monkeypatch, tmp_path, counts, results, gates, state):
    events, rows, committed = [], [], []
    args = step_arguments(monkeypatch, tmp_path, order=events, rows=rows,
                          relay_state={}, record_step=committed.append)
    card = {"id": "fixture-no-delivery", "delivers": [], "inputs": {}}
    monkeypatch.setattr(walk_step.bind, "bind", lambda *a, **k: (card, "", {}))

    def prepare(**kwargs):
        counts["prepare"] = counts.get("prepare", 0) + 1
        return {"inputs": {}}, {"host": "192.0.2.10", "port": "81"}

    def drive(*args, **kwargs):
        counts["execute"] = counts.get("execute", 0) + 1
        if kwargs.get("feedback"):
            counts["feedback"] = counts.get("feedback", 0) + 1
        return dict(next(results))

    def gate(**kwargs):
        counts["verify"] = counts.get("verify", 0) + 1
        return dict(next(gates))

    monkeypatch.setattr(preparation, "prepare_inputs", prepare)
    monkeypatch.setattr(walk_step.assessment, "_fact_gate", gate)
    monkeypatch.setattr(walk_step.graph_criteria, "to_produce", lambda *a, **k: [{"ref": "fact-1"}])
    monkeypatch.setattr(reporting, "node_row", lambda **k: {
        "status": "proved" if k["proved"] else "stopped",
        "reason": k["result"].get("reason", "")})
    args.update(drive=drive, graph_state=state)
    return args, committed, card


def denied_gate():
    return {"proved": False, "status": "failed", "reason": "VERIFICATION_DENIED",
            "denied": ["fact-1"], "unconfirmed": [], "source_call": ""}


def proved_gate():
    return {"proved": True, "status": "proved", "reason": "",
            "denied": [], "unconfirmed": [], "source_call": "call-1"}


def unknown_gate():
    return {"proved": False, "status": "unconfirmed", "reason": "OUTPUT_FACT_UNCONFIRMED",
            "denied": [], "unconfirmed": ["fact-1"], "source_call": ""}


def test_correctable_denial_reuses_precheck_and_commits_once(monkeypatch, tmp_path):
    state, counts = {"attempts": {}, "exhausted_nodes": []}, {}
    args, committed, _ = correction_arguments(
        monkeypatch, tmp_path, counts,
        iter([dict(proved_result(), correctable=True), proved_result()]),
        iter([denied_gate(), proved_gate()]), state)
    result = walk_step.run_step(**args)
    assert result.row["status"] == "proved"
    assert counts == {"prepare": 1, "execute": 2, "verify": 2, "feedback": 1}
    assert state["attempts"]["execute"]["12"] == 2
    assert state["attempts"]["verify"]["12"] == 2
    assert state["attempts"]["precheck"]["12"] == 1
    assert state["exhausted_nodes"] == []
    assert committed == [result]
    assert "correctable" not in result.row


def test_false_premise_does_not_authorize_correction(monkeypatch, tmp_path):
    state, counts = {"attempts": {}, "exhausted_nodes": []}, {}
    gate = dict(denied_gate(), denied=["premise-1"])
    args, committed, _ = correction_arguments(
        monkeypatch, tmp_path, counts, iter([dict(proved_result(), correctable=True)]),
        iter([gate]), state)
    result = walk_step.run_step(**args)
    assert counts["execute"] == counts["verify"] == 1
    assert result.row["status"] != "proved"
    assert state["exhausted_nodes"] == []
    assert committed == [result]


@pytest.mark.parametrize("pending, expected", [([], True), (["unsettled-call"], False)])
def test_private_driver_restart_permission_reads_pending_journal(monkeypatch, tmp_path, pending, expected):
    from agents.executor import driver as executor_driver
    reads = []

    class Journal:
        def __init__(self, **kwargs):
            self.secrets = []

        def _read(self):
            reads.append(True)
            return []

        def _pending(self, events):
            return pending

    monkeypatch.setattr(executor_driver, "LeanRun", Journal)
    monkeypatch.setattr(executor_driver, "validate_task", lambda *args: None)
    monkeypatch.setattr(executor_driver.card_reader, "max_turns_of", lambda card: 8)
    result = executor_driver.drive({}, {}, {}, None, run_dir=tmp_path,
                                   max_steps=0, private_result=True)
    assert reads == [True]
    assert result["reason"] == "LEAN_STEP_LIMIT"
    assert result["correctable"] is expected


def test_preseeded_execute_budget_is_not_refreshed(monkeypatch, tmp_path):
    state = {"attempts": {"execute": {"12": 3}}, "exhausted_nodes": []}
    counts = {}
    args, committed, _ = correction_arguments(
        monkeypatch, tmp_path, counts, iter([dict(proved_result(), correctable=True)]),
        iter([denied_gate()]), state)
    result = walk_step.run_step(**args)
    assert state["attempts"]["execute"]["12"] == 4
    assert state["exhausted_nodes"] == ["12"]
    assert counts["execute"] == counts["verify"] == 1
    assert committed == [result]
    assert result.row["status"] != "proved"


def test_restart_and_verification_correction_share_one_allowance(monkeypatch, tmp_path):
    state = {"attempts": {"execute": {"12": 1}}, "exhausted_nodes": []}
    counts = {}
    unavailable = {"status": "uncertain", "claimed_verdict": "uncertain",
                   "reason": "LEAN_MODEL_REPLY_UNAVAILABLE", "correctable": True}
    args, committed, _ = correction_arguments(
        monkeypatch, tmp_path, counts,
        iter([unavailable, dict(proved_result(), correctable=True), proved_result()]),
        iter([unknown_gate(), denied_gate(), proved_gate()]), state)
    result = walk_step.run_step(**args)
    assert result.row["status"] == "proved"
    assert state["attempts"]["execute"]["12"] == 4
    assert counts["execute"] == counts["verify"] == 3
    assert counts["prepare"] == 1
    assert state["exhausted_nodes"] == []
    assert committed == [result]


def test_reentry_cannot_refresh_spent_execute_budget(monkeypatch, tmp_path):
    state = {"attempts": {"execute": {"12": 4}}, "exhausted_nodes": []}
    counts = {}
    args, committed, _ = correction_arguments(
        monkeypatch, tmp_path, counts, iter([]), iter([]), state)
    result = walk_step.run_step(**args)
    assert state["attempts"]["execute"]["12"] == 4
    assert counts.get("execute", 0) == counts.get("verify", 0) == 0
    assert state["exhausted_nodes"] == ["12"]
    assert result.row["status"] != "proved"
    assert committed == [result]


def test_changed_carrier_rechecks_without_refreshing_execute(monkeypatch, tmp_path):
    state, counts = {"attempts": {"execute": {"12": 1}}, "exhausted_nodes": []}, {}
    args, committed, _ = correction_arguments(
        monkeypatch, tmp_path, counts,
        iter([dict(proved_result(), correctable=True), proved_result()]),
        iter([denied_gate(), proved_gate()]), state)
    registry = [{"channel_id": "carrier-1", "host": "192.0.2.1", "logical": "origin",
                 "privilege": "admin", "kind": "console_session", "session_id": "1"}]
    monkeypatch.setattr(positions, "exec_preconditions", lambda *a, **k: [("origin", "admin", [])])
    monkeypatch.setattr(walk_step.session_registry, "snapshot", lambda root: deepcopy(registry))
    monkeypatch.setattr(positions, "resolve_carrier_for_node",
                        lambda document, node_id, rows, **k: (dict(rows[0]), "fixture"))

    def probe(*args, **kwargs):
        counts["probe"] = counts.get("probe", 0) + 1
        return True, "FIXTURE_ALIVE"

    monkeypatch.setattr(walk_step.sessions, "probe", probe)
    original = args["drive"]

    def drive(*a, **k):
        result = original(*a, **k)
        if counts["execute"] == 1:
            registry[0].update(channel_id="carrier-2", session_id="2")
        return result

    args["drive"] = drive
    result = walk_step.run_step(**args)
    assert result.row["status"] == "proved"
    assert counts["prepare"] == counts["probe"] == 2
    assert state["attempts"]["precheck"]["12"] == 2
    assert state["attempts"]["execute"]["12"] == 3
    assert committed == [result]


def test_changed_credential_file_rechecks_without_refreshing_execute(monkeypatch, tmp_path):
    state, counts = {"attempts": {"execute": {"12": 1}}, "exhausted_nodes": []}, {}
    args, committed, card = correction_arguments(
        monkeypatch, tmp_path, counts,
        iter([dict(proved_result(), correctable=True), proved_result()]),
        iter([denied_gate(), proved_gate()]), state)
    card["inputs"]["credential_ref"] = {}
    source = tmp_path / "private-source.json"
    source.write_text('{"generation": 1}', encoding="utf-8")
    args["credentials"] = contracts.CredentialInputs(
        source={"path": str(source), "credentials": {}}, run_dirs=[tmp_path],
        materials_dir=None, role_accounts={})
    original = args["drive"]

    def drive(*a, **k):
        result = original(*a, **k)
        if counts["execute"] == 1:
            source.write_text('{"generation": 2}', encoding="utf-8")
        return result

    args["drive"] = drive
    result = walk_step.run_step(**args)
    assert result.row["status"] == "proved"
    assert counts["prepare"] == 2
    assert state["attempts"]["precheck"]["12"] == 2
    assert state["attempts"]["execute"]["12"] == 3
    assert committed == [result]


def test_named_cells_preserve_delivery_before_verify_then_session(monkeypatch, tmp_path):
    events, committed, rows = [], [], []
    args = step_arguments(monkeypatch, tmp_path, order=events, rows=rows,
                          relay_state={"state": "live"}, record_step=committed.append)
    card = dict(CARD, delivers=["console"])
    monkeypatch.setattr(walk_step.bind, "bind", lambda *a, **k: (card, "", {}))

    def drive(*a, **k):
        events.append("execute")
        return {"status": "model_reported", "claimed_verdict": "pass"}

    def record_channels(**kwargs):
        events.append("session")
        return [{"channel_id": "channel-1", "session_id": "1"}], None

    args["drive"] = drive
    monkeypatch.setattr(session_flow, "record_channels", record_channels)
    args["graph_state"] = {"attempts": {}, "exhausted_nodes": []}
    walk_step.run_step(**args)
    assert [e for e in events if e in {"execute", "delivery", "relay", "verify", "session"}] == [
        "execute", "delivery", "relay", "verify", "session"]
    for cell in ("execute", "verify", "session"):
        assert args["graph_state"]["attempts"][cell]["12"] == 1
    assert len(committed) == 1


def test_planner_faults_and_rejected_handbacks_share_four_calls():
    document = graph()
    order = ["14", "12", "7"]
    observations = {"6": "TRUE", "4": "TRUE", "3": "TRUE"}
    decided = {n: {"status": "proved", "verification": checked_observations(document, n, observations)}
               for n in order}
    replies = iter([RuntimeError("fixture transport failure"), {},
                    {"decision": "continue", "next_node_id": "2", "change_note": None},
                    {"decision": "continue", "next_node_id": "5", "change_note": None}])
    calls = []

    class Planner:
        def available(self):
            return True

        def complete(self, **kwargs):
            calls.append(kwargs["user"])
            answer = next(replies)
            if isinstance(answer, Exception):
                raise answer
            return ModelReply(ok=True, payload=answer, text=json.dumps(answer))

    state = {"attempts": {}, "exhausted_nodes": []}
    node, note = planning.plan_next(document=document, state=decided, order=order,
                                   run_id="fixture", client=Planner(), graph_state=state)
    assert str(node["id"]) == "5"
    assert len(calls) == 4
    assert state["attempts"]["planner"]["3"] == 4
    assert [r["reason_code"] for r in note["refusals"]] == [
        "PLANNER_CALL_FAILED", "planner_shape_invalid", "fact_unavailable", "PLANNER_RETRY_EXECUTABLE"]
    with pytest.raises(planning.PlannerFailure, match="PLANNER_ATTEMPTS_EXHAUSTED"):
        planning.plan_next(document=document, state=decided, order=order,
                          run_id="fixture", client=Planner(), graph_state=state)
    assert len(calls) == 4


def read_state(root, materials):
    path, thread_id = langgraph_runner.checkpoint_identity(
        root=root, repository=ROOT, materials_dir=materials)
    with SqliteSaver.from_conn_string(str(path)) as saver:
        row = saver.get_tuple({"configurable": {"thread_id": thread_id}})
        assert row is not None
        return row.checkpoint["channel_values"]


def test_converged_stop_is_checkpoint_only_and_artifact_shape_unchanged(monkeypatch, tmp_path):
    document = credential_graph()
    source, material = private_source(tmp_path)
    root, materials = tmp_path / "run", tmp_path / "materials"
    plan_harness(monkeypatch, document, lambda *a, **k: proved_result())
    assert run_plan.main(plan_args(root, source) + ["--materials-dir", str(materials)]) == 0
    summary = json.loads((root / "plan_result.json").read_text(encoding="utf-8"))
    assert set(summary) == {
        "order", "planner", "nodes", "not_attempted", "proved", "stopped", "blocked",
        "blocked_upstream", "final_goal", "plan", "undecided", "note", "passed"}
    state = read_state(root, materials)
    assert state["route"] == "done" and state["stop_reason"] == "converged"
    assert state["attempts"]["execute"] == {"1": 1, "3": 1}
    assert state["attempts"]["verify"] == {"1": 1, "3": 1}
    assert material["secret"] not in json.dumps(state)
    assert summary["order"] == ["1", "3"]


def test_unknown_stops_blocked_without_restart(monkeypatch, tmp_path):
    source, _ = private_source(tmp_path)
    root, materials = tmp_path / "run", tmp_path / "materials"
    client, real_verify, dispatched = InventoryPlanner(), verifier.verify_node, []

    def driver(*args, **kwargs):
        dispatched.append(True)
        return dict(proved_result(), correctable=True)

    plan_harness(monkeypatch, credential_graph(producer_only=True), driver, client=client)
    monkeypatch.setattr(verifier, "verify_node", real_verify)
    assert run_plan.main(plan_args(root, source) + ["--materials-dir", str(materials)]) == 2
    assert dispatched == [True]
    assert [task for task, _ in client.calls] == ["pick_next_node", "verify", "pick_next_node"]
    state = read_state(root, materials)
    assert state["stop_reason"] == "blocked"
    assert state["attempts"]["execute"] == {"1": 1}
    summary = json.loads((root / "plan_result.json").read_text(encoding="utf-8"))
    assert not {"stop_reason", "attempts", "cell"} & summary.keys()


def test_unreadable_planner_exhausts_shared_four_attempts(monkeypatch, tmp_path):
    class DeadPlanner:
        def __init__(self):
            self.calls = 0

        def available(self):
            return True

        def complete(self, **kwargs):
            self.calls += 1
            return SimpleNamespace(ok=True, payload={}, error="", text="{}")

    source, _ = private_source(tmp_path)
    root, materials = tmp_path / "run", tmp_path / "materials"
    client = DeadPlanner()
    plan_harness(monkeypatch, credential_graph(), lambda *a, **k: proved_result(), client=client)
    assert run_plan.main(plan_args(root, source) + ["--materials-dir", str(materials)]) == 2
    assert client.calls == 4
    state = read_state(root, materials)
    assert state["stop_reason"] == "budget_exhausted"
    assert state["attempts"]["planner"]["0"] == 4
    assert not state["attempts"].get("execute")
    summary = json.loads((root / "plan_result.json").read_text(encoding="utf-8"))
    assert not {"stop_reason", "attempts", "cell"} & summary.keys()
