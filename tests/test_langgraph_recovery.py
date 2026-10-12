"""Offline saved-boundary recovery, including a genuinely terminated owner."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest

from orchestration import cli, langgraph_runner
from orchestration.contracts import WalkResult
from runtime import lean_transport
from tests.support import FakeClock, ROOT
from tests.test_lean_kernel import Collector, REQUEST, run_at
import check_recovery


def test_atomic_replace_survives_a_transient_handle(tmp_path, monkeypatch):
    """Windows holds a fresh file open for a moment; the boundary retries, then gives up."""
    from graph import files

    target = tmp_path / "intent.json"
    real = os.replace
    attempts = []

    def flaky(source, destination):
        attempts.append(1)
        if len(attempts) < 3:
            raise PermissionError(5, "access denied")
        return real(source, destination)

    monkeypatch.setattr(files.os, "replace", flaky)
    monkeypatch.setattr(files.time, "sleep", lambda seconds: None)
    files.atomic_write(target, b"{}\n", force=True)
    assert target.read_bytes() == b"{}\n"
    assert len(attempts) == 3


def interrupt_before_commit(run, monkeypatch):
    append = run._append

    def stop(kind, **payload):
        if kind == "commit" and payload.get("phase") == "committing":
            raise SystemExit("stopped before transport commit")
        return append(kind, **payload)

    monkeypatch.setattr(run, "_append", stop)
    with pytest.raises(SystemExit, match="before transport"):
        run.call(REQUEST)
    return next(row for row in run.history() if row["kind"] == "intent")["call_id"]


def test_before_commit_continues_original_call_with_remaining_deadline(monkeypatch, tmp_path):
    clock = FakeClock()
    monkeypatch.setattr(lean_transport, "time", clock)
    first_transport = Collector()
    first = run_at(tmp_path, first_transport)
    original = interrupt_before_commit(first, monkeypatch)
    clock.now += 17
    transport = Collector()
    resumed = run_at(tmp_path, transport)
    facts = resumed.recover_calls()
    fact = next(row for row in facts if row["call_id"] == original)
    assert fact["state"] == "not_executed"
    assert first_transport.calls == transport.calls == []
    receipt = resumed.call(REQUEST, resume_call=original)
    assert receipt["call_id"] == original
    assert receipt["status"] == "completed_transport"
    assert len(transport.calls) == 1
    assert 0 < transport.calls[0][1] <= 43
    events = resumed.history()
    assert [row["call_id"] for row in events if row["kind"] == "intent"] == [original]
    assert [row["call_id"] for row in events if row["kind"] == "receipt"] == [original]


def test_after_commit_before_receipt_adopts_original_artifacts(monkeypatch, tmp_path):
    transport = Collector()
    run = run_at(tmp_path, transport)

    def stop(*args, **kwargs):
        raise SystemExit("stopped after original artifacts")

    monkeypatch.setattr(run, "_publish_receipt", stop)
    with pytest.raises(SystemExit, match="original artifacts"):
        run.call(REQUEST)
    original = next(row for row in run.history() if row["kind"] == "intent")["call_id"]
    replacement = Collector()
    resumed = run_at(tmp_path, replacement)
    facts = resumed.recover_calls()
    assert next(row for row in facts if row["call_id"] == original)["state"] == "finished"
    assert len(transport.calls) == 1 and replacement.calls == []
    receipt = next(row for row in resumed.history() if row["kind"] == "receipt")
    assert receipt["call_id"] == original
    assert receipt["receipt"]["status"] == "completed_transport"
    resumed.recover_calls()
    assert len([row for row in resumed.history() if row["kind"] == "receipt"]) == 1
    assert replacement.calls == []


def test_mid_commit_unknown_is_never_resent(tmp_path):
    first = run_at(tmp_path, Collector("crash"))
    with pytest.raises(KeyboardInterrupt):
        first.call(REQUEST)
    original = next(row for row in first.history() if row["kind"] == "intent")["call_id"]
    transport = Collector()
    resumed = run_at(tmp_path, transport)
    facts = resumed.recover_calls()
    assert next(row for row in facts if row["call_id"] == original)["state"] == "unknown"
    for request in (REQUEST, dict(REQUEST, path="/different")):
        with pytest.raises(ValueError, match="LEAN_.*(UNRESOLVED|UNKNOWN)"):
            resumed.call(request)
    with pytest.raises(ValueError, match="LEAN_.*(UNRESOLVED|UNKNOWN|RESUME)"):
        resumed.call(REQUEST, resume_call=original)
    assert transport.calls == []
    assert not any(row["kind"] == "retry" for row in resumed.history())


def test_terminated_owner_recovers_complete_original_artifact_without_send(tmp_path):
    program = """
from pathlib import Path
import sys
from tests.test_lean_kernel import Collector, REQUEST, run_at

run = run_at(Path(sys.argv[1]), Collector())
def paused(*args, **kwargs):
    print("READY", flush=True)
    sys.stdin.readline()
    raise SystemExit("parent must terminate this process")
run._publish_receipt = paused
run.call(REQUEST)
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT / "src"), str(ROOT), environment.get("PYTHONPATH", "")])
    process = subprocess.Popen(
        [sys.executable, "-B", "-c", program, str(tmp_path)], cwd=ROOT,
        env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    ready = threading.Event()
    output = []

    def read_boundary():
        output.append(process.stdout.readline())
        ready.set()

    reader = threading.Thread(target=read_boundary, daemon=True)
    reader.start()
    try:
        assert ready.wait(10), "child did not reach the durable artifact boundary"
        assert output == ["READY\n"], "child exited before the saved commit boundary"
        process.terminate()
        process.wait(timeout=10)
        assert process.returncode != 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        process.communicate(timeout=10)
        reader.join(timeout=1)
    transport = Collector()
    resumed = run_at(tmp_path, transport)
    facts = resumed.recover_calls()
    assert len(facts) == 1 and facts[0]["state"] == "finished"
    assert transport.calls == []
    receipts = [row for row in resumed.history() if row["kind"] == "receipt"]
    assert len(receipts) == 1
    assert receipts[0]["receipt"]["status"] == "completed_transport"


def runner_options(tmp_path, walk, planner, step, attached, **extra):
    return dict(
        root=tmp_path / "run", repository=ROOT,
        materials_dir=tmp_path / "private", max_nodes=1,
        walk=walk, secrets=["batch3-private-token"],
        planner=planner, step=step, stop_reason=lambda state: "converged",
        selected_node=lambda: "n", attach_save=lambda save: attached.update(save=save),
        **extra)


def test_same_attempt_progress_survives_reentry_and_is_not_counted_twice(tmp_path):
    attached = {}
    first = WalkResult()
    planned = []

    def planner(state):
        planned.append(True)
        state.setdefault("attempts", {}).setdefault("planner", {})["0"] = 1
        return True

    def stopped_step(state):
        state.setdefault("attempts", {}).setdefault("execute", {})["n"] = 1
        state["active_step"] = {
            "node_id": "n", "attempt": 1, "phase": "execute",
            "parent_source": {"kind": "base", "host": "192.0.2.10"},
            "detail": "batch3-private-token"}
        attached["save"](state)
        raise SystemExit("interrupted attempt")

    with pytest.raises(SystemExit, match="interrupted attempt"):
        langgraph_runner.run_walk_graph(
            **runner_options(tmp_path, first, planner, stopped_step, attached))
    path, saved = check_recovery.read_state(tmp_path / "run", tmp_path / "private")
    assert saved["attempts"]["execute"] == {"n": 1}
    assert "batch3-private-token" not in json.dumps(saved)
    second = WalkResult()
    entered = []

    def restored_step(state):
        entered.append(deepcopy(state["active_step"]))
        assert state["attempts"]["execute"]["n"] == 1
        assert state["active_step"]["attempt"] == 1
        second.state["n"] = {"status": "proved"}
        second.order.append("n")
        state["active_step"] = {}

    langgraph_runner.run_walk_graph(**runner_options(
        tmp_path, second, planner, restored_step, attached, resume=True))
    assert len(entered) == len(planned) == 1
    assert second.order == ["n"]
    _, completed = check_recovery.read_state(tmp_path / "run", tmp_path / "private")
    assert completed["attempts"]["execute"] == {"n": 1}
    assert completed["route"] == "done"
    assert completed["stop_reason"] == "converged"
    assert_plain(completed)
    assert path.parent == (tmp_path / "private" / "checkpoints").resolve()
    assert "batch3-private-token".encode() not in path.read_bytes()


def test_existing_checkpoint_requires_resume_and_finished_refuses_resume(tmp_path):
    attached = {}
    walk = WalkResult()
    planner = lambda state: False
    step = lambda state: pytest.fail("a finished walk must not run a step")
    langgraph_runner.run_walk_graph(**runner_options(tmp_path, walk, planner, step, attached))
    with pytest.raises(ValueError, match="WALK_CHECKPOINT_EXISTS"):
        langgraph_runner.run_walk_graph(**runner_options(
            tmp_path, WalkResult(), planner, step, attached))
    with pytest.raises(ValueError, match="WALK_ALREADY_FINISHED"):
        langgraph_runner.run_walk_graph(**runner_options(
            tmp_path, WalkResult(), planner, step, attached, resume=True))


def test_resume_missing_checkpoint_refuses_without_starting_work(tmp_path):
    planner = lambda state: pytest.fail("missing checkpoint must not start work")
    with pytest.raises(ValueError, match="WALK_CHECKPOINT_MISSING"):
        langgraph_runner.run_walk_graph(**runner_options(
            tmp_path, WalkResult(), planner, planner, {}, resume=True))


def test_cli_resume_is_backward_compatible():
    base = ["--graph", "fixture.json", "--run-root", "fixture",
            "--remote", "fixture@192.0.2.1", "--model", "offline"]
    ordinary = cli.parse_args(base)
    resumed = cli.parse_args(base + ["--resume"])
    assert ordinary.resume is False
    assert resumed.resume is True


def assert_plain(value):
    if isinstance(value, dict):
        assert all(type(key) is str for key in value)
        for item in value.values():
            assert_plain(item)
    elif isinstance(value, list):
        for item in value:
            assert_plain(item)
    else:
        assert type(value) in (str, int, float, bool, type(None))


def test_recovery_durable_state_contains_only_values_and_no_private_tokens(tmp_path):
    secret = "batch3-private-token"
    transport = Collector(body="token=" + secret)
    run = run_at(tmp_path / "node", transport, secrets=[secret])
    receipt = run.call(dict(REQUEST, headers={"Authorization": "Bearer " + secret}))
    assert receipt["status"] == "completed_transport"
    run.recover_calls()
    assert_plain(run.history())
    for path in (tmp_path / "node").rglob("*"):
        if path.is_file():
            assert secret.encode() not in path.read_bytes(), path.name

def test_invalidated_parent_position_cannot_resolve_to_another_channel(monkeypatch):
    from runtime import recovery, sessions
    row = {
        "channel_id": "parent-channel", "kind": "console_session",
        "session_id": "17", "uuid": "original-incarnation",
        "session_type": "shell", "platform": "linux", "host": "192.0.2.10",
        "logical": "origin", "source_node": "1", "source_call": "original-call",
        "privilege": "user", "endpoint": {"host": "127.0.0.1", "port": 55553,
                                           "ssl": False}}
    frozen = recovery.parent_binding(row)
    probes = []
    monkeypatch.setattr(sessions, "probe",
                        lambda candidate, executor=None, **kwargs: probes.append(deepcopy(candidate)) or
                        (True, "FIXTURE_ALIVE"))
    restored = recovery.restore_parent(frozen, [deepcopy(row)], executor=None)
    assert restored == row and probes == [row]
    probes.clear()
    replaced = dict(row, uuid="new-incarnation")
    other = dict(row, channel_id="another-parent-channel")
    with pytest.raises(ValueError, match="RECOVERY_PARENT_INVALIDATED"):
        recovery.restore_parent(frozen, [replaced, other], executor=None)
    assert probes == []
    assert frozen["refs"]["channel_id"] == "parent-channel"
    assert frozen["refs"]["session_id"] == "17"
    assert frozen["refs"]["uuid"] == "original-incarnation"
    assert_plain(frozen)


def test_cancelled_model_call_is_unknown_and_not_retried():
    from runtime.recovery import RecoveryModel, safe_data
    calls, saved = [], []
    secret = "batch3-private-token"
    state = {}

    class InterruptedModel:
        def available(self):
            return True

        def complete(self, **kwargs):
            calls.append(kwargs)
            raise KeyboardInterrupt("cancelled provider call")

    context = {"state": state, "save": lambda value: saved.append(safe_data(value, [secret]))}
    client = InterruptedModel()
    first = RecoveryModel(client, context, [secret], timeout=90)
    kwargs = dict(task="verify", system="fixture system",
                  user="token=" + secret, timeout=90)
    with pytest.raises(KeyboardInterrupt):
        first.complete(**kwargs)
    second = RecoveryModel(client, context, [secret], timeout=90)
    with pytest.raises((ValueError, RuntimeError), match="MODEL_CALL_UNKNOWN"):
        second.complete(**kwargs)
    assert len(calls) == 1
    assert state["model_calls"]
    assert secret not in json.dumps(saved)
    assert_plain(saved)
    with pytest.raises(TypeError):
        safe_data({"client": client}, [secret])

def delivery_recovery_case(monkeypatch, tmp_path):
    from runtime import session_delivery, session_io, sessions
    from tests.test_run_plan_support import delivery_fixture
    arguments, action_calls = delivery_fixture(tmp_path, monkeypatch)
    plan = session_delivery.begin_session_delivery(**arguments)
    info = dict(arguments["declaration"]["expected"], uuid="original-session-incarnation",
                platform="linux")
    listing = {"17": info}
    monkeypatch.setattr(session_io, "rpc_call",
                        lambda *args, **kwargs: lambda *args, **kwargs: deepcopy(listing))
    registered, probed = [], []
    row = {
        "channel_id": "received-channel", "kind": "console_session",
        "session_id": "17", "uuid": info["uuid"], "session_type": "shell",
        "platform": "linux", "host": "192.0.2.7", "logical": "fixture-host",
        "source_node": "fixture", "source_call": plan["owner"],
        "endpoint": dict(plan["endpoint"])}

    def register(root, **kwargs):
        registered.append(deepcopy(kwargs))
        return deepcopy(row)

    def probe(candidate, **kwargs):
        probed.append(deepcopy(candidate))
        binding = {key: str(candidate.get(key) or "") for key in
                   ("channel_id", "kind", "session_id", "session_type", "platform",
                    "host", "logical", "uuid")}
        binding["endpoint"] = candidate["endpoint"]
        kwargs["evidence_out"].update({
            "carrier": candidate["channel_id"], "binding": binding, "state": "alive",
            "call_id": "call-probe", "identity_call_id": "call-identity",
            "identity": {"call_id": "call-identity", "user": "fixture-user"}})
        return True, "SESSION_PROBE_CONFIRMED"

    monkeypatch.setattr(sessions, "register_session", register)
    monkeypatch.setattr(sessions, "probe", probe)
    finish = dict(executor=None, plan=plan, rpc_conf=arguments["rpc_conf"],
                  root=tmp_path, host="192.0.2.7", logical="fixture-host",
                  privilege="user", node_id="fixture")
    return finish, listing, registered, probed, action_calls


def test_generated_session_before_registration_recovers_same_incarnation(monkeypatch, tmp_path):
    from runtime import session_delivery, session_delivery_finish, sessions
    options, listing, registered, probed, action_calls = delivery_recovery_case(
        monkeypatch, tmp_path)
    phases = []
    save = session_delivery_finish._save_delivery_plan

    def track(root, plan):
        result = save(root, plan)
        if plan.get("receipt_phase"):
            phases.append(plan["receipt_phase"])
        return result

    monkeypatch.setattr(session_delivery_finish, "_save_delivery_plan", track)
    with monkeypatch.context() as interrupted:
        def stop(*args, **kwargs):
            raise SystemExit("session generated before registration")
        interrupted.setattr(sessions, "register_session", stop)
        with pytest.raises(SystemExit, match="before registration"):
            session_delivery.finish_session_delivery(**options)
    path = tmp_path / "delivery" / options["plan"]["owner"] / "plan.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["receipt_phase"] == "registering"
    assert stored["delivery_receipt"]["received_session"]["session_id"] == "17"
    assert stored["delivery_receipt"]["received_session"]["uuid"] == listing["17"]["uuid"]
    assert registered == probed == []
    receipt = session_delivery.finish_session_delivery(**options)
    assert receipt["state"] == "completed" and receipt["sessions"] == ["17"]
    assert len(registered) == len(probed) == 1
    assert registered[0]["session_id"] == "17"
    assert registered[0]["source_call"] == options["plan"]["owner"]
    assert {"received", "registering", "registered", "probing", "probed"} <= set(phases)
    assert json.loads(path.read_text(encoding="utf-8"))["receipt_phase"] == "probed"
    assert action_calls == ["echo prepare"]
    assert options["rpc_conf"]["rpc_password"].encode() not in path.read_bytes()


@pytest.mark.parametrize("failure", ["query_failed", "multi_match", "changed_uuid"])
def test_delivery_unknown_checks_lower_layer_without_registration_retry(
        monkeypatch, tmp_path, failure):
    from runtime import session_delivery, session_io, sessions
    options, listing, registered, probed, action_calls = delivery_recovery_case(
        monkeypatch, tmp_path)
    if failure == "changed_uuid":
        with monkeypatch.context() as interrupted:
            def stop(*args, **kwargs):
                raise SystemExit("received session is frozen")
            interrupted.setattr(sessions, "register_session", stop)
            with pytest.raises(SystemExit):
                session_delivery.finish_session_delivery(**options)
        listing["17"]["uuid"] = "replacement-incarnation"
    elif failure == "multi_match":
        listing["18"] = dict(listing["17"], uuid="another-incarnation")
    else:
        def bad_query(*args, **kwargs):
            raise RuntimeError("underlying query failed")
        monkeypatch.setattr(session_io, "rpc_call", lambda *args, **kwargs: bad_query)
    receipt = session_delivery.finish_session_delivery(**options)
    assert receipt["state"] == "unknown"
    assert registered == probed == []
    assert action_calls == ["echo prepare"]


def test_run_step_reentry_does_not_duplicate_attempt_bookkeeping(monkeypatch, tmp_path):
    from orchestration import walk_step
    from tests.test_langgraph_batch2 import correction_arguments, proved_gate
    from tests.test_run_plan_support import proved_result
    state = {"attempts": {}, "exhausted_nodes": []}
    counts, saved = {}, []
    args, committed, card = correction_arguments(
        monkeypatch, tmp_path, counts, iter([proved_result()]),
        iter([proved_gate()]), state)
    monkeypatch.setattr(walk_step.bind, "faces", lambda *args, **kwargs: [card])

    def interrupt(value):
        if value.get("attempts", {}).get("execute", {}).get("12") == 1:
            saved.append(deepcopy(value))
            raise SystemExit("attempt saved before driver")

    args["save_state"] = interrupt
    with pytest.raises(SystemExit, match="saved before driver"):
        walk_step.run_step(**args)
    assert committed == []
    assert counts.get("execute", 0) == 0
    args.update(graph_state=saved[-1], save_state=lambda value: None)
    result = walk_step.run_step(**args)
    assert result.row["status"] == "proved"
    assert args["graph_state"]["attempts"]["execute"]["12"] == 1
    assert args["graph_state"]["attempts"]["precheck"]["12"] == 1
    assert counts["execute"] == counts["verify"] == 1
    assert committed == [result]

def test_completed_step_pending_writes_are_not_mistaken_for_finished_run(monkeypatch, tmp_path):
    from langgraph.checkpoint.sqlite import SqliteSaver
    attached, calls = {}, []
    first = WalkResult()
    put = SqliteSaver.put
    interrupted = []

    def fail_before_checkpoint(saver, config, checkpoint, *args, **kwargs):
        values = checkpoint.get("channel_values") or {}
        if (not interrupted and values.get("route") == "done"
                and (values.get("walk") or {}).get("order") == ["n"]
                and not values.get("stop_reason")):
            interrupted.append(True)
            raise SystemExit("completed step pending writes only")
        return put(saver, config, checkpoint, *args, **kwargs)

    def step(state):
        calls.append(True)
        first.order.append("n")
        first.state["n"] = {"status": "proved"}

    with monkeypatch.context() as crash:
        crash.setattr(SqliteSaver, "put", fail_before_checkpoint)
        with pytest.raises(SystemExit):
            langgraph_runner.run_walk_graph(**runner_options(
                tmp_path, first, lambda state: True, step, attached))
    second = WalkResult()
    langgraph_runner.run_walk_graph(**runner_options(
        tmp_path, second, lambda state: pytest.fail("planner already completed"),
        lambda state: pytest.fail("step already completed"),
        attached, resume=True))
    assert calls == [True]
    assert second.order == ["n"]
    _, state = check_recovery.read_state(tmp_path / "run", tmp_path / "private")
    assert state["route"] == "done" and state["stop_reason"] == "converged"

def test_startup_input_checkpoint_can_resume_before_first_planner(monkeypatch, tmp_path):
    from langgraph.checkpoint.sqlite import SqliteSaver
    attached, planned, stepped = {}, [], []
    put = SqliteSaver.put
    stopped = []

    def save_input_then_stop(saver, config, checkpoint, metadata, *args, **kwargs):
        result = put(saver, config, checkpoint, metadata, *args, **kwargs)
        if metadata.get("source") == "input" and not stopped:
            stopped.append(True)
            raise SystemExit("initial graph input saved")
        return result

    first = WalkResult()
    with monkeypatch.context() as crash:
        crash.setattr(SqliteSaver, "put", save_input_then_stop)
        with pytest.raises(SystemExit):
            langgraph_runner.run_walk_graph(**runner_options(
                tmp_path, first, lambda state: planned.append(True) or True,
                lambda state: stepped.append(True), attached))
    assert planned == stepped == []
    second = WalkResult()

    def complete_step(state):
        stepped.append(True)
        second.order.append("n")
        second.state["n"] = {"status": "proved"}

    langgraph_runner.run_walk_graph(**runner_options(
        tmp_path, second, lambda state: planned.append(True) or True,
        complete_step, attached, resume=True))
    assert planned == stepped == [True]
    assert second.order == ["n"]


def test_framework_failure_does_not_serialize_exception_secret(tmp_path):
    secret = "batch3-private-token"

    def failed_planner(state):
        raise RuntimeError("provider token=" + secret)

    with pytest.raises(RuntimeError):
        langgraph_runner.run_walk_graph(**runner_options(
            tmp_path, WalkResult(), failed_planner,
            lambda state: pytest.fail("failed planner cannot start a step"), {}))
    path, _ = langgraph_runner.checkpoint_identity(
        root=tmp_path / "run", repository=ROOT, materials_dir=tmp_path / "private")
    assert path.is_file()
    for artifact in path.parent.glob(path.name + "*"):
        assert secret.encode() not in artifact.read_bytes(), artifact.name

@pytest.mark.parametrize("damage", ["owner", "uuid", "query", "multi", "target"])
def test_relay_recovery_requires_original_owner_parent_and_targets(monkeypatch, damage):
    from runtime import harvest, session_registry
    from runtime.recovery import parent_binding, recover_relay

    carrier = {"channel_id": "session-1", "kind": "console_session", "session_id": "7",
               "uuid": "original-uuid", "host": "192.0.2.10", "logical": "pivot",
               "endpoint": {"host": "192.0.2.1", "port": 55553}}
    frozen = parent_binding(carrier)
    row = {"channel_id": "tunnel-original", "kind": "proxy", "alive": True,
           "parent": "session-1", "session_binding": deepcopy(carrier),
           "note": json.dumps({"session_id": "7", "proved": [["192.0.2.42", "445"]]}),
           "tunnel_ports": [{"target": "192.0.2.42", "port": "445", "listen": "2201"}]}
    resource = {"host": "192.0.2.10", "port": 2201, "protocol": "tcp"}
    key = json.dumps(resource, sort_keys=True, separators=(",", ":"))
    lease = {"owner": "relay-original", "state": "held"}
    records = [row]
    monkeypatch.setattr(session_registry, "snapshot", lambda root: [carrier])
    monkeypatch.setattr(session_registry, "_registry",
                        lambda root: {"resources": {key: lease}, "releases": {}})
    monkeypatch.setattr(harvest, "read", lambda *args, **kwargs: records)
    options = dict(root="run", run_dir="run", frozen=frozen, owner="relay-original",
                   before=[], targets=[["192.0.2.42", 445]])
    assert recover_relay(**options)["state"] == "completed"
    if damage == "owner":
        lease["owner"] = "another-relay"
    elif damage == "uuid":
        carrier["uuid"] = "replacement-uuid"
    elif damage == "query":
        def unreadable(*args, **kwargs):
            raise OSError("unreadable artifact")
        monkeypatch.setattr(harvest, "read", unreadable)
    elif damage == "multi":
        records.append(dict(row, channel_id="tunnel-other"))
    else:
        row["tunnel_ports"][0]["target"] = "192.0.2.43"
    assert recover_relay(**options)["state"] == "unknown"

def test_saved_model_transport_timeout_is_unknown_without_hidden_resend(monkeypatch):
    from agents._model.client import HttpModel
    from runtime.recovery import RecoveryModel

    calls = []
    def timeout(*args):
        calls.append(args)
        raise TimeoutError("unclear provider commit")

    client = HttpModel(name="test", base_url="https://invalid.test", api_key="private-token",
                       opener=timeout, retries=4)
    state = {}
    model = RecoveryModel(client, {"state": state, "save": lambda values: None},
                          ["private-token"])
    with pytest.raises(ValueError, match="MODEL_CALL_UNKNOWN"):
        model.complete(task="test", system="test", user="test", timeout=90, retries=4)
    with pytest.raises(ValueError, match="MODEL_CALL_UNKNOWN"):
        model.complete(task="test", system="test", user="test", timeout=90, retries=4)
    assert len(calls) == 1
    assert calls[0][-1] <= 90
    assert state["model_calls"][0]["phase"] == "unknown"
    assert "private-token" not in json.dumps(state)

def test_interrupted_staging_is_recorded_and_blocks_the_parent(monkeypatch, tmp_path):
    from runtime import channels
    from runtime.runner import ExecOutcome

    sent = []
    def console_call(row, action, timeout):
        sent.append(action)
        marker = action["completion"]["marker"]
        if len(sent) == 2:
            raise KeyboardInterrupt("second staged block interrupted")
        return ExecOutcome(returncode=0, read_stop="end_marker",
                           stdout=marker + "start\n\n" + marker + "end 0\n")

    monkeypatch.setattr(channels, "console_call", console_call)
    secret = "batch3-staged-private-token"
    session = {"channel_id": "session-stage", "kind": "console_session",
               "session_id": "7", "uuid": "original-uuid", "session_type": "meterpreter",
               "platform": "linux", "capacity": {"max_bytes": 4096}}
    request = dict(REQUEST, method="POST", body="y" * 6000 + secret)
    run = run_at(tmp_path, Collector(), session=session, secrets=[secret])
    with pytest.raises(KeyboardInterrupt, match="staged block"):
        run.call(request)
    events = run.history()
    intents = [row for row in events if row["kind"] == "intent"]
    parent, children = intents[0], intents[1:]
    assert parent.get("parent_call_id", "") == ""
    assert len(children) == len(sent) == 2
    assert all(row["parent_call_id"] == parent["call_id"] for row in children)
    assert children[0]["staging_index"] == 0 and children[1]["staging_index"] == 1
    assert all("payload_sha256" in row["request"] and "payload" not in row["request"]
               for row in children)
    resumed = run_at(tmp_path, Collector(), session=session, secrets=[secret])
    facts = {row["call_id"]: row for row in resumed.recover_calls()}
    assert facts[parent["call_id"]]["state"] == "unknown"
    assert facts[children[0]["call_id"]]["state"] == "finished"
    assert facts[children[1]["call_id"]]["state"] == "unknown"
    with pytest.raises(ValueError, match="LEAN_UNRESOLVED_CALL"):
        resumed.call(request, resume_call=parent["call_id"])
    assert len(sent) == 2
    for artifact in tmp_path.rglob("*"):
        if artifact.is_file():
            assert secret.encode() not in artifact.read_bytes(), artifact.name
