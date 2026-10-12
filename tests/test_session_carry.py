"""Observed session lifecycle, explicit binding, and resource ownership regressions."""
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from orchestration import evidence  # noqa: E402

from runtime import msfservice  # noqa: E402

from runtime import session_io  # noqa: E402

from runtime import session_registry  # noqa: E402

from runtime import sessions  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from runtime import session_identity, session_io, session_registry, sessions
import run_plan
from runtime import msfservice, session_registry, session_io
from runtime.runner import ExecOutcome


ENDPOINT = {"host": "127.0.0.1", "port": 55553, "ssl": False}
CAPABILITIES = {"capacity": {"max_bytes": 4096, "source": "fixture payload measurement"},
                "shell_ready": True}
RESOURCE = {"host": "192.0.2.1", "port": 12345, "protocol": "tcp"}


@pytest.fixture
def registry(tmp_path, monkeypatch):
    monkeypatch.setenv("AGV_MSF_RPC", "msf:fixture-secret@127.0.0.1:55553")
    monkeypatch.setattr(session_registry, "_resource_root", lambda root: tmp_path / "resources")
    info = {"type": "shell", "session_host": "192.0.2.7", "platform": "linux", "uuid": "session-uuid"}
    listed = {"1": dict(info)}
    monkeypatch.setattr(msfservice, "client_for", lambda endpoint, *, deadline: object())
    def shape(client, sid, *, deadline):
        if sid not in listed:
            raise msfservice.MsfSessionMissing(sid)
        return dict(listed[sid], sid=sid)
    monkeypatch.setattr(msfservice, "session_shape", shape)
    monkeypatch.setattr(msfservice, "sessions", lambda client, *, deadline: dict(listed))
    receipt = {"confirmed": True, "command_rc": 0, "call_id": "probe-a", "outcome": ExecOutcome(0)}
    monkeypatch.setattr(session_io, "call_bound", lambda *a, **k: dict(receipt))
    def put(sid="1", *, root=tmp_path, capabilities=CAPABILITIES, **changes):
        listed.setdefault(sid, dict(info, uuid="uuid-" + sid)).update(changes)
        return sessions.register_session(root, endpoint=ENDPOINT, session_id=sid, logical="host-a",
                                        source_node="step-a", capabilities=capabilities)
    return SimpleNamespace(root=tmp_path, listed=listed, receipt=receipt, put=put)
def test_registration_uses_observed_type_and_uuid(registry):
    """Registration preserves authoritative type and incarnation instead of guessing from output."""
    row = registry.put(type="meterpreter", platform="windows")
    assert row["session_type"] == "meterpreter" and row["platform"] == "windows"
    assert row["uuid"] == registry.listed["1"]["uuid"]


def test_registration_keeps_liveness_unknown(registry):
    """A listed object alone cannot become a proven usable session."""
    assert registry.put()["observation"]["state"] == "unknown"


def test_registration_refuses_unknown_type(registry):
    """Unknown types are refused rather than becoming native sessions by default."""
    with pytest.raises(ValueError, match="SESSION_TYPE_UNSUPPORTED"):
        registry.put(type="unknown-type")


def test_registration_requires_observed_host(registry):
    """The graph's logical name cannot stand in for an observed session host."""
    with pytest.raises(ValueError, match="SESSION_METADATA_INCOMPLETE"):
        registry.put(session_host="")


def test_registration_requires_capacity(registry):
    """A carrier kind supplies no invented line limit."""
    with pytest.raises(ValueError, match="SESSION_CAPABILITIES_REQUIRED"):
        registry.put(capabilities={})


def test_capacity_requires_a_source(registry):
    """The send capacity must identify its measured or declared source."""
    with pytest.raises(ValueError, match="SESSION_CAPABILITIES_INVALID"):
        registry.put(capabilities={"capacity": {"max_bytes": 4096, "source": ""}, "shell_ready": True})


def test_harvest_history_never_becomes_current_state(registry):
    """Historical entries cannot resurrect an available session."""
    (registry.root / "harvest.jsonl").write_text('{"kind":"ssh","alive":true}\n')
    assert session_registry.snapshot(registry.root) == []


def test_probe_requires_a_confirmed_command(registry):
    """The usable-session check still runs and now requires framed command completion."""
    row = registry.put()
    assert sessions.probe(row)[0] is True
    assert session_registry.snapshot(registry.root)[0]["observation"]["state"] == "alive"
def test_unconfirmed_transport_stays_unknown(registry):
    """A transport reply without completion cannot count as a live-session proof."""
    row = registry.put()
    registry.receipt["confirmed"] = False
    assert sessions.probe(row)[0] is False
    assert session_registry.snapshot(registry.root)[0]["observation"]["state"] == "unknown"


def test_nonzero_command_stays_unknown(registry):
    """Transport rc zero cannot hide a failed probe command."""
    row = registry.put()
    registry.receipt["command_rc"] = 9
    assert sessions.probe(row)[0] is False
    assert session_registry.snapshot(registry.root)[0]["observation"]["state"] == "unknown"


def test_rpc_hiccup_is_unknown(registry, monkeypatch):
    """An RPC interruption remains unknown instead of producing death evidence."""
    row = registry.put()
    def unavailable(*args, **kwargs):
        raise msfservice.MsfUnreachable("unavailable")
    monkeypatch.setattr(msfservice, "session_shape", unavailable)
    assert sessions.probe(row)[0] is False
    assert session_registry.snapshot(registry.root)[0]["observation"]["state"] == "unknown"


def test_authoritative_absence_is_dead(registry):
    """A confirmed absent session supplies the death evidence that an RPC hiccup lacks."""
    row = registry.put()
    registry.listed.clear()
    assert sessions.probe(row) == (False, "CONSOLE_SESSION_GONE")
    assert session_registry.snapshot(registry.root)[0]["observation"]["state"] == "dead"


def test_probe_refuses_a_changed_type(registry):
    """Reusing an identifier cannot silently change how the bound session is interpreted."""
    row = registry.put()
    registry.listed["1"]["type"] = "meterpreter"
    assert "SESSION_BINDING_CHANGED" in sessions.probe(row)[1]


def test_carry_preserves_physical_identity(registry):
    """Carrying still transfers usable sessions while keeping one physical lock identity."""
    row = registry.put()
    target = registry.root / "target"
    carried, unavailable, superseded = sessions.carry_handles(registry.root, target, executor=None)
    assert carried[0][0] == row["channel_id"] and unavailable == superseded == []
    moved = session_registry.snapshot(target)[0]
    assert moved["channel_id"] == row["channel_id"] and moved["registry_root"] == str(target.resolve())
def test_carry_keeps_all_confirmed_bindings(registry):
    """Carry preserves alternatives instead of choosing a privilege-ranked favorite."""
    first, second = registry.put(), registry.put("2")
    carried, unavailable, superseded = sessions.carry_handles(registry.root, registry.root / "target", executor=None)
    assert {row[0] for row in carried} == {first["channel_id"], second["channel_id"]}
    assert unavailable == superseded == []
def test_carry_does_not_copy_unknown(registry):
    """An unconfirmed session is not carried and is not mislabeled dead or superseded."""
    registry.put()
    registry.receipt["confirmed"] = False
    carried, unavailable, superseded = sessions.carry_handles(registry.root, registry.root / "target", executor=None)
    assert carried == superseded == [] and len(unavailable) == 1


def test_revoke_requires_a_matching_receipt(registry):
    """A generic closing event cannot revoke a different session."""
    row = registry.put()
    with pytest.raises(ValueError, match="SESSION_STOP_UNCONFIRMED"):
        sessions.revoke_session(registry.root, row, receipt={"session_id": "2", "state": "stopped"})


def test_revoke_checks_actual_absence(registry):
    """A successful stop RPC alone cannot revoke a session still listed by the console."""
    row = registry.put()
    with pytest.raises(ValueError, match="SESSION_STOP_UNCONFIRMED"):
        sessions.revoke_session(registry.root, row, receipt={"session_id": "1", "state": "stopped"})


def test_confirmed_revoke_removes_reuse(registry):
    """A confirmed stopped session remains recorded but cannot be reused."""
    row = registry.put()
    registry.listed.clear()
    sessions.revoke_session(registry.root, row, receipt={"session_id": "1", "state": "stopped"})
    assert session_registry.snapshot(registry.root) == []
    stored = json.loads((registry.root / "sessions.json").read_text())
    assert stored["sessions"][row["channel_id"]]["lifecycle"] == "revoked"


def test_resource_owner_excludes_another_run(registry):
    """The same physical resource cannot be reserved through a different run registry."""
    session_registry.reserve_resources(registry.root, owner="first", resources=[RESOURCE])
    with pytest.raises(ValueError, match="SESSION_RESOURCE_BUSY"):
        session_registry.reserve_resources(registry.root / "other-run", owner="second", resources=[RESOURCE])


def test_unconfirmed_cleanup_keeps_ownership(registry):
    """An incomplete cleanup cannot make a leased port available again."""
    session_registry.reserve_resources(registry.root, owner="first", resources=[RESOURCE])
    with pytest.raises(ValueError, match="SESSION_RESOURCE_CLEANUP_UNCONFIRMED"):
        session_registry.release_resources(registry.root, owner="first", receipts=[{"confirmed": False}])
    assert json.loads((session_registry._resource_root(registry.root) / "sessions.json").read_text())["resources"]
def test_cleanup_releases_only_its_owner(registry):
    """Successful cleanup releases only the corresponding delivery attempt's resources."""
    session_registry.reserve_resources(registry.root, owner="first", resources=[RESOURCE])
    session_registry.reserve_resources(registry.root, owner="second", resources=[dict(RESOURCE, port=12346)])
    session_registry.release_resources(registry.root, owner="first", receipts=[{"confirmed": True, "command_rc": 0}])
    values = json.loads((session_registry._resource_root(registry.root) / "sessions.json").read_text())["resources"].values()
    assert {row["owner"] for row in values} == {"second"}
def test_rpc_carries_one_deadline(registry, monkeypatch):
    """The configured local RPC path passes one deadline to both client setup and invocation."""
    seen = []
    monkeypatch.setattr(msfservice, "client_for", lambda endpoint, *, deadline: seen.append(deadline) or object())
    monkeypatch.setattr(msfservice, "call", lambda client, method, *a, deadline: seen.append(deadline) or {})
    monkeypatch.setattr(session_io.time, "monotonic", lambda: 100.0)
    session_io.rpc_call()("session.list", deadline=123.0)
    assert seen == [123.0, 123.0]


def test_missing_console_does_not_implicitly_restart(monkeypatch):
    """Unavailable RPC is reported without destroying sessions through an implicit restart."""
    monkeypatch.setenv("AGV_MSF_RPC", "")
    result = session_io.ensure_console()
    assert result["state"] == "unavailable" and result["restarted"] is False


def test_probe_distinguishes_alive_unknown_and_missing(registry, monkeypatch):
    """An unconfirmed probe stays unknown; only an authoritative absence is dead."""
    row = registry.put()
    registry.receipt["confirmed"] = False
    alive, reason = sessions.probe(row)
    assert alive is False
    assert reason != "CONSOLE_SESSION_GONE"
    stored = session_registry.snapshot(registry.root)[0]
    assert stored["observation"]["state"] == "unknown"

    def gone(client, sid, *, deadline):
        raise msfservice.MsfSessionMissing(sid)

    monkeypatch.setattr(msfservice, "session_shape", gone)
    alive, reason = sessions.probe(row)
    assert alive is False and reason == "CONSOLE_SESSION_GONE"
    assert session_registry.snapshot(registry.root)[0]["observation"]["state"] == "dead"


def test_carry_cli_reports_its_result(registry, capsys):
    """The carry CLI still completes and reports which explicitly bound sessions transferred."""
    import session_manager

    registry.put()
    assert session_manager.main(
        ["carry", "--from", str(registry.root), "--to", str(registry.root / "target")]) == 0
    assert json.loads(capsys.readouterr().out)["carried"]


@pytest.mark.parametrize("value", [True, 0, -1, float("inf"), float("nan"), "1"])
def test_session_deadline_requires_a_finite_positive_budget(value):
    """An invalid caller budget cannot fall back to an invented RPC timeout."""
    with pytest.raises(ValueError, match="SESSION_TIMEOUT_INVALID"):
        session_io._deadline(value)


def test_probe_refuses_a_reused_session_identifier(registry):
    """A new incarnation of the same session number cannot inherit the old binding."""
    row = registry.put()
    registry.listed["1"]["uuid"] = "replacement-instance"
    assert "SESSION_BINDING_CHANGED" in sessions.probe(row)[1]


def test_resource_release_is_idempotent_after_a_crash(registry):
    """A durable release can be reconciled without rerunning an already confirmed cleanup."""
    receipts = [{"confirmed": True, "command_rc": 0, "call_id": "cleanup-a"}]
    session_registry.reserve_resources(registry.root, owner="first", resources=[RESOURCE])
    session_registry.release_resources(registry.root, owner="first", receipts=receipts)
    session_registry.release_resources(registry.root, owner="first", receipts=receipts)
    state = json.loads((session_registry._resource_root(registry.root) / "sessions.json").read_text())
    assert state["resources"] == {} and state["releases"]["first"]["receipts"] == receipts
def test_registration_rejects_relabelling_existing_binding(registry):
    """Registering the same incarnation cannot move its logical host or provenance."""
    original = registry.put()
    with pytest.raises(ValueError, match="SESSION_BINDING_RELABELLED"):
        sessions.register_session(registry.root, endpoint=ENDPOINT, session_id="1",
                                 logical="other-host", source_node="step-a",
                                 capabilities=CAPABILITIES)
    assert session_registry.snapshot(registry.root)[0]["logical"] == original["logical"]


def test_reused_session_number_has_a_new_incarnation_identity(registry):
    """A newly observed UUID can reuse a session number without inheriting the old binding."""
    first = registry.put()
    registry.listed.clear()
    sessions.revoke_session(registry.root, first, receipt={"session_id": "1", "state": "stopped"})
    second = registry.put(uuid="new-incarnation")
    assert first["channel_id"] != second["channel_id"]
    assert [row["uuid"] for row in session_registry.snapshot(registry.root)] == ["new-incarnation"]


def test_no_uuid_cannot_infer_safe_identifier_reuse(registry):
    """A reused identifier without authoritative incarnation evidence remains refused."""
    first = registry.put(uuid="")
    registry.listed.clear()
    sessions.revoke_session(registry.root, first, receipt={"session_id": "1", "state": "stopped"})
    with pytest.raises(ValueError, match="SESSION_REVOKED_BINDING"):
        registry.put(uuid="")


def test_live_old_incarnation_is_retired_only_by_observed_replacement(registry):
    """Registering an authoritative replacement retires the old incarnation without ranking."""
    first = registry.put()
    replacement = registry.put(uuid="new-incarnation")
    rows = session_registry.snapshot(registry.root)
    assert [row["channel_id"] for row in rows] == [replacement["channel_id"]]
    stored = json.loads((registry.root / "sessions.json").read_text())
    assert stored["sessions"][first["channel_id"]]["observation"]["reason"] == "SESSION_INCARNATION_REPLACED"


def test_the_identity_probe_budget_outlasts_a_settling_answer():
    """An unframed console verb settles only after its capture goes quiet; the budget must allow it.

    walk-140 node 7: a three-second budget cut the live pc1 console off mid-answer and the
    delivery recorded SESSION_PROBE_UNCONFIRMED for a session that was answering.
    """
    from runtime import channels

    assert session_identity.IDENTITY_COMMAND_BUDGET > channels.CONSOLE_IDLE_READS * channels.CONSOLE_READ_STEP


def test_one_channel_keeps_one_owner_and_contexts_are_observations(registry):
    """A privilege observed in place appends a context row on the same channel, never a second owner."""
    row = registry.put()
    observed = session_registry.register_observation(registry.root, channel_id=row["channel_id"],
                                            logical="web2", privilege="system", environment="host",
                                            identity={"user": "SYSTEM"})
    assert observed["channel_id"] == row["channel_id"]
    assert [item["privilege"] for item in session_registry.observations(registry.root)] == ["system"]
    with pytest.raises(ValueError, match="SESSION_OBSERVATION_CHANNEL_UNKNOWN"):
        session_registry.register_observation(registry.root, channel_id="ch-missing", logical="x",
                                     privilege="root", identity={}, environment="host")
    with pytest.raises(ValueError, match="SESSION_OBSERVATION_PRIVILEGE_REQUIRED"):
        session_registry.register_observation(registry.root, channel_id=row["channel_id"], logical="x",
                                     privilege="   ", identity={}, environment="host")


def test_a_registry_carrying_the_dropped_audit_column_stays_readable(tmp_path):
    """2026-10-08 事故回归：写侧新增合法审计字段后，读侧不许把整份登记表判成无效。

    现象：登记去重会把"丢弃"记进 dropped，而读侧当时要求键集恰好是四张表，
    于是写入之后再读就抛 SESSION_REGISTRY_INVALID（walk-186 第 12 步验收时整轮崩）。
    """
    registry = {"sessions": {"channel-1": {"lifecycle": "active", "host": "192.0.2.7"}},
                "resources": {}, "releases": {}, "contexts": {},
                "dropped": [{"node": "12", "dropped": ["pc1", "system"], "logical": "pc1"}]}
    (tmp_path / "sessions.json").write_text(json.dumps(registry), encoding="utf-8")
    rows = session_registry.snapshot(tmp_path)
    assert [row["host"] for row in rows] == ["192.0.2.7"]
    assert session_registry.observations(tmp_path) == []
    #: 真正的畸形文件仍然要被拒（未知键 / 表类型不对 / dropped 不是对象列表）。
    for broken in ({"sessions": {}, "resources": {}, "releases": {}, "contexts": {}, "typo": []},
                   {"sessions": [], "resources": {}, "releases": {}, "contexts": {}},
                   {"sessions": {}, "resources": {}, "releases": {}, "contexts": {}, "dropped": [1]}):
        (tmp_path / "sessions.json").write_text(json.dumps(broken), encoding="utf-8")
        with pytest.raises(ValueError, match="SESSION_REGISTRY_INVALID"):
            session_registry.snapshot(tmp_path)
