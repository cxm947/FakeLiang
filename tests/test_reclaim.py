"""回收之后要能"回查"：清干净了没有得能被查，不是靠感觉（爷爷 2026-10-06）。"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import reclaim       # noqa: E402
from runtime import session_io, sessions   # noqa: E402


def carrier():
    return {"kind": "console_session", "channel_id": "ch-1", "host": "192.0.2.10",
            "logical": "worker", "platform": "linux", "session_type": "shell",
            "endpoint": {"host": "127.0.0.1", "port": 55553, "ssl": False},
            "session_id": "1", "shell_ready": True,
            "capacity": {"max_bytes": 65536, "source": "test declaration"}}


def wire(monkeypatch, text, *, confirmed=True, command_rc=0):
    calls = []

    def call(binding, request, timeout):
        calls.append((binding, request, timeout))
        outcome = type("O", (), {"stdout": text, "stderr": "", "returncode": 0,
                                 "timed_out": False, "tool_error": None,
                                 "read_stop": "end_marker" if confirmed else "idle"})()
        return {"outcome": outcome, "confirmed": confirmed,
                "command_rc": command_rc if confirmed else None}

    monkeypatch.setattr(session_io, 'call_bound', call)
    return calls


CLEAN = "@@ files\n@@ listeners\n@@ processes\n@@ keyline\n0\nLEFTOVER-DONE\n"
DIRTY = ("@@ files\n/tmp/agv_session.exe\n@@ listeners\nLISTEN 0 256 127.0.0.1:1090\n"
         "@@ processes\n@@ keyline\n2\nLEFTOVER-DONE\n")


def test_a_clean_host_says_clean(monkeypatch):
    """A clean report still needs one completed observation on the bound session."""
    calls = wire(monkeypatch, "framestart\n" + CLEAN + "frameend 0\n")
    lines = reclaim.leftover_scan(None, [carrier()], apply=True)
    assert lines == ["worker: Clean"]
    assert len(calls) == 1 and calls[0][0] == carrier()


def test_what_is_left_is_named_not_swallowed(monkeypatch):
    """The confirmed observation still reports every remaining artifact by name."""
    wire(monkeypatch, DIRTY)
    lines = reclaim.leftover_scan(None, [carrier()], apply=True)
    assert "Remaining" in lines[0]
    assert "agv_session.exe" in lines[0] and "1090" in lines[0] and "keyline: 2" in lines[0]


def test_a_host_we_can_no_longer_enter_is_reported_as_such(monkeypatch):
    """An unusable session still produces an explicit unknown cleanup result."""
    def unavailable(binding, request, timeout):
        raise ValueError("SESSION_NOT_PRESENT")

    monkeypatch.setattr(session_io, 'call_bound', unavailable)
    lines = reclaim.leftover_scan(None, [carrier()], apply=True)
    assert "SESSION_NOT_PRESENT" in lines[0]
    assert "RECLAIM_OBSERVATION_UNCONFIRMED" in lines[0]


def test_unconfirmed_or_incomplete_output_never_proves_clean(monkeypatch):
    """Neither a clean-looking partial read nor an empty report proves cleanup."""
    wire(monkeypatch, CLEAN, confirmed=False)
    assert "RECLAIM_OBSERVATION_UNCONFIRMED" in reclaim.leftover_scan(
        None, [carrier()], apply=True)[0]
    wire(monkeypatch, "LEFTOVER-DONE\n")
    assert "RECLAIM_REPORT_INCOMPLETE" in reclaim.leftover_scan(
        None, [carrier()], apply=True)[0]


def test_ambiguous_host_aliases_do_not_pick_a_session():
    """Two bindings for one host remain ambiguous instead of selecting the first."""
    first = carrier()
    second = dict(first, session_id="2", channel_id="ch-2")
    mapping = reclaim.executor_spellings(None, [first, second], "")
    assert first["host"] not in mapping and first["logical"] not in mapping


def stop_fixture(monkeypatch, *, observed=None, failure=""):
    from contextlib import ExitStack
    from runtime import channels, msfservice

    binding = dict(carrier(), uuid="incarnation-current")
    current = {"sid": "1", "type": "shell", "uuid": binding["uuid"],
               "session_host": binding["host"]}
    if observed is not None:
        current.update(observed)
    calls, revoked, released = [], [], []
    token = ExitStack()
    token.callback(lambda: released.append(True))

    def begin(row):
        if failure == "busy":
            raise ValueError("CHANNEL_BUSY")
        return token

    def client(endpoint, *, deadline):
        calls.append(("client", deadline))
        return object()

    def shape(client, sid, *, deadline):
        calls.append(("shape", deadline))
        if failure == "missing":
            raise msfservice.MsfSessionMissing(sid)
        if failure == "unreachable":
            raise msfservice.MsfUnreachable("disconnected")
        return current

    def stop(client, sid, *, deadline):
        calls.append(("stop", deadline))
        return True

    monkeypatch.setattr(channels, "begin_use", begin)
    monkeypatch.setattr(msfservice, "client_for", client)
    monkeypatch.setattr(msfservice, "session_shape", shape)
    monkeypatch.setattr(msfservice, "stop_session", stop)
    monkeypatch.setattr(sessions, 'revoke_session',
        lambda root, row, *, receipt, timeout: revoked.append((root, row, receipt, timeout)))
    rpc = {"host": "127.0.0.1", "port": 55553, "user": "test", "password": "private"}
    return binding, rpc, calls, revoked, released


def test_a_reused_session_number_cannot_stop_a_different_uuid(monkeypatch):
    """Reclaim refuses a replacement incarnation instead of stopping an unrelated session."""
    binding, rpc, calls, revoked, released = stop_fixture(
        monkeypatch, observed={"uuid": "replacement"})
    lines = reclaim.stop_framework(None, [binding], rpc, apply=True, run_dir="registry")
    assert lines == ["session 1: RECLAIM_IDENTITY_CHANGED"]
    assert [name for name, _ in calls] == ["client", "shape"]
    assert revoked == [] and released == [True]


def test_an_authoritative_matching_incarnation_is_stopped_then_revoked(monkeypatch):
    """Only the matching UUID, type and host may be stopped and subsequently revoked."""
    binding, rpc, calls, revoked, released = stop_fixture(monkeypatch)
    lines = reclaim.stop_framework(None, [binding], rpc, apply=True, run_dir="registry")
    assert lines == ["session 1 stopped and registration revoked"]
    assert [name for name, _ in calls] == ["client", "shape", "stop"]
    assert len({deadline for _, deadline in calls}) == 1
    assert revoked[0][:3] == ("registry", binding, {"session_id": "1", "state": "stopped"})
    assert released == [True]


def test_identity_gaps_or_changed_type_and_host_never_stop_a_session(monkeypatch):
    """Missing identity fields and changed authoritative roles preserve the registered session."""
    for observed, reason in [({"uuid": None}, "UNCONFIRMED"),
                             ({"session_host": ""}, "UNCONFIRMED"),
                             ({"type": "unknown"}, "UNCONFIRMED"),
                             ({"session_host": "192.0.2.99"}, "CHANGED"),
                             ({"type": "meterpreter"}, "CHANGED")]:
        binding, rpc, calls, revoked, released = stop_fixture(monkeypatch, observed=observed)
        lines = reclaim.stop_framework(None, [binding], rpc, apply=True, run_dir="registry")
        assert lines == ["session 1: RECLAIM_IDENTITY_" + reason]
        assert all(name != "stop" for name, _ in calls)
        assert revoked == [] and released == [True]
    binding, rpc, calls, revoked, released = stop_fixture(monkeypatch)
    binding.pop("uuid")
    assert reclaim.stop_framework(None, [binding], rpc, apply=True, run_dir="registry") == [
        "session 1: RECLAIM_IDENTITY_UNCONFIRMED"]
    assert all(name != "stop" for name, _ in calls) and revoked == [] and released == [True]


def test_busy_missing_and_unreachable_sessions_preserve_the_registry(monkeypatch):
    """Ownership and RPC failures remain named per-session results without revocation."""
    for failure, reason in [("busy", "CHANNEL_BUSY"), ("missing", "RECLAIM_SESSION_MISSING"),
                            ("unreachable", "RECLAIM_RPC_UNCONFIRMED")]:
        binding, rpc, calls, revoked, released = stop_fixture(monkeypatch, failure=failure)
        lines = reclaim.stop_framework(None, [binding], rpc, apply=True, run_dir="registry")
        assert reason in lines[0]
        assert all(name != "stop" for name, _ in calls) and revoked == []
        assert released == ([] if failure == "busy" else [True])


def test_a_dry_run_only_says_what_it_would_check(monkeypatch):
    """A dry run still makes no remote call."""
    calls = wire(monkeypatch, CLEAN)
    lines = reclaim.leftover_scan(None, [carrier()], apply=False)
    assert calls == []
    assert "会回查" in lines[0]
