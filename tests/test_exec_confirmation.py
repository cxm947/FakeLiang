"""The acceptance basis for an execCode fact is what the session itself reported."""
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from agents.verifier import backstops  # noqa: E402

from runtime import delivery_commands  # noqa: E402

from agents.verifier import service  # noqa: E402

from orchestration import session_flow  # noqa: E402

from runtime import session_io  # noqa: E402

from runtime import session_registry  # noqa: E402

from runtime import sessions  # noqa: E402

from orchestration import positions  # noqa: E402
ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import run_plan
from tests.support import stub_callers
from runtime import session_identity, session_io, session_registry, sessions
from runtime import msfservice
from runtime import session_registry
from runtime import session_io
from runtime import session_identity
from runtime.runner import ExecOutcome


ENDPOINT = {"host": "127.0.0.1", "port": 55553, "ssl": False}
CAPABILITIES = {"capacity": {"max_bytes": 4096, "source": "fixture payload measurement"},
                "shell_ready": True}
HOST_MAP = {"web1": "192.0.2.10", "ubuntu": "192.0.2.10", "web2_docker": "192.0.2.10",
            "pc1": "192.0.2.30"}


def framed(marker, body):
    middle = (body + "\n") if body else ""
    return marker + "start\n" + middle + marker + "end 0\n"


def session_row(**changes):
    row = {"kind": "console_session", "source_node": "12", "host": "ubuntu",
           "channel_id": "session-1", "session_id": "1", "lifecycle": "registered",
           "identity": {"uid": "0", "user": "root", "hostname": "ubuntu",
                        "environment": "host", "call_id": "call-identity", "at": 1.0}}
    row.update(changes)
    return row


def criterion(logical="web1", privilege="root"):
    return {"ref": "11", "logical": logical, "privilege": privilege}


@pytest.fixture
def observed(tmp_path, monkeypatch):
    """One registered shell session, plus a fake console that answers the identity probe."""
    monkeypatch.setenv("AGV_MSF_RPC", "msf:fixture-secret@127.0.0.1:55553")
    monkeypatch.setattr(session_registry, "_resource_root", lambda root: tmp_path / "resources")
    info = {"type": "shell", "session_host": "ubuntu", "platform": "linux",
            "uuid": "session-uuid"}
    listed = {"1": dict(info)}
    monkeypatch.setattr(msfservice, "client_for", lambda endpoint, *, deadline: object())
    monkeypatch.setattr(msfservice, "session_shape",
                        lambda client, sid, *, deadline: dict(listed[sid], sid=sid))
    monkeypatch.setattr(msfservice, "sessions", lambda client, *, deadline: dict(listed))
    body = {"value": "0\nroot\nubuntu\n"}

    def fake_call(binding, request, timeout):
        command = str(request.get("cmd") or "")
        if "agv-session-probe" in command:
            return {"confirmed": True, "command_rc": 0, "call_id": "call-probe",
                    "marker": "agvprobe",
                    "outcome": ExecOutcome(returncode=0, stdout=framed("agvprobe", ""),
                                           read_stop="end_marker")}
        return {"confirmed": True, "command_rc": 0, "call_id": "call-identity",
                "marker": "agvident",
                "outcome": ExecOutcome(returncode=0, stdout=framed("agvident", body["value"]),
                                       read_stop="end_marker")}

    monkeypatch.setattr(session_io, "call_bound", fake_call)
    row = sessions.register_session(tmp_path, endpoint=ENDPOINT, session_id="1",
                                   logical="web1", source_node="12",
                                   source_call="delivery-fixture", capabilities=CAPABILITIES)
    return SimpleNamespace(root=tmp_path, row=row, body=body)
def test_identity_command_follows_the_observed_platform():
    """The identity check is chosen from the platform the console reported."""
    assert session_identity.identity_command({"platform": "windows", "session_type": "meterpreter"}) \
        == session_identity.IDENTITY_PROBE["windows"]
    assert session_identity.identity_command({"platform": "linux", "session_type": "shell"}) \
        == session_identity.IDENTITY_PROBE["posix"]


def test_read_identity_reads_a_container_from_the_raw_output():
    """A container marker in the raw evidence is what makes the position a container."""
    assert session_identity.read_identity("linux", "0\nroot\nubuntu\n")["environment"] == "host"
    inside = session_identity.read_identity("linux", "0\nroot\n8e172820ac78\n/docker/abc\n")
    assert inside["environment"] == "container"
    assert inside["uid"] == "0" and inside["user"] == "root"


def test_read_identity_refuses_output_it_cannot_read():
    """Unreadable output stays unobserved instead of being guessed."""
    assert session_identity.read_identity("linux", "command not found\n") == {}
    assert session_identity.read_identity("linux", "") == {}
    assert session_identity.read_identity("windows", "nt authority\\system\nWEB2\n") == {
        "uid": "", "user": "nt authority\\system", "hostname": "WEB2", "environment": "host"}


def test_read_identity_tolerates_a_console_banner():
    """A console prints its own chatter around the payload; the reading is found by shape."""
    body = "Process 1731 created.\nChannel 1 created.\n0\nroot\nubuntu\n"
    identity = session_identity.read_identity("linux", body)
    assert identity["uid"] == "0"
    assert identity["user"] == "root"
    assert identity["hostname"] == "ubuntu"
    assert identity["environment"] == "host"


def test_a_meterpreter_position_opens_its_shell_channel_first(meterpreter_path, monkeypatch):
    """A meterpreter session reads text as its own commands; the channel is opened, not assumed."""
    written = []
    script = iter(["Process 10 created.\nChannel 1 created.\n", "",
                   "echo agvCHREADY\n", "0\nagvCHREADY\n"])
    monkeypatch.setattr(msfservice, "shell_write",
                        lambda client, sid, text, *, deadline: written.append(text))
    monkeypatch.setattr(msfservice, "shell_read",
                        lambda client, sid, *, deadline: next(script, ""))
    opened, reason = session_io.ensure_shell_channel(meterpreter_path.row, timeout=5.0)
    assert opened is True and reason == "SHELL_CHANNEL_OPEN"
    assert written[0] == "shell\n"
    assert "echo agvCHREADY" in written[1]
    assert session_registry.snapshot(meterpreter_path.root)[0]["shell_channel"] is True
    opened, reason = session_io.ensure_shell_channel(
        session_registry.snapshot(meterpreter_path.root)[0], timeout=5.0)
    assert opened is True and written[0] == "shell\n" and len(written) == 2, \
        "a second look must not reopen it"


def test_probe_records_the_identity_the_session_reported(observed):
    """The probe keeps the raw identity observation next to the liveness observation."""
    alive, reason = sessions.probe(observed.row, timeout=5.0)
    assert alive is True
    row = session_registry.snapshot(observed.root)[0]
    assert row["observation"]["state"] == "alive"
    assert row["identity"]["uid"] == "0"
    assert row["identity"]["user"] == "root"
    assert row["identity"]["call_id"] == "call-identity"
    assert row["identity"]["raw"] == observed.body["value"].strip()
@pytest.fixture
def live_path(tmp_path, monkeypatch):
    """A registered session with the real framed-call path left in place."""
    monkeypatch.setenv("AGV_MSF_RPC", "msf:fixture-secret@127.0.0.1:55553")
    monkeypatch.setattr(session_registry, "_resource_root", lambda root: tmp_path / "resources")
    listed = {"1": {"type": "shell", "session_host": "ubuntu", "platform": "linux",
                    "uuid": "session-uuid"}}
    monkeypatch.setattr(msfservice, "client_for", lambda endpoint, *, deadline: object())
    monkeypatch.setattr(msfservice, "session_shape",
                        lambda client, sid, *, deadline: dict(listed[sid], sid=sid))
    row = sessions.register_session(tmp_path, endpoint=ENDPOINT, session_id="1",
                                   logical="web1", source_node="12", source_call="delivery-x",
                                   capabilities=CAPABILITIES)
    return SimpleNamespace(root=tmp_path, row=row)
@pytest.fixture
def meterpreter_path(tmp_path, monkeypatch):
    """The same registration, for the console kind that reads text as its own commands."""
    monkeypatch.setenv("AGV_MSF_RPC", "msf:fixture-secret@127.0.0.1:55553")
    monkeypatch.setattr(session_registry, "_resource_root", lambda root: tmp_path / "resources")
    listed = {"1": {"type": "meterpreter", "session_host": "ubuntu", "platform": "linux",
                    "uuid": "session-uuid"}}
    monkeypatch.setattr(msfservice, "client_for", lambda endpoint, *, deadline: object())
    monkeypatch.setattr(msfservice, "session_shape",
                        lambda client, sid, *, deadline: dict(listed[sid], sid=sid))
    row = sessions.register_session(tmp_path, endpoint=ENDPOINT, session_id="1",
                                   logical="web1", source_node="12", source_call="delivery-x",
                                   capabilities=CAPABILITIES)
    return SimpleNamespace(root=tmp_path, row=row)
def test_probe_reads_identity_through_the_real_call_path(live_path, monkeypatch):
    """The framed call path itself is exercised: no session had ever been probed for real."""
    from runtime import channels

    seen = []

    def console_call(binding, action, timeout):
        marker = action["completion"]["marker"]
        seen.append(action["text"])
        body = "0\nroot\nubuntu\n" if "id -un" in action["text"] else ""
        return ExecOutcome(returncode=0, read_stop="end_marker",
                           stdout=marker + "start\n" + body + marker + "end 0\n")

    monkeypatch.setattr(channels, "console_call", console_call)
    alive, reason = sessions.probe(live_path.row, timeout=10.0)
    assert alive is True
    row = session_registry.snapshot(live_path.root)[0]
    assert row["identity"]["uid"] == "0" and row["identity"]["user"] == "root"
    assert any("agv-session-probe" in text for text in seen)
    assert any("id -u" in text for text in seen)
    assert row["observation"]["state"] == "alive"


def test_declared_privilege_is_not_evidence():
    """A row without an identity observation cannot confirm the fact."""
    rows = [session_row(identity=None)]
    verdict = backstops.backstop_exec_code(criterion=criterion(), sessions=rows,
                                          host_map=HOST_MAP, node_id="12")
    assert verdict["verdict"] == "UNKNOWN"
    assert verdict["reason"] == "EXEC_IDENTITY_UNOBSERVED"


def test_observed_root_on_the_mapped_host_is_confirmed():
    """The identity the session reported, on the mapped host, is the acceptance basis."""
    rows = [session_row()]
    verdict = backstops.backstop_exec_code(criterion=criterion(), sessions=rows,
                                          host_map=HOST_MAP, node_id="12")
    assert verdict["verdict"] == "TRUE"
    assert verdict["checker"] == "session_observed_identity"
    assert verdict["evidence"][0]["call_id"] == "call-identity"
    assert verdict["evidence"][0]["observed_identity"]["uid"] == "0"


def test_container_root_is_not_host_root():
    """A container identity cannot stand in for a host identity."""
    rows = [session_row(identity={"uid": "0", "user": "root", "hostname": "8e172820ac78",
                                  "environment": "container", "call_id": "call-identity"})]
    verdict = backstops.backstop_exec_code(criterion=criterion(), sessions=rows,
                                          host_map=HOST_MAP, node_id="12")
    assert verdict["verdict"] == "UNKNOWN"
    assert verdict["reason"] == "EXEC_ENVIRONMENT_MISMATCH"


def test_container_fact_needs_a_container_identity():
    """When the deployment marks the target as a container, a host identity is not it."""
    rows = [session_row()]
    inside = backstops.backstop_exec_code(
        criterion=criterion(logical="web2_docker"), sessions=rows, host_map=HOST_MAP,
        node_id="12", environments={"web2_docker": "container"})
    assert inside["reason"] == "EXEC_ENVIRONMENT_MISMATCH"
    rows = [session_row(identity={"uid": "0", "user": "root", "hostname": "8e172820ac78",
                                  "environment": "container", "call_id": "call-identity"})]
    inside = backstops.backstop_exec_code(
        criterion=criterion(logical="web2_docker"), sessions=rows, host_map=HOST_MAP,
        node_id="12", environments={"web2_docker": "container"})
    assert inside["verdict"] == "TRUE"


def test_a_windows_system_label_needs_the_observed_account():
    """The session tag alone never becomes the execution identity."""
    rows = [session_row(host="pc1",
                        identity={"uid": "", "user": "lab\\administrator",
                                  "hostname": "PC1", "environment": "host",
                                  "call_id": "call-identity"})]
    verdict = backstops.backstop_exec_code(
        criterion=criterion(logical="pc1", privilege="system"), sessions=rows,
        host_map=HOST_MAP, node_id="12")
    assert verdict["reason"] == "EXEC_IDENTITY_NOT_SYSTEM"
    rows = [session_row(host="pc1",
                        identity={"uid": "", "user": "nt authority\\system",
                                  "hostname": "PC1", "environment": "host",
                                  "call_id": "call-identity"})]
    verdict = backstops.backstop_exec_code(
        criterion=criterion(logical="pc1", privilege="system"), sessions=rows,
        host_map=HOST_MAP, node_id="12")
    assert verdict["verdict"] == "TRUE"


def test_a_service_account_matches_across_separator_styles():
    """The graph writes www_data; the account reports www-data."""
    rows = [session_row(identity={"uid": "33", "user": "www-data", "hostname": "8e172820ac78",
                                  "environment": "container", "call_id": "call-identity"})]
    verdict = backstops.backstop_exec_code(
        criterion=criterion(logical="web2_docker", privilege="www_data"), sessions=rows,
        host_map=HOST_MAP, node_id="12", environments={"web2_docker": "container"})
    assert verdict["verdict"] == "TRUE"


def test_two_matching_sessions_cannot_be_resolved():
    """Ambiguity is reported instead of picking the first or the highest one."""
    rows = [session_row(), session_row(channel_id="session-2", session_id="2")]
    verdict = backstops.backstop_exec_code(criterion=criterion(), sessions=rows,
                                          host_map=HOST_MAP, node_id="12")
    assert verdict["verdict"] == "UNKNOWN"
    assert verdict["reason"] == "EXEC_EVIDENCE_AMBIGUOUS"


def test_an_identity_without_a_recorded_call_is_not_evidence():
    """Evidence that cannot be cited back to a recorded call stays unusable."""
    rows = [session_row(identity={"uid": "0", "user": "root", "hostname": "ubuntu",
                                  "environment": "host", "call_id": ""})]
    verdict = backstops.backstop_exec_code(criterion=criterion(), sessions=rows,
                                          host_map=HOST_MAP, node_id="12")
    assert verdict["reason"] == "EXEC_IDENTITY_CALL_UNRECORDED"


def test_another_nodes_session_is_not_this_nodes_evidence():
    """A session another node registered does not confirm this node's output."""
    rows = [session_row(source_node="7")]
    verdict = backstops.backstop_exec_code(criterion=criterion(), sessions=rows,
                                          host_map=HOST_MAP, node_id="12")
    assert verdict["reason"] == "NO_REGISTERED_OUTPUT_SESSION"


def test_a_retired_session_is_not_current_evidence():
    """A revoked incarnation does not stand in for a live one."""
    rows = [session_row(lifecycle="revoked")]
    verdict = backstops.backstop_exec_code(criterion=criterion(), sessions=rows,
                                          host_map=HOST_MAP, node_id="12")
    assert verdict["verdict"] == "UNKNOWN"


GETUID = "Server username: root\n"
SYSINFO = ("Computer     : 192.168.3.106\nOS           : Ubuntu 18.04 (Linux)\n"
           "Architecture : x64\n")


def test_a_console_reports_its_own_identity_without_a_shell():
    """`getuid`/`sysinfo` answer on their own, whatever channel the console is in."""
    identity = session_identity.read_native_identity("linux", GETUID, SYSINFO)
    assert identity["uid"] == "0"
    assert identity["user"] == "root"
    assert identity["hostname"] == "192.168.3.106"
    assert identity["environment"] == "host"
    assert identity["source"] == "console_identity_commands"


def test_a_container_shaped_computer_name_reads_as_a_container():
    """A container's console reports the container id as its computer name."""
    podinfo = ("Computer     : 8e172820ac78\nOS           : Ubuntu 18.04 (Linux)\n")
    identity = session_identity.read_native_identity("linux", GETUID, podinfo)
    assert identity["environment"] == "container"


def test_a_console_that_refuses_to_say_stays_unobserved():
    """No username means no observation, and a missing computer name is not filled in."""
    assert session_identity.read_native_identity("linux", "", SYSINFO) == {}
    partial = session_identity.read_native_identity("linux", GETUID, "")
    assert partial["user"] == "root" and partial["environment"] == "unknown"


def test_native_identity_is_recorded_with_the_call_that_answered(meterpreter_path, monkeypatch):
    """The observation cites the console call that produced it."""
    answers = iter([GETUID, SYSINFO])
    monkeypatch.setattr(
        session_io, "call_bound",
        lambda row, request, timeout: {"confirmed": True, "command_rc": 0,
                                       "call_id": "call-" + str(request["cmd"]),
                                       "outcome": ExecOutcome(returncode=None,
                                                              stdout=next(answers),
                                                              timed_out=True,
                                                              read_stop="deadline")})
    identity = session_identity.observe_native_identity(meterpreter_path.row, timeout=10.0)
    assert identity["user"] == "root" and identity["uid"] == "0"
    assert identity["call_id"] == "call-getuid"
def test_a_later_probe_asks_only_for_an_answer(meterpreter_path, monkeypatch):
    """A recorded identity is not re-read, but the console must still answer to be alive."""
    asked = []

    def fake(row, request, timeout):
        asked.append(request["cmd"])
        return {"confirmed": True, "command_rc": 0, "call_id": "call-" + request["cmd"],
                "outcome": ExecOutcome(returncode=None, stdout="Server username: root\n",
                                       timed_out=True, read_stop="deadline")}

    monkeypatch.setattr(session_io, "call_bound", fake)
    monkeypatch.setattr(session_io, "ensure_shell_channel",
                        lambda row, **kwargs: (True, "SHELL_CHANNEL_OPEN"))
    stored = {"uid": "0", "user": "root", "hostname": "192.168.52.10", "environment": "host",
              "call_id": "call-old"}
    registry = meterpreter_path.root / "sessions.json"
    data = json.loads(registry.read_text(encoding="utf-8"))
    for item in data["sessions"].values():
        item["identity"] = stored
        item["shell_channel"] = True
    registry.write_text(json.dumps(data), encoding="utf-8", newline="\n")
    row = dict(session_registry.snapshot(meterpreter_path.root)[0],
               registry_root=str(meterpreter_path.root))
    alive, _reason = sessions.probe(row, timeout=8.0)
    assert alive is True
    assert asked == ["getuid"], "the identity is already known; only an answer is needed"
    assert session_registry.snapshot(meterpreter_path.root)[0]["identity"] == stored
    assert session_registry.snapshot(meterpreter_path.root)[0]["observation"]["state"] == "alive"


def test_native_identity_preserves_evidence_when_sysinfo_is_unconfirmed(monkeypatch):
    """A failed sysinfo retains the confirmed account without confirming the whole read."""
    asked = []

    def call(binding, request, timeout):
        command = request["cmd"]
        asked.append(command)
        if command == "getuid":
            return {
                "confirmed": True,
                "command_rc": 0,
                "call_id": "call-getuid",
                "outcome": ExecOutcome(
                    0, stdout="Server username: NT AUTHORITY\\SYSTEM\n",
                    read_stop="quiet"),
            }
        assert command == "sysinfo"
        return {
            "confirmed": False,
            "command_rc": None,
            "call_id": "call-sysinfo",
            "outcome": ExecOutcome(
                None, stdout="", timed_out=True, read_stop="deadline"),
        }

    monkeypatch.setattr(session_io, "call_bound", call)
    with pytest.raises(
            session_identity.NativeIdentityUnconfirmed,
            match="SESSION_IDENTITY_COMMAND_UNCONFIRMED: sysinfo") as caught:
        session_identity.observe_native_identity(
            {"platform": "windows"}, timeout=20.0,
            commands=("getuid", "sysinfo", "getuid"))

    assert asked == ["getuid", "sysinfo"]
    assert caught.value.failed_call_id == "call-sysinfo"
    partial = caught.value.partial_identity
    assert partial["user"] == "NT AUTHORITY\\SYSTEM"
    assert partial["call_id"] == "call-getuid"
    assert partial["hostname"] == ""
    assert partial["environment"] == "unknown"
    assert partial["raw"] == "Server username: NT AUTHORITY\\SYSTEM\n"
