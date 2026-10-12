"""Session ownership and explicit bound-action contracts."""
import inspect
import json
import os
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from runtime import channels
from tests import support


def test_a_meterpreter_position_keeps_its_shell_channel_open():
    """The framed text must not close the persistent channel it is written into.

    Measured on the lab (2026-10-08): a trailing `exit` closed the channel the payload's
    output was still travelling through, so the completion marker never arrived and the call
    stayed unsettled.
    """
    from runtime import dispatch

    binding = {"session_type": "meterpreter", "platform": "linux", "uuid": "u",
               "endpoint": {"host": "127.0.0.1", "port": 55553, "ssl": False},
               "channel_id": "c", "session_id": "1",
               "capacity": {"max_bytes": 4096, "source": "fixture"}, "shell_ready": True}
    action = dispatch.bind_console({"tool": "cmd", "cmd": "echo hi"}, binding, marker="agvm1")
    assert 'exit "$probe_rc"' not in action["text"]
    assert "\n" not in action["text"].strip()
    assert action["text"].startswith("printf '%s\\n' agvm1start; ")
    assert action["text"].rstrip("\n").endswith(
        'printf \'\\n%s %s\\n\' agvm1end "$probe_rc"')
    assert "agvm1start" in action["text"] and "agvm1end" in action["text"]
    shell = dict(binding, session_type="shell")
    other = dispatch.bind_console({"tool": "cmd", "cmd": "echo hi"}, shell, marker="agvm2")
    assert 'exit "$probe_rc"' in other["text"]


def test_unconfirmed_native_attempt_is_archived_before_a_new_attempt(
        tmp_path, monkeypatch):
    """A new call proceeds without replaying or confirming the old unanswered call."""
    import json

    from runtime import channels, msfservice
    from tests import support

    console = support.wire_console(
        monkeypatch, tmp_path=tmp_path, session_type="meterpreter",
        when_run=[("getuid", "Server username: fixture-user\n")])
    binding = dict(
        support.session_binding(sid="5", session_type="meterpreter"),
        registry_root=str(tmp_path), uuid="fixture-incarnation")

    def shape(client, sid, *, deadline):
        return {"sid": sid, "type": "meterpreter", "uuid": "fixture-incarnation"}

    monkeypatch.setattr(msfservice, "session_shape", shape)
    first = channels.console_call(
        binding, {"operation": "native", "text": "sysinfo", "completion": None}, 1.0)
    assert first.stdout == ""
    assert first.read_stop == "deadline"
    assert first.timed_out is True

    token = channels.begin_use(binding)
    try:
        directory = token.session_dir
        pending = directory / "unsettled.json"
        previous = json.loads(pending.read_text(encoding="utf-8"))
    finally:
        channels.end_use(token)

    second = channels.console_call(
        binding, {"operation": "native", "text": "getuid", "completion": None}, 5.0)

    assert console.singles == ["sysinfo", "getuid"]
    assert second.stdout == "Server username: fixture-user\n"
    assert second.read_stop == "quiet"
    assert not pending.exists()

    archives = list(directory.glob("unsettled-*.json"))
    assert len(archives) == 1
    archived = json.loads(archives[0].read_text(encoding="utf-8"))
    assert all(archived[key] == value for key, value in previous.items())
    assert archived["archive"]["state"] == "unresolved"
    assert archived["archive"]["capture_sha256"] is None
    assert not (directory / (previous["attempt_id"] + ".json")).exists()

    completed = [
        path for path in directory.glob("*.json")
        if len(path.stem) == 32
        and all(char in "0123456789abcdef" for char in path.stem)
    ]
    assert len(completed) == 1
    current = json.loads(completed[0].read_text(encoding="utf-8"))
    assert current["attempt_id"] != previous["attempt_id"]
    assert current["previous_unresolved"] == {
        "attempt_id": previous["attempt_id"],
        "archive": archives[0].name,
    }


def test_channels_has_only_the_five_session_entry_points():
    functions = {name for name, value in vars(channels).items()
                 if inspect.isfunction(value) and value.__module__ == channels.__name__}
    assert functions == {"begin_use", "end_use", "_read_until", "_capture_outcome", "console_call",
                         "_reconcile_settled_attempt", "_archive_unresolved_attempt"}


def test_physical_session_aliases_share_one_os_lock(monkeypatch, tmp_path):
    monkeypatch.setattr(channels.tempfile, "gettempdir", lambda: str(tmp_path))
    binding = support.session_binding()
    token = channels.begin_use(binding)
    alias = dict(binding, channel_id="another-run", logical="renamed-host", privilege="admin")
    try:
        with pytest.raises(ValueError, match="CHANNEL_BUSY"):
            channels.begin_use(alias)
        other = channels.begin_use(support.session_binding(sid="2"))
        channels.end_use(other)
        channels.end_use(ExitStack())
        with pytest.raises(ValueError, match="CHANNEL_BUSY"):
            channels.begin_use(alias)
    finally:
        channels.end_use(token)
    channels.end_use(token)
    again = channels.begin_use(alias)
    channels.end_use(again)


def test_a_lock_is_not_stolen_when_its_file_looks_old(monkeypatch, tmp_path):
    monkeypatch.setattr(channels.tempfile, "gettempdir", lambda: str(tmp_path))
    binding = support.session_binding()
    token = channels.begin_use(binding)
    lock = token.session_dir / "owner.lock"
    try:
        os.utime(lock, (1, 1))
        with pytest.raises(ValueError, match="CHANNEL_BUSY"):
            channels.begin_use(binding)
    finally:
        channels.end_use(token)
    assert lock.is_file()


def test_another_process_cannot_acquire_the_same_session(monkeypatch, tmp_path):
    monkeypatch.setattr(channels.tempfile, "gettempdir", lambda: str(tmp_path))
    binding = support.session_binding()
    code = (
        "import json,sys,tempfile\n"
        "sys.path.insert(0,sys.argv[1])\n"
        "from runtime import channels\n"
        "tempfile.gettempdir=lambda:sys.argv[2]\n"
        "try:\n"
        " token=channels.begin_use(json.loads(sys.argv[3]))\n"
        "except ValueError as error:\n"
        " print(str(error))\n"
        "else:\n"
        " print('ACQUIRED');channels.end_use(token)\n")
    argv = [sys.executable, "-B", "-c", code, str(ROOT / "src"), str(tmp_path), json.dumps(binding)]
    token = channels.begin_use(binding)
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=10,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        assert done.returncode == 0 and done.stdout.strip() == "CHANNEL_BUSY", done.stderr
    finally:
        channels.end_use(token)
    done = subprocess.run(argv, capture_output=True, text=True, timeout=10,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert done.returncode == 0 and done.stdout.strip() == "ACQUIRED", done.stderr


@pytest.mark.parametrize("binding", [None, {}, {"endpoint": {}, "session_id": "1"},
    {"endpoint": {"host": "host", "port": True, "ssl": False}, "session_id": "1"}])
def test_incomplete_bindings_never_acquire_a_lock(binding):
    with pytest.raises(ValueError, match="CHANNEL_BINDING_INVALID"):
        channels.begin_use(binding)


def test_bound_delivery_commands_are_sent_once_without_rewriting(monkeypatch, tmp_path):
    """An upstream-bound cleanup/upload action is preserved without automatic delivery tiers."""
    text = "base64 -d /tmp/declared.b64 > /tmp/declared.bin\nrm -f /tmp/declared.b64\n"
    console = support.wire_console(monkeypatch, tmp_path=tmp_path,
        when_written=[(text, "agvteststart\nwritten\nagvtestend 0\n")])
    outcome = channels.console_call(support.session_binding(), support.bound_action(text), 2.0)
    assert outcome.read_stop == "end_marker"
    assert console.writes == [text]
    console_writes = console.writes
    assert any("base64 -d" in item for item in console_writes), "内容是按段写进会话再解码的"
    assert any("rm -f" in item for item in console_writes), "先清场，别把上一次的残片拼进来"


def test_a_native_verb_settles_on_its_own_answer_instead_of_the_deadline(monkeypatch, tmp_path):
    """`sysinfo` closes no frame: a complete answer used to be recorded as a 60 s timeout."""
    answer = "Computer        : PC1\nOS              : Windows 7 (6.1 Build 7601).\n"
    console = support.wire_console(monkeypatch, tmp_path=tmp_path, session_type="meterpreter",
                                   when_run=[("sysinfo", answer)])
    outcome = channels.console_call(
        support.session_binding(session_type="meterpreter"),
        support.bound_action("sysinfo", marker=None, operation="native"), 60.0)
    assert console.singles == ["sysinfo"]
    assert outcome.read_stop == "quiet" and not outcome.timed_out
    assert outcome.returncode == 0 and "Computer" in outcome.stdout
