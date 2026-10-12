"""控制台载体：引擎本机用 msf 服务端点驱动会话（不再往控制端推发送端脚本）。

2026-10-07 桥评审定稿的**完成判据**：
* 有序、完整的**目标侧** start/end 帧 ＝ 运输完成（带退出码时同时给出命令码）；
* 提示符 / 连续空读**只能**停没有结束帧的捕获，且一律记未确认（不是完成）；
* 到点仍没结束 ＝ 未确认（绝不假装成功）；
* 载体**绝不自造**目标侧帧；没有 session id / 行太长 ＝ 具名拒绝。
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from runtime import channels, msfservice
from tests import support


def test_pending_recovery_requires_its_own_matching_completion(tmp_path):
    """A completed attempt can recover its pending marker without borrowing another result."""
    import json
    from hashlib import sha256

    previous = {
        "attempt_id": "a" * 32,
        "session_uuid": "fixture-incarnation",
        "operation": "native",
        "completion": None,
        "payload_sha256": sha256(b"sysinfo").hexdigest(),
        "at": 1.0,
    }
    settled = dict(
        previous,
        read_stop="quiet",
        command_rc=0,
        capture_sha256=sha256(b"Computer: fixture\n").hexdigest(),
    )
    observed = {"uuid": previous["session_uuid"]}
    pending = tmp_path / "unsettled.json"
    terminal = tmp_path / (previous["attempt_id"] + ".json")
    pending.write_text(json.dumps(previous), encoding="utf-8")

    other = tmp_path / ("b" * 32 + ".json")
    other.write_text(
        json.dumps(dict(settled, attempt_id="b" * 32)), encoding="utf-8")
    assert channels._reconcile_settled_attempt(pending, previous, observed) is False
    assert pending.exists() and other.exists()

    for changes in (
        {"attempt_id": "b" * 32},
        {"session_uuid": "other-incarnation"},
        {"operation": "shell"},
        {"completion": {"marker": "different"}},
        {"payload_sha256": sha256(b"getuid").hexdigest()},
        {"at": 2.0},
        {"read_stop": "transport_error"},
        {"command_rc": False},
        {"capture_sha256": sha256(b"").hexdigest()},
    ):
        terminal.write_text(json.dumps(dict(settled, **changes)), encoding="utf-8")
        assert channels._reconcile_settled_attempt(pending, previous, observed) is False
        assert pending.exists()

    terminal.write_text(json.dumps(settled), encoding="utf-8")
    assert channels._reconcile_settled_attempt(
        pending, previous, {"uuid": "replacement-incarnation"}) is False
    assert pending.exists()

    assert channels._reconcile_settled_attempt(pending, previous, observed) is True
    assert not pending.exists()
    assert json.loads(terminal.read_text(encoding="utf-8")) == settled
    assert other.exists()


def test_shell_readiness_is_explicit_and_never_opens_a_shell(monkeypatch, tmp_path):
    """An unavailable shell is refused before sending instead of being implicitly created."""
    console = support.wire_console(monkeypatch, tmp_path=tmp_path, session_type="meterpreter")
    binding = dict(support.session_binding(session_type="meterpreter"), shell_ready=False)
    with pytest.raises(ValueError, match="CHANNEL_SHELL_NOT_READY"):
        channels.console_call(binding, support.bound_action(), 3.0)
    assert console.writes == [] and console.singles == []
    assert console.deadlines == []


def test_the_carrier_preserves_the_bound_text_and_remote_exit_frame(monkeypatch, tmp_path):
    """A complete ordered remote frame ends capture without rewriting the caller's text."""
    text = "already bound: spaces  and quotes 'x'\n"
    console = support.wire_console(monkeypatch, tmp_path=tmp_path,
        when_written=[(text, "agvteststart\r\nanswer\r\nagvtestend 17\r\n")])
    outcome = channels.console_call(support.session_binding(), support.bound_action(text), 3.0)
    assert console.writes == [text]
    assert outcome.read_stop == "end_marker" and outcome.returncode == 0
    assert "agvtestend 17\r\n" in outcome.stdout
    assert console.deadlines and set(console.deadlines) == {3.0}


def test_a_prompt_and_silence_remain_unconfirmed(monkeypatch, tmp_path):
    """Unframed output remains unconfirmed even when it resembles a returning prompt."""
    console = support.wire_console(monkeypatch, tmp_path=tmp_path,
        when_written=[("request", "root@lab:~# \r\n")])
    outcome = channels.console_call(support.session_binding(),
        support.bound_action("request", marker=None), 0.7)
    assert outcome.read_stop == "deadline" and outcome.timed_out
    assert outcome.returncode is None and "root@lab:~#" in outcome.stdout
    assert console.clock.now == pytest.approx(0.7)


def test_native_output_settles_the_call_it_answered(monkeypatch, tmp_path):
    """Native output settles the call: no frame is fabricated, and the session stays usable.

    Measured on the lab (2026-10-08): a console command always ends its read on the deadline,
    and treating that as unresolved blocked every later call on that session.
    """
    console = support.wire_console(monkeypatch, tmp_path=tmp_path, session_type="meterpreter",
        when_run=[("sysinfo", "Computer: test-host\r\n")])
    binding = support.session_binding(session_type="meterpreter")
    action = support.bound_action("sysinfo", operation="native", marker=None)
    outcome = channels.console_call(binding, action, 0.7)
    assert console.singles == ["sysinfo"] and console.writes == []
    assert outcome.returncode is None and outcome.read_stop == "deadline"
    assert "Computer: test-host" in outcome.stdout and "agvtest" not in outcome.stdout
    assert list((tmp_path / "session-locks").rglob("unsettled.json")) == []
    token = channels.begin_use(binding)
    channels.end_use(token)


def test_a_native_call_that_answered_nothing_stays_unsettled(monkeypatch, tmp_path):
    """Silence is not an answer; nothing may be treated as settled without one."""
    console = support.wire_console(monkeypatch, tmp_path=tmp_path, session_type="meterpreter",
        when_run=[("sysinfo", "")])
    binding = support.session_binding(session_type="meterpreter")
    channels.console_call(binding, support.bound_action("sysinfo", operation="native",
                                                        marker=None), 0.7)
    assert list((tmp_path / "session-locks").rglob("unsettled.json"))


@pytest.mark.parametrize("kind", ["", "unknown", "undeclared-session-type"])
def test_unknown_session_types_are_refused_without_rpc(monkeypatch, tmp_path, kind):
    """Unknown declared types still refuse before RPC without choosing a default transport."""
    console = support.wire_console(monkeypatch, tmp_path=tmp_path)
    with pytest.raises(ValueError, match="CHANNEL_SESSION_TYPE_UNKNOWN"):
        channels.console_call(support.session_binding(session_type=kind), support.bound_action(), 1.0)
    assert console.deadlines == []


def test_an_authoritative_type_change_refuses_before_send(monkeypatch, tmp_path):
    """A stale binding does not send through the replacement session type."""
    console = support.wire_console(monkeypatch, tmp_path=tmp_path, session_type="meterpreter")
    binding = support.session_binding()
    with pytest.raises(ValueError, match="CHANNEL_SESSION_TYPE_CHANGED"):
        channels.console_call(binding, support.bound_action(), 1.0)
    assert console.writes == [] and console.singles == []
    token = channels.begin_use(binding)
    channels.end_use(token)


def test_an_authoritative_incarnation_change_refuses_before_send(monkeypatch, tmp_path):
    """A reused session number cannot authorize an action bound to a different UUID."""
    console = support.wire_console(monkeypatch, tmp_path=tmp_path)
    monkeypatch.setattr(msfservice, "session_shape",
        lambda client, sid, *, deadline: {"sid": sid, "type": "shell", "uuid": "new"})
    with pytest.raises(ValueError, match="CHANNEL_SESSION_CHANGED"):
        channels.console_call(dict(support.session_binding(), uuid="old"), support.bound_action(), 1.0)
    assert console.writes == []


def test_capacity_is_a_declared_byte_limit_not_an_upload_hint(monkeypatch, tmp_path):
    """UTF-8 byte overflow is refused without truncation, upload, or command replacement."""
    console = support.wire_console(monkeypatch, tmp_path=tmp_path)
    binding = support.session_binding(capacity=3)
    with pytest.raises(ValueError, match="CHANNEL_CAPACITY_EXCEEDED"):
        channels.console_call(binding, support.bound_action("\u00e9\u00e9"), 1.0)
    with pytest.raises(ValueError, match="CHANNEL_CAPACITY_UNDECLARED"):
        channels.console_call(dict(binding, capacity={"max_bytes": 100, "source": ""}),
                              support.bound_action("x"), 1.0)
    assert console.writes == [] and console.deadlines == []


def test_transport_exceptions_release_ownership_but_keep_the_pending_call(monkeypatch, tmp_path):
    """A failed write releases its OS lock; the next call archives that intent, never replays it."""
    import json

    support.wire_console(monkeypatch, tmp_path=tmp_path)
    binding = support.session_binding()

    def fail(client, sid, text, *, deadline):
        raise msfservice.MsfUnreachable("disconnected")

    monkeypatch.setattr(msfservice, "shell_write", fail)
    outcome = channels.console_call(binding, support.bound_action(), 1.0)
    assert outcome.read_stop == "transport_error" and outcome.returncode is None
    token = channels.begin_use(binding)
    try:
        directory = token.session_dir
        pending = directory / "unsettled.json"
        assert pending.is_file()
        previous = json.loads(pending.read_text(encoding="utf-8"))
    finally:
        channels.end_use(token)

    #: The old dispatch is neither replayed nor confirmed: it becomes an archive the new
    #: attempt names, so the audited record still says "output unknown".
    channels.console_call(binding, support.bound_action(), 1.0)

    archives = list(directory.glob("unsettled-*.json"))
    assert len(archives) == 1
    archived = json.loads(archives[0].read_text(encoding="utf-8"))
    assert archived["attempt_id"] == previous["attempt_id"]
    assert archived["archive"]["state"] == "unresolved"
    assert archived["archive"]["capture_sha256"] is None
    assert not (directory / (previous["attempt_id"] + ".json")).exists()

    token = channels.begin_use(binding)
    try:
        replacement = json.loads(pending.read_text(encoding="utf-8"))
    finally:
        channels.end_use(token)
    assert replacement["attempt_id"] != previous["attempt_id"]
    assert replacement["previous_unresolved"] == {
        "attempt_id": previous["attempt_id"], "archive": archives[0].name}


def test_endpoint_changes_are_refused_before_dispatch(monkeypatch, tmp_path):
    """A binding cannot silently follow changed console credentials to another endpoint."""
    console = support.wire_console(monkeypatch, tmp_path=tmp_path)
    monkeypatch.setenv("AGV_MSF_RPC", "msf:pw@other.invalid:55553")
    with pytest.raises(ValueError, match="CHANNEL_ENDPOINT_CHANGED"):
        channels.console_call(support.session_binding(), support.bound_action(), 1.0)
    assert console.deadlines == []


@pytest.mark.parametrize("timeout", [0, -1, True, float("inf"), float("nan")])
def test_invalid_deadlines_are_refused_without_dispatch(monkeypatch, tmp_path, timeout):
    """No invalid timeout can turn into an implicit fixed execution budget."""
    console = support.wire_console(monkeypatch, tmp_path=tmp_path)
    with pytest.raises(ValueError, match="CHANNEL_TIMEOUT_INVALID"):
        channels.console_call(support.session_binding(), support.bound_action(), timeout)
    assert console.deadlines == []


def test_a_new_authoritative_incarnation_preserves_the_previous_pending_intent(monkeypatch, tmp_path):
    """A new observed UUID may use the same session number without erasing the old pending intent."""
    console = support.wire_console(monkeypatch, tmp_path=tmp_path)
    observed = {"uuid": "old"}
    monkeypatch.setattr(msfservice, "session_shape",
        lambda client, sid, *, deadline: {"sid": sid, "type": "shell", **observed})
    old = dict(support.session_binding(), uuid="old")
    outcome = channels.console_call(old, support.bound_action("first"), 0.7)
    assert outcome.read_stop == "deadline"
    observed["uuid"] = "new"
    console.when_written = [("second", "agvteststart\nnew result\nagvtestend 0\n")]
    outcome = channels.console_call(dict(old, uuid="new"), support.bound_action("second"), 0.7)
    assert outcome.read_stop == "end_marker" and console.writes == ["first", "second"]
    token = channels.begin_use(old)
    try:
        archived = list(token.session_dir.glob("unsettled-*.json"))
        assert len(archived) == 1
        import json
        assert json.loads(archived[0].read_text(encoding="utf-8"))["session_uuid"] == "old"
        assert not (token.session_dir / "unsettled.json").exists()
    finally:
        channels.end_use(token)


def test_bound_posix_text_is_not_rewritten(monkeypatch, tmp_path):
    """The caller's explicit POSIX command passes unchanged through the same transport."""
    text = "/bin/sh -c 'id -u'\n"
    console = support.wire_console(monkeypatch, tmp_path=tmp_path,
        when_written=[(text, "agvteststart\n0\nagvtestend 0\n")])
    outcome = channels.console_call(support.session_binding(), support.bound_action(text), 3.0)
    assert console.writes == [text]
    assert outcome.read_stop == "end_marker"
    assert outcome.returncode == 0 and not outcome.timed_out
