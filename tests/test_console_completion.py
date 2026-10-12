"""完成证据与读期限的**离线**回归用例（2026-10-07 桥评审交付）。

钉住四件事：
* 输出在旧的静默窗口之后才到 → 必须等到（不再被 1.8 秒截断）；
* 缓冲区里**上一条命令留下的提示符**不许完成带帧调用；
* 分块到达的结束行必须等**完整**的退出码才成立；
* 到期没结束 → 未确认，且**真实期限**要落进 call.json 与回执（不是 5 秒硬底）。
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from runtime import channels, runner
from runtime.lean import _transport_receipt_fields
from tests import support

MARKER = "agvabc123"
START = MARKER + "start"
END = MARKER + "end"
HANDLE = support.session_binding()
ACTION = support.bound_action("already bound command\n", marker=MARKER)
ARGV = ["/bin/sh", "-c", "already bound command"]


class ScheduledConsole(support.FakeConsole):
    """Expose scripted bytes only at their declared arrival times."""
    def __init__(self, events):
        super().__init__()
        self.events = list(events)

    def pop(self):
        if self.events and self.events[0][0] <= self.clock.now + 1e-9:
            return self.events.pop(0)[1]
        return ""


@pytest.fixture
def console_env(monkeypatch, tmp_path):
    def install(events, *, session_type="shell"):
        console = ScheduledConsole(events)
        support.wire_console(monkeypatch, console, tmp_path=tmp_path, session_type=session_type)
        return console, console.clock
    return install


def execute_console(tmp_path, timeout):
    return runner.execute(
        ARGV, run_dir=tmp_path, skill_id="test.console-completion", call_id="test-call",
        timeout=timeout,
        executor=lambda argv, limit: channels.console_call(HANDLE, ACTION, limit))


def test_output_after_the_old_idle_window_is_read(console_env):
    """A late ordered frame is captured instead of stopping at the former idle window."""
    console, clock = console_env([(0.0, START + "\r\n"), (2.4, "answer\r\n"),
                                  (3.0, END + " 0\r\n")])
    outcome = channels.console_call(HANDLE, ACTION, 5.0)
    assert outcome.read_stop == "end_marker" and not outcome.timed_out
    assert "answer\r\n" in outcome.stdout and END + " 0\r\n" in outcome.stdout
    assert clock.now >= 3.0 - 1e-9 and not console.events
    assert set(console.deadlines) == {5.0}


def test_an_old_prompt_cannot_complete_a_marked_call(console_env):
    """A previous prompt cannot complete the new invocation's explicit frame."""
    console, clock = console_env([(0.0, "C:\\Windows>\r\n"), (0.6, START + "\r\n"),
                                  (2.4, "answer\r\n"), (3.0, END + " 0\r\n")])
    outcome = channels.console_call(HANDLE, ACTION, 5.0)
    assert outcome.read_stop == "end_marker" and "answer\r\n" in outcome.stdout
    assert clock.now >= 3.0 - 1e-9 and not console.events


@pytest.mark.parametrize("head,tail", [(END, " 17\r\n"), (END + " 1", "7\r\n"),
                                      (END + " 17\r", "\n")])
def test_split_end_lines_wait_for_the_complete_exit_code(console_env, head, tail):
    """Split completion lines wait for the complete code and terminating newline."""
    console, clock = console_env([(0.0, START + "\r\n"), (0.3, head), (2.4, tail)])
    outcome = channels.console_call(HANDLE, ACTION, 5.0)
    assert outcome.read_stop == "end_marker"
    assert clock.now >= 2.4 - 1e-9 and not console.events
    assert runner.observe_marker_frame(outcome.stdout, MARKER) == (True, 17)


def test_deadline_reaches_call_json_and_receipt_logic(console_env, tmp_path):
    """A real subsecond deadline remains unconfirmed in capture, persisted call, and receipt."""
    console_env([(0.0, START + "\r\npartial output\r\n")])
    result = execute_console(tmp_path, timeout=0.7)
    assert result.read_stop == "deadline" and result.returncode is None and result.timed_out
    assert result.status == "timeout" and "partial output" in result.stdout
    saved = json.loads((result.call_dir / "call.json").read_text(encoding="utf-8"))
    assert saved["read_stop"] == "deadline" and saved["returncode"] is None
    assert saved["timed_out"] is True and saved["status"] == "timeout"
    assert _transport_receipt_fields(result, MARKER) == {
        "status": "unknown", "command_rc": None, "read_stop": "deadline"}


def test_completed_transport_preserves_a_failing_command_code(console_env, tmp_path):
    """A completed transport does not turn remote exit code 17 into command success."""
    console_env([(0.0, START + "\r\n"), (2.4, "answer\r\n"), (3.0, END + " 17\r\n")])
    result = execute_console(tmp_path, timeout=5.0)
    assert result.status == "executed"
    assert _transport_receipt_fields(result, MARKER) == {
        "status": "completed_transport", "command_rc": 17, "read_stop": "end_marker"}


@pytest.mark.parametrize("read_stop", ["prompt", "idle"])
def test_weak_stops_cannot_be_promoted_by_frame_shaped_text(tmp_path, read_stop):
    """A legacy weak stop stays unconfirmed even when captured text resembles a frame."""
    result = runner.execute(["unused"], run_dir=tmp_path, skill_id="test.console-completion",
        executor=lambda argv, timeout: runner.ExecOutcome(
            0, START + "\n" + END + " 0\n", read_stop=read_stop))
    assert result.status == "unconfirmed" and result.to_json()["read_stop"] == read_stop
    assert _transport_receipt_fields(result, MARKER) == {
        "status": "unknown", "command_rc": None, "read_stop": read_stop}


def test_meterpreter_output_has_no_fabricated_completion(console_env):
    """Native output has no synthesized completion and cannot be promoted by silence."""
    console, _ = console_env([(0.0, "Computer: test-host\r\n")], session_type="meterpreter")
    outcome = channels.console_call(support.session_binding(session_type="meterpreter"),
        support.bound_action("sysinfo", operation="native", marker=None), 0.7)
    assert console.singles == ["sysinfo"]
    assert START not in outcome.stdout and END not in outcome.stdout
    assert outcome.read_stop == "deadline" and outcome.returncode is None
    assert _transport_receipt_fields(outcome, MARKER)["status"] == "unknown"


def test_a_late_frame_is_retained_without_claiming_timely_completion(monkeypatch):
    """Bytes returned after the deadline remain evidence but do not establish in-budget completion."""
    clock = support.FakeClock()
    monkeypatch.setattr(channels, "time", clock)
    def late(client, sid, *, deadline):
        clock.now = deadline + 0.1
        return START + "\n" + END + " 0\n"
    seen, stopped = channels._read_until("1", object(), completion={"marker": MARKER},
                                        deadline=0.7, reader=late)
    assert stopped == "deadline" and END + " 0\n" in seen


@pytest.mark.parametrize("text,expected", [
    (START + "\n" + END + " 17\n", (True, 17)),
    (START + "\n" + END + "\n", (True, None)),
    (START + "\n" + END + " 1", (False, None)),
    (START + "\n" + END + " 17\r", (False, None)),
    (START + "\n" + END + " 0 junk\n", (False, None)),
    (END + " 0\n" + START + "\n", (False, None)),
    (START + "\nagvother123end 0\n", (False, None)),
    ("echo " + START + "\necho " + END + " 0\n", (False, None)),
])
def test_marker_parser_requires_an_ordered_complete_frame(text, expected):
    """Only ordered complete frame lines satisfy the shared completion parser."""
    assert runner.observe_marker_frame(text, MARKER) == expected
