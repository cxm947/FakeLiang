"""Offline counterexamples for the runtime's three retained trust boundaries."""
from copy import deepcopy
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import tempfile

import pytest

from runtime import lean, lean_transport
from runtime.runner import ExecOutcome, ownership



CARD = {"id": "recon.fixture", "kind": "recon", "runs_at": "base", "inputs": {},
        "tools": ["http"], "body": "Inspect the native response.", "digest": "fixture-card-v1"}
TASK = {"node_id": "fixture-node", "goal": "Observe this endpoint", "inputs": {"target": "192.0.2.54"}}
SCOPE = {"host": "192.0.2.54", "port": 18080, "protocol": "tcp", "vantage": "base",
         "resources": "whole_endpoint"}
REQUEST = {"tool": "http", "method": "GET", "path": "/"}


class Collector:
    def __init__(self, mode="ok", body="permission denied; root required", label="controller-a"):
        self.mode, self.body, self.label_value, self.calls = mode, body, label, []

    def label(self):
        return self.label_value

    def __call__(self, argv, timeout):
        self.calls.append((list(argv), timeout))
        payload = json.loads(base64.b64decode(argv[-1]))
        if self.mode == "crash":
            raise KeyboardInterrupt("process stopped after dispatch")
        if self.mode == "error":
            raise RuntimeError("transport interrupted after send")
        marker = payload["marker"]
        stdout = marker + "start\n" + self.body + "\n" + marker + "end\n"
        if self.mode == "no_marker":
            stdout = self.body
        return ExecOutcome(1 if self.mode == "nonzero" else 0, stdout, "",
                           timed_out=self.mode == "timeout")


def run_at(path, executor=None, **changes):
    options = {"card": deepcopy(CARD), "task": deepcopy(TASK), "scope": deepcopy(SCOPE),
               "executor": executor or Collector()}
    options.update(changes)
    return lean.LeanRun(path, **options)


def test_scope_is_structural_and_shell_is_not_allowed_by_a_target_substring(tmp_path):
    transport = Collector()
    run = run_at(tmp_path, transport)
    for request in [{"tool": "shell", "command": "echo 192.0.2.54; do_something_else"},
                    dict(REQUEST, path="http://192.0.2.99/"),
                    dict(REQUEST, headers={"Host": "192.0.2.99"}),
                    dict(REQUEST, target="192.0.2.99")]:
        with pytest.raises(ValueError, match="LEAN_(TOOL|HTTP)"):
            run.call(request)
    assert transport.calls == [] and run.history() == []
    with pytest.raises(ValueError, match="LEAN_SCOPE_UNSUPPORTED"):
        run_at(tmp_path / "resource", transport, scope=dict(SCOPE, resources="/allowed-only"))
    assert transport.calls == []


def test_interruption_after_intent_survives_restart_and_new_ids_cannot_bypass_it(tmp_path):
    """Abandon and restart cannot resolve an intent that has no completion receipt."""
    first_transport = Collector("crash")
    first = run_at(tmp_path, first_transport)
    with pytest.raises(KeyboardInterrupt):
        first.call(REQUEST)
    original = first.history()[0]
    assert original["kind"] == "intent" and len(first_transport.calls) == 1
    first.record_abandon(original["call_id"], "local waiting stopped")
    second_transport = Collector()
    second = run_at(tmp_path, second_transport)
    for request in [REQUEST, dict(REQUEST, path="/new-request")]:
        with pytest.raises(ValueError, match="LEAN_(CALL_UNRESOLVED|UNRESOLVED_CALL)"):
            second.call(request)
    report = second.conclude("completed", [], "pass")
    assert report["status"] == "uncertain" and report["pending_calls"] == [original["call_id"]]
    assert second_transport.calls == []
    assert first.history()[0] == original


@pytest.mark.parametrize("mode", ["timeout", "error", "no_marker"])
def test_every_unconfirmed_dispatched_request_blocks_later_changes(tmp_path, mode):
    """Unknown receipts block the same request, a new request and explicit retry after abandon."""
    transport = Collector(mode)
    run = run_at(tmp_path, transport)
    receipt = run.call(REQUEST)
    assert receipt["status"] == "unknown"
    run.record_abandon(receipt["call_id"], "local waiting stopped")
    resumed = run_at(tmp_path, transport)
    for request in (REQUEST, dict(REQUEST, path="/another"),
                    dict(REQUEST, retry_of=receipt["call_id"], retry_reason="stopped waiting")):
        with pytest.raises(ValueError, match="LEAN_UNRESOLVED_CALL"):
            resumed.call(request)
    assert len(transport.calls) == 1
    assert not any(row["kind"] == "retry" for row in resumed.history())
    report = resumed.conclude("outcome unknown", [], "uncertain")
    assert report["status"] == "uncertain"
    assert report["pending_calls"] == [receipt["call_id"]]


@pytest.mark.parametrize("receipt_status", [None, "unknown"])
@pytest.mark.parametrize("request_kind", ["same", "different", "retry"])
def test_unresolved_guard_runs_before_any_action_preparation(monkeypatch, receipt_status, request_kind):
    """Even after abandon, no validation, staging, transport or retry event precedes the guard."""
    from contextlib import nullcontext

    call_id = "call-20261008T010203-abcdef-" + "1" * 32
    events = [{"kind": "intent", "call_id": call_id},
              {"kind": "abandon", "call_id": call_id}]
    verified = []
    if receipt_status is not None:
        events.insert(1, {"kind": "receipt", "call_id": call_id,
                          "receipt": {"status": receipt_status}})
    run = lean.LeanRun.__new__(lean.LeanRun)
    run.root = Path("unused")
    run.card = CARD
    run._read = lambda: deepcopy(events)
    run._verify = lambda key, receipt: verified.append(key)
    run._append = lambda *args, **kwargs: pytest.fail("no new event before refusing dispatch")
    monkeypatch.setattr(lean_transport, "ownership", lambda root: nullcontext())
    monkeypatch.setattr(lean.dispatch, "require_declared",
                        lambda *args: pytest.fail("action preparation must not start"))
    request = dict(REQUEST)
    if request_kind == "different":
        request["path"] = "/another"
    elif request_kind == "retry":
        request.update(retry_of=call_id, retry_reason="stopped waiting")
    with pytest.raises(ValueError, match="LEAN_UNRESOLVED_CALL"):
        run.call(request)
    assert verified == ([] if receipt_status is None else [call_id])
    assert len(events) == (2 if receipt_status is None else 3)


def test_a_complete_wrapper_bracket_beats_the_senders_own_exit_code(tmp_path):
    """括号齐了就是运输完成 —— 判据以**目标侧 shell 打的那两行**为准，不是发送端自己的哨兵。

    实测 2026-10-06 walk-69 node 48：命令在目标上跑完了、括号两行都在
    （`agv78c585start` … `agv78c585end`），只是发送端额外挂在长命令行尾巴上的
    `& echo agv-marker-…` 只剩回显、没有输出（cmd 按 `&` 重切长行）→ 旧判据把整条调用记 unknown，
    模型被禁止引用那次**其实完整**的观测，只好换个任务名（agv_exec2）重打一遍。
    爷爷 2026-10-07：观测完整就是完整，不该被一个会被吞掉的标记一票否决。
    """
    transport = Collector("nonzero")          # 发送端 exit=1，但括号两行都在
    run = run_at(tmp_path, transport)
    receipt = run.call(REQUEST)
    assert receipt["status"] == "completed_transport"
    #: 已确认的调用不再挡住后面的动作。
    resumed = run_at(tmp_path, transport)
    resumed.call(dict(REQUEST, path="/another"))
    assert len(transport.calls) == 2


def test_intent_must_persist_before_dispatch_and_unpublished_receipt_cannot_be_adopted(tmp_path, monkeypatch):
    first_transport = Collector()
    first = run_at(tmp_path / "intent", first_transport)
    original_append = first._append

    def cannot_append(kind, **payload):
        if kind == "intent":
            raise OSError("disk unavailable")
        return original_append(kind, **payload)

    monkeypatch.setattr(first, "_append", cannot_append)
    with pytest.raises(OSError):
        first.call(REQUEST)
    assert first_transport.calls == []
    transport = Collector()
    run = run_at(tmp_path / "receipt", transport)
    publish = lean_transport.atomic_write

    def cannot_publish(path, data, **kwargs):
        if Path(path).name == "receipt.json":
            raise OSError("receipt disk failure")
        return publish(path, data, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(lean_transport, "atomic_write", cannot_publish)
        result = run.call(REQUEST)
    assert result["status"] == "unknown" and len(transport.calls) == 1
    resumed = run_at(tmp_path / "receipt", transport)
    with pytest.raises(ValueError, match="LEAN_UNRESOLVED_CALL"):
        resumed.call(dict(REQUEST, path="/next"))
    with pytest.raises(ValueError, match="LEAN_CALL_UNKNOWN"):
        resumed.cite(result["call_id"], "root")


def test_card_task_scope_client_and_actual_executor_are_frozen_across_restarts(tmp_path, monkeypatch):
    run_at(tmp_path)
    changes = [{"card": dict(CARD, body="different knowledge")},
               {"task": dict(TASK, inputs={"target": "192.0.2.99"})},
               {"scope": dict(SCOPE, host="192.0.2.55")},
               {"executor": Collector(label="other-controller")}, {"python": "another-python"}]
    for change in changes:
        with pytest.raises(ValueError, match="LEAN_BINDING_CHANGED"):
            run_at(tmp_path, **change)
    monkeypatch.setattr(lean.lean_http, "CLIENT_SOURCE", lean.lean_http.CLIENT_SOURCE + "\n# changed")
    with pytest.raises(ValueError, match="LEAN_BINDING_CHANGED"):
        run_at(tmp_path)


def test_torn_log_and_concurrent_owner_refuse_without_dispatch(tmp_path):
    transport = Collector()
    run = run_at(tmp_path, transport)
    with ownership(tmp_path):
        with pytest.raises(OSError):
            run.call(REQUEST)
    assert transport.calls == []
    (tmp_path / "events.jsonl").write_bytes(b'{"kind":"intent"')
    with pytest.raises(ValueError, match="LEAN_LOG_INVALID"):
        run.call(REQUEST)
    with pytest.raises(ValueError, match="LEAN_LOG_INVALID"):
        run_at(tmp_path, transport)
    assert transport.calls == []


def test_abrupt_process_exit_after_send_never_replays_on_a_new_process(tmp_path):
    root = Path(__file__).resolve().parents[1]
    script = r'''
import json, os, sys
from pathlib import Path
from tests.test_lean_kernel import run_at, REQUEST
from runtime.runner import ExecOutcome
folder, mode = Path(sys.argv[1]), sys.argv[2]
count = folder / 'transport-count.txt'
def transport(argv, timeout):
    with count.open('a', encoding='utf-8') as stream:
        stream.write('sent\n'); stream.flush(); os.fsync(stream.fileno())
    if mode == 'first':
        os._exit(73)
    return ExecOutcome(0, 'unexpected replay')
run = run_at(folder / 'run', transport)
if mode == 'first':
    run.call(REQUEST)
else:
    refusals = []
    for request in [REQUEST, dict(REQUEST, path='/new-id')]:
        try:
            run.call(request)
        except ValueError as error:
            refusals.append(str(error))
    report = run.conclude('finished', [], 'pass')
    print(json.dumps({'refusals': refusals, 'pending': report['pending_calls'], 'status': report['status']}))
'''
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(root / "src"), str(root)]),
               PYTHONDONTWRITEBYTECODE="1")
    first = subprocess.run([sys.executable, "-B", "-c", script, str(tmp_path), "first"],
                           cwd=root, env=env, capture_output=True, text=True)
    assert first.returncode == 73, first.stderr
    for _ in range(2):
        resumed = subprocess.run([sys.executable, "-B", "-c", script, str(tmp_path), "resume"],
                                 cwd=root, env=env, capture_output=True, text=True, check=True)
        result = json.loads(resumed.stdout)
        assert len(result["refusals"]) == 2 and result["status"] == "uncertain"
        assert len(result["pending"]) == 1
    assert (tmp_path / "transport-count.txt").read_text(encoding="utf-8") == "sent\n"


@pytest.mark.parametrize("runs_at,vantage,label", [
    ("base", "hop-a", "hop-a"), ("position", "hop-a", None),
    ("position", "hop-a", "hop-b"), (None, "base", "controller-a")])
def test_execution_view_requires_a_card_declaration_and_an_actual_position_binding(tmp_path, runs_at, vantage, label):
    calls = []
    def executor(argv, timeout):
        calls.append(argv)
        return ExecOutcome(0)
    if label is not None:
        executor.label = lambda: label
    card = dict(CARD, runs_at=runs_at)
    with pytest.raises(ValueError, match="LEAN_EXECUTION_BINDING_INVALID"):
        run_at(tmp_path, executor, card=card, scope=dict(SCOPE, vantage=vantage))
    assert calls == []


def test_declared_position_accepts_the_actual_bound_executor_label(tmp_path):
    transport = Collector(label="hop-a")
    run = run_at(tmp_path, transport, card=dict(CARD, runs_at="position"), scope=dict(SCOPE, vantage="hop-a"))
    receipt = run.call(REQUEST)
    assert receipt["scope"]["vantage"] == receipt["executor_label"] == "hop-a"




SHELL_SCOPE = {"host": "192.0.2.54", "port": 6379, "protocol": "tcp", "vantage": "base",
               "resources": "whole_endpoint"}


def test_a_named_tool_becomes_one_wrapped_argv_for_the_call():
    """工具类：名字 + 参数数组 → 一条带标记的 argv（参数各自独立，不会被再引号一次）。"""
    from runtime import dispatch

    argv = dispatch.build({"tool": "tool", "name": "nmap",
                           "args": ["-Pn", "-n", "-sT", "-p", "6379", "192.0.2.54"]},
                          marker="agvmarker")
    assert argv[:2] == ["/bin/sh", "-c"]
    assert "agvmarkerstart" in argv[2] and "agvmarkerend" in argv[2]
    assert "nmap" in argv[2] and "192.0.2.54" in argv[2]


@pytest.mark.parametrize("answer", [
    {"tool": "tool", "name": "nc", "args": "192.0.2.99"},          # args 不是列表
    {"tool": "tool", "name": "", "args": []},                       # 没有工具名
    {"tool": "tool", "name": "nmap", "args": ["a" * 5000]},         # 单个参数过长
    {"tool": "tool", "name": "nmap", "args": ["x"] * 65},           # 参数个数过多
    {"tool": "cmd"},                                                # 没有命令文本
])
def test_a_malformed_tool_request_is_refused_by_name(answer):
    """写歪了就具名拒绝（可回喂）——**不再有"扫命令里的地址"那种猜测式拒绝**。"""
    from runtime import dispatch

    with pytest.raises(ValueError) as caught:
        dispatch.build(answer, marker="agvmarker")
    assert str(caught.value).startswith("LEAN_")


def test_a_shell_call_needs_the_card_to_declare_the_tool():
    from runtime.lean import LeanRun
    card = {"id": "x.y", "digest": "d", "runs_at": "base", "tools": ["http"]}
    task = {"node_id": "n", "inputs": {}}
    run = LeanRun(run_dir=Path(tempfile.mkdtemp()), card=card, task=task, scope=SHELL_SCOPE,
                  executor=lambda argv, timeout: ExecOutcome(0, "", ""), timeout=5, secrets=())
    with pytest.raises(ValueError, match="LEAN_TOOL_UNDECLARED"):
        run.call({"tool": "cmd", "cmd": "id"})


def test_a_null_body_means_no_body_and_a_number_is_still_refused():
    """The model writes "body": null for a GET; that is "no body", not an invalid answer - while a
    non-string body stays a refusal."""
    from runtime import lean_http
    scope = {"host": "10.0.0.9", "port": 8080, "protocol": "tcp",
             "resources": "whole_endpoint", "vantage": "base"}
    argv = lean_http.prepare({"tool": "http", "method": "GET", "path": "/", "headers": {},
                              "body": None}, scope, "m1")
    assert isinstance(argv, list) and argv[0] and len(argv) > 2
    try:
        lean_http.prepare({"tool": "http", "method": "POST", "path": "/", "headers": {},
                           "body": 7}, scope, "m1")
    except ValueError as error:
        assert "LEAN_HTTP_BODY_INVALID" in str(error)
    else:
        raise AssertionError("a non-string body must still be refused")


def test_the_end_marker_finds_its_own_line_even_when_the_command_prints_no_final_newline():
    """An ordered end frame stays on its own line and carries the observed command exit code."""
    from runtime.markers import marker_script
    from runtime.runner import observe_marker_frame

    script = marker_script(["/bin/sh", "-c", "printf no-newline-here"], "agvtest")
    assert '"$probe_rc"' in script
    for code in (0, 7, -1):
        capture = "agvteststart\nno-newline-here\nagvtestend %d\n" % code
        assert observe_marker_frame(capture, "agvtest") == (True, code)
    unmarked = "agvteststart\nno-newline-hereagvtestend 0\n"
    assert observe_marker_frame(unmarked, "agvtest") == (False, None)
    assert observe_marker_frame("agvteststart\nagvtestend\n", "agvtest") == (True, None)


def test_trusted_argv_is_rendered_without_unwrapping_shell_arguments():
    """Trusted undo argv keeps every token, including an explicitly supplied shell and its flags."""
    import shlex
    from runtime import dispatch

    argv = ["/bin/sh", "-c", "printf '%s' 'a b'"]
    request = dispatch.command_request(argv, platform="linux")
    assert request["tool"] == "cmd"
    assert shlex.split(request["cmd"]) == argv
    with pytest.raises(ValueError, match="LEAN_POSITION_PLATFORM_MISSING"):
        dispatch.command_request(argv, platform="")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows command interpreter required")
def test_windows_argv_preserves_argument_boundaries_through_cmd():
    """Windows serialization preserves spaces, quotes, empty arguments and shell metacharacters."""
    import ctypes
    from runtime import dispatch

    directory = ctypes.create_unicode_buffer(32768)
    assert ctypes.windll.kernel32.GetSystemDirectoryW(directory, len(directory))
    command_interpreter = str(Path(directory.value) / "cmd.exe")
    arguments = ["hello world", 'quote"here', "trail\\", "", "a&b", "a|b", "a^b", "<literal>", "a(b)"]
    probe = "import json,sys;print(json.dumps(sys.argv[1:]))"
    argv = [sys.executable, "-B", "-c", probe, *arguments]
    request = dispatch.command_request(argv, platform="windows")
    action = dispatch.bind_console(request, {"session_type": "meterpreter", "platform": "windows"},
                                   marker="agvargv")
    assert request["cmd"] in action["text"]
    invocation = '"' + command_interpreter + '" /d /s /v:off /c "' + request["cmd"] + '"'
    result = subprocess.run(invocation, capture_output=True, text=True, encoding="utf-8",
                            timeout=5, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == arguments


@pytest.mark.parametrize("argument", ["%VALUE%", "!VALUE!", "line\nnext", "line\rnext"])
def test_windows_argv_refuses_environment_expansion_and_multiline_arguments(argument):
    """Unsupported argv expansion is rejected before sending instead of silently changing its value."""
    from runtime import dispatch

    with pytest.raises(ValueError, match="WINDOWS_ARGV_UNREPRESENTABLE"):
        dispatch.bind_console({"tool": "tool", "name": "program", "args": [argument]},
                              {"session_type": "meterpreter", "platform": "windows"}, marker="m")
    raw = "echo " + argument
    action = dispatch.bind_console({"tool": "cmd", "cmd": raw},
                                   {"session_type": "meterpreter", "platform": "windows"}, marker="m")
    assert raw in action["text"]


def test_a_rerun_has_to_be_asked_for_explicitly(tmp_path):
    """The engine does not infer that the world moved: the model names the call to repeat.

    External review 2026-10-08: a non-zero exit code does not mean "no side effect", and an
    unrelated call succeeding does not mean the relevant precondition changed -- so a repeat is a
    deliberate, recorded decision (`retry_of` + `retry_reason`), never an inference.
    """
    import json

    run = run_at(tmp_path, Collector(), task=dict(TASK, inputs={"secrets": []}))
    one = run.call(dict(REQUEST, method="POST", body="agv"))
    #: ??? -> ???**?????**?? call_id??????"???"????
    again = run.call(dict(REQUEST, method="POST", body="agv"))
    assert again["call_id"] == one["call_id"]
    events = [json.loads(line)
              for line in (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
              if line.strip()]
    refusals = [event for event in events if event.get("kind") == "refusal"]
    assert refusals and refusals[-1]["refusal"]["reason_code"] == "LEAN_CALL_ALREADY_RAN"
    #: ??????????-> ?????????????????
    two = run.call(dict(REQUEST, method="POST", body="agv", retry_of=one["call_id"],
                        retry_reason="the file it reads now exists"))
    assert two["call_id"] != one["call_id"]
    events = [json.loads(line)
              for line in (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
              if line.strip()]
    retries = [event for event in events if event.get("kind") == "retry"]
    assert retries and retries[0]["call_id"] == one["call_id"]
    assert retries[0]["reason"] == "the file it reads now exists"
