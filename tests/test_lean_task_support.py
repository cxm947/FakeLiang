"""Lean HTTP and standalone dispatch run offline through the actual client bytes."""
import base64
from contextlib import redirect_stdout
from email.message import Message
import hashlib
import http.client
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from runtime import lean_http
from runtime.runner import ExecOutcome, observe_marker_frame
from scripts import run_lean_task as cli


#: 一个端点就是 host:port over tcp（爷爷 2026-10-04：http 也是 tcp，图处理时已折成 tcp）。
SCOPE = {"host": "192.0.2.54", "port": 8080, "protocol": "tcp", "vantage": "base",
         "resources": "whole_endpoint"}
REQUEST = {"tool": "http", "method": "GET", "path": "/"}


def native_client(monkeypatch, *, body=b"Quartz Portal", content_type="text/html; charset=utf-8", status=200, extra_headers=()):
    """Execute the production -c bytes with a scripted socket; never create a network client."""
    calls = []
    class Connection:
        def __init__(self, host, port, timeout):
            calls.append(("connect_to", host, port, timeout))
            self.sock = SimpleNamespace(getpeername=lambda: ("192.0.2.54", 8080))
        def connect(self):
            calls.append(("connect",))
        def request(self, method, path, body=None, headers=None):
            calls.append(("request", method, path, body, headers))
        def getresponse(self):
            headers = Message()
            if content_type is not None:
                headers["Content-Type"] = content_type
            for name, value in extra_headers:
                headers[name] = value
            if status == 302:
                headers["Location"] = "http://192.0.2.99/elsewhere"
            def read(size):
                calls.append(("read", size))
                return body[:size]
            return SimpleNamespace(headers=headers, read=read, status=status, reason="fixture",
                                   getheaders=lambda: list(headers.items()))
        def close(self):
            calls.append(("close",))
    monkeypatch.setattr(http.client, "HTTPConnection", Connection)
    def execute(argv, timeout):
        assert argv[1:3] == ["-c", lean_http.CLIENT_SOURCE]
        output = io.StringIO()
        with monkeypatch.context() as patch, redirect_stdout(output):
            patch.setattr("sys.argv", ["-c", argv[3]])
            exec(compile(argv[2], "<lean-http-client>", "exec"), {"__name__": "__main__"})
        return ExecOutcome(0, output.getvalue(), "")
    return execute, calls


def collected(executor, request=None, scope=None):
    argv = lean_http.prepare(request or REQUEST, scope or SCOPE, "probe123", "/custom/python3")
    outcome = executor(argv, 1)
    lines = outcome.stdout.splitlines()
    assert lines[0] == "probe123start" and lines[-1] == "probe123end 0"
    return json.loads(lines[1])


def card(runs_at="base"):
    return {"id": "method.fixture", "digest": "fixture-digest", "name": "method-fixture", "kind": "method",
            "runs_at": runs_at, "tools": ["http"], "delivers": ["evidence"], "body": "Keep all knowledge.",
            "inputs": {"target_url": {"from": "graph"}, "command": {"from": "model"}}}


def task():
    target = "http://%s:%d" % (SCOPE["host"], SCOPE["port"])
    return {"node_id": "generic-node", "goal": "Observe the page", "inputs": {"target_url": target},
            "scope": dict(SCOPE)}


def cli_args(tmp_path, supplied_task, actions):
    return ["--card", "method.fixture", "--task", json.dumps(supplied_task), "--run-dir", str(tmp_path),
            "--actions", json.dumps(actions)]



CARD_FOR_CORRECTION = {"id": "method.fixture", "kind": "method", "runs_at": "base", "inputs": {},
                       "tools": ["http"], "body": "Observe the endpoint.", "digest": "fixture-card-v1"}
TASK_FOR_CORRECTION = {"node_id": "fixture-node", "goal": "Observe", "inputs": {}, "scope": SCOPE}


def _explicit_console_binding(platform, session_type="meterpreter"):
    return {"channel_id": "ch-1", "kind": "console_session", "session_id": "17",
            "endpoint": {"host": "127.0.0.1", "port": 55553, "ssl": False},
            "session_type": session_type, "platform": platform, "shell_ready": True,
            "capacity": {"max_bytes": 65536, "source": "offline test payload declaration"}}


def _console_result(action):
    completion = action["completion"]
    if completion is None:
        return ExecOutcome(None, "native output\n", read_stop="deadline", timed_out=True)
    marker = completion["marker"]
    return ExecOutcome(0, marker + "start\nok\n" + marker + "end 0\n", read_stop="end_marker")
