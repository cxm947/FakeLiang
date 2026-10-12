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

from tests.test_lean_task_support import (
    SCOPE, REQUEST, native_client, collected, card, task, cli_args,
    CARD_FOR_CORRECTION, TASK_FOR_CORRECTION,
    _explicit_console_binding, _console_result,
)
from agents.executor import input as task_input


def test_the_receipt_carries_the_body_verbatim_not_only_escaped(monkeypatch):
    """回执里除了机械报告那行 JSON，还要有**原文块** —— 账本存的就是原文，所见即所存。

    爷爷 2026-10-07："卡里面去掉所有转义可以吗？为什么要加 / 、\\ 两种转义符呢"
    —— 说得对：与其在核对那一层写"转义不算内容"的补丁，不如让记账格式本身不再多转义一层。
    报告那行仍是 JSON（机器要读状态 / 头 / 摘要），响应体再单独原样走一趟。
    """
    body = b'{"status":1,"msg":"","url":"general\\/index.php?isIE=0"}'
    executor, _calls = native_client(monkeypatch, body=body, content_type="application/json")
    argv = lean_http.prepare(REQUEST, SCOPE, "probe123", "/custom/python3")
    outcome = executor(argv, 1)
    text = outcome.stdout
    assert "<<<agv-body>>>" in text and "<<<agv-body-end>>>" in text
    raw = text.split("<<<agv-body>>>", 1)[1].split("<<<agv-body-end>>>", 1)[0].strip()
    assert raw == body.decode("utf-8"), "原文块里必须是原文（一个字符都不转义）"
    assert text.splitlines()[-1] == "probe123end 0", "标记行仍然是最后一行"


@pytest.mark.parametrize("body,content_type,expected_status,expected", [
    ("中文页面".encode("gbk"), "text/html; charset=gbk", "decoded", "中文页面"),
    ("中文页面".encode("utf-8"), "text/html; charset=utf-8", "decoded", "中文页面"),
    (b"page", None, "decoded", "page"),
    (b"page", "text/html; charset=not-a-codec", "unknown_charset", ""),
    ("中文页面".encode("gbk"), "text/html; charset=utf-8", "decode_failed", ""),
])
def test_native_http_charset_audit_is_strict_and_has_no_encoded_secret_channel(
        monkeypatch, body, content_type, expected_status, expected):
    executor, _ = native_client(monkeypatch, body=body, content_type=content_type)
    result = collected(executor)
    assert result["body"] == expected
    assert result["body_decoding"]["status"] == expected_status
    assert result["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert "body_base64" not in result
    assert result["peer"] == {"host": "192.0.2.54", "port": 8080}


def test_native_http_ignores_proxy_environment_and_does_not_follow_redirect(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9999")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9999")
    executor, calls = native_client(monkeypatch, status=302)
    result = collected(executor, dict(REQUEST, method="POST", path="/check?a=1", body="text"))
    assert result["status"] == 302
    assert [row for row in calls if row[0] == "connect_to"] == [("connect_to", "192.0.2.54", 8080, 10)]
    assert [row for row in calls if row[0] == "request"] == [("request", "POST", "/check?a=1", b"text", {})]


def test_native_http_reports_the_explicit_body_ceiling(monkeypatch):
    executor, calls = native_client(monkeypatch, body=b"x" * (64 * 1024 + 20))
    result = collected(executor)
    assert result["truncation"] == {"truncated": True, "body_limit": 65536, "body_bytes": 65536}
    assert len(result["body"]) == 65536
    assert ("read", 65537) in calls


@pytest.mark.parametrize("proposed,reason", [
    (dict(REQUEST, origin="http://192.0.2.99"), "REQUEST_INVALID"),
    (dict(REQUEST, target_host="192.0.2.99"), "REQUEST_INVALID"),
    (dict(REQUEST, path="http://192.0.2.99/"), "PATH_INVALID"),
    (dict(REQUEST, path="//192.0.2.99/"), "PATH_INVALID"),
    (dict(REQUEST, path="/\\\\192.0.2.99/"), "PATH_INVALID"),
    (dict(REQUEST, path="/\r\nHost: other"), "PATH_INVALID"),
    (dict(REQUEST, method="CONNECT"), "METHOD_UNSUPPORTED"),
    (dict(REQUEST, headers={"hOsT": "192.0.2.99"}), "HEADER_FORBIDDEN"),
    (dict(REQUEST, headers={"Content-Length": "1"}), "HEADER_FORBIDDEN"),
    (dict(REQUEST, headers={"Transfer-Encoding": "chunked"}), "HEADER_FORBIDDEN"),
    (dict(REQUEST, headers={"X-Test": "ok\r\nHost: other"}), "HEADERS_INVALID"),
    (dict(REQUEST, headers={"X-Test": "first", "x-test": "second"}), "HEADERS_INVALID"),
    (dict(REQUEST, body={"field": "not a string"}), "BODY_INVALID"),
])
def test_native_http_rejects_model_endpoint_or_framing_overrides_before_dispatch(proposed, reason):
    with pytest.raises(ValueError, match="LEAN_HTTP_" + reason):
        lean_http.prepare(proposed, SCOPE, "probe123", "python3")


@pytest.mark.parametrize("host", ["domain.test", "192.0.2.54:8080", "192.0.2.54/24", "", None])
def test_the_endpoint_host_is_one_literal_ip(host):
    with pytest.raises(ValueError, match="LEAN_ENDPOINT_HOST_INVALID"):
        lean_http.prepare(REQUEST, dict(SCOPE, host=host), "probe123", "python3")


@pytest.mark.parametrize("port", [0, 70000, "8080", True])
def test_the_endpoint_port_is_one_bounded_integer(port):
    with pytest.raises(ValueError, match="LEAN_ENDPOINT_PORT_INVALID"):
        lean_http.prepare(REQUEST, dict(SCOPE, port=port), "probe123", "python3")


@pytest.mark.parametrize("protocol", ["http", "https", "udp", "", None])
def test_only_tcp_is_a_transport_here(protocol):
    """图里的服务写法在读到图的时候就折成 tcp 了；这里不该再出现第二种写法。"""
    with pytest.raises(ValueError, match="LEAN_ENDPOINT_PROTOCOL_UNSUPPORTED"):
        lean_http.prepare(REQUEST, dict(SCOPE, protocol=protocol), "probe123", "python3")


def test_fine_resource_scope_is_named_unsupported_and_the_endpoint_is_carried_through():
    with pytest.raises(ValueError, match="LEAN_ENDPOINT_RESOURCE_SCOPE_UNSUPPORTED"):
        lean_http.prepare(REQUEST, dict(SCOPE, resources=["/allowed"]), "probe123", "python3")
    argv = lean_http.prepare(REQUEST, SCOPE, "probe123", "python3")
    params = json.loads(base64.b64decode(argv[-1]))
    assert params["host"] == "192.0.2.54" and params["port"] == 8080


def test_real_cli_records_http_then_checks_citation_without_registering_graph_success(tmp_path, monkeypatch, capsys):
    executor, calls = native_client(monkeypatch)
    monkeypatch.setattr(cli, "load_card", lambda *_: card())
    monkeypatch.setattr(task_input, "subprocess_executor", executor)
    assert cli.main(cli_args(tmp_path, task(), [{"kind": "call", "request": REQUEST}])) == 2
    first = json.loads(capsys.readouterr().out)
    receipt = first["last_receipt"]
    assert receipt["status"] == "completed_transport"
    count = len(calls)
    finish = {"kind": "finish", "claim": "The page contains this name", "claimed_verdict": "pass",
              "citations": [{"call_id": receipt["call_id"], "quote": "Quartz Portal", "require_marker": True}]}
    assert cli.main(cli_args(tmp_path, task(), [finish])) == 0
    conclusion = json.loads(capsys.readouterr().out)
    assert conclusion["status"] == "model_reported"
    assert len(calls) == count, "resume citation checking cannot replay the HTTP request"
    assert not any(key in conclusion for key in ("graph_pass", "registered_session", "registered_fact"))


@pytest.mark.parametrize("change", [{"target_url": "http://192.0.2.99:8080"}, {"target_host": "192.0.2.99"},
                                    {"port": 8081}, {"protocol": "udp"}])
def test_cli_refuses_target_binding_conflicts_without_dispatch(tmp_path, monkeypatch, capsys, change):
    calls = []
    monkeypatch.setattr(cli, "load_card", lambda *_: card())
    monkeypatch.setattr(task_input, "subprocess_executor", lambda *args: calls.append(args))
    supplied = task()
    supplied["inputs"].update(change)
    assert cli.main(cli_args(tmp_path, supplied, [{"kind": "call", "request": REQUEST}])) == 2
    assert "LEAN_TASK_TARGET_CONFLICT" in capsys.readouterr().out
    assert calls == [] and not (tmp_path / "events.jsonl").exists()


def test_cli_does_not_require_model_owned_input_before_model_action(tmp_path, monkeypatch, capsys):
    executor, _ = native_client(monkeypatch)
    monkeypatch.setattr(cli, "load_card", lambda *_: card())
    monkeypatch.setattr(task_input, "subprocess_executor", executor)
    assert "command" not in task()["inputs"]
    assert cli.main(cli_args(tmp_path, task(), [{"kind": "call", "request": REQUEST}])) == 2
    assert json.loads(capsys.readouterr().out)["last_receipt"]["status"] == "completed_transport"


def test_cli_binds_the_one_transport_and_requires_a_finer_vantage_to_match_it():
    params = SimpleNamespace(chain=None, remote="kali@192.0.2.2", password="pw", key=None)
    selected, owner = cli.select_executor(params, card("base"), dict(SCOPE))
    assert callable(selected) and owner is not None and selected is owner
    assert owner.label() == "kali@192.0.2.2"
    _same, named = cli.select_executor(params, card("position"), dict(SCOPE, vantage="kali@192.0.2.2"))
    assert named is not None
    owner.close()
    named.close()
    local, none = cli.select_executor(
        SimpleNamespace(chain=None, remote=None, password=None, key=None), card("base"), dict(SCOPE))
    assert local is cli.subprocess_executor and none is None
    with pytest.raises(ValueError, match="LEAN_VANTAGE_BINDING_UNAVAILABLE"):
        cli.select_executor(SimpleNamespace(chain=None, remote=None, password=None, key=None),
                            card("base"), dict(SCOPE, vantage="relay-user@192.0.2.7"))
    with pytest.raises(ValueError, match="LEAN_VANTAGE_BINDING_UNAVAILABLE"):
        cli.select_executor(params, card("base"), dict(SCOPE, vantage="relay-user@192.0.2.7"))
    with pytest.raises(ValueError, match="LEAN_CHAIN_UNSUPPORTED"):
        cli.select_executor(SimpleNamespace(chain="chain.json", remote=None, password=None, key=None),
                            card("base"), dict(SCOPE))




def test_native_http_keeps_sensitive_response_header_names_without_values(monkeypatch):
    executor, _ = native_client(monkeypatch, extra_headers=[("Set-Cookie", "session=private-new-cookie"),
        ("Authorization", "Bearer private-new-token"), ("X-Product", "Quartz Portal")])
    result = collected(executor)
    assert ["Set-Cookie", "<redacted>"] in result["headers"]
    assert ["Authorization", "<redacted>"] in result["headers"]
    assert ["X-Product", "Quartz Portal"] in result["headers"]
    assert "private-new" not in json.dumps(result)


def test_real_cli_runs_a_base_card_through_one_execution_point(tmp_path, monkeypatch, capsys):
    native, _ = native_client(monkeypatch)
    sent = []
    def base(argv, timeout):
        sent.append(list(argv))
        return native(argv, timeout)
    base.label = lambda: "control-user@192.0.2.2"
    monkeypatch.setattr(cli, "load_card", lambda *_: card("base"))
    monkeypatch.setattr(task_input, "subprocess_executor", base)
    assert cli.main(cli_args(tmp_path, task(), [{"kind": "call", "request": REQUEST}])) == 2
    result = json.loads(capsys.readouterr().out)
    assert result.get("last_receipt", {}).get("status") == "completed_transport", result
    assert len(sent) == 1


def test_cli_refuses_a_finer_vantage_no_transport_proves(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_card", lambda *_: card("position"))
    monkeypatch.setattr(task_input, "subprocess_executor",
                        lambda *args: pytest.fail("an unproved vantage must not dispatch"))
    supplied = task()
    supplied["scope"]["vantage"] = "relay-user@192.0.2.7"
    assert cli.main(cli_args(tmp_path, supplied, [{"kind": "call", "request": REQUEST}])) == 2
    assert "LEAN_VANTAGE_BINDING_UNAVAILABLE" in capsys.readouterr().out




def test_cli_model_uses_lean_prompt_history_and_existing_model_log(tmp_path, monkeypatch, capsys):
    from agents._model.contract import ModelReply

    native, _ = native_client(monkeypatch)
    monkeypatch.setattr(task_input, "subprocess_executor", native)
    monkeypatch.setattr(cli, "load_card", lambda *_: card())
    prompts = []
    class Client:
        def available(self):
            return True
        def complete(self, **kwargs):
            prompts.append(kwargs)
            # A provider hiccup (empty answer) must not end a step: measured twice on 2026-10-05.
            assert kwargs["task"] == "lean_action" and kwargs["retries"] == 4
            state = json.loads(kwargs["user"])
            assert state["card"]["body"] == "Keep all knowledge."
            assert all(event["kind"] != "decision" for event in state["history"])
            receipts = [event["receipt"] for event in state["history"] if event["kind"] == "receipt"]
            action = ({"kind": "finish", "claim": "A page answered", "claimed_verdict": "pass",
                       "citations": [{"call_id": receipts[-1]["call_id"], "quote": "Quartz Portal"}]}
                      if len(receipts) == 2 else {"kind": "call", "request": dict(REQUEST, path="/page-" + str(len(receipts)))})
            return ModelReply(ok=True, text=json.dumps(action), payload=action, model="offline")
    monkeypatch.setattr(cli, "client_from_env", lambda **_: Client())
    args = ["--card", "method.fixture", "--task", json.dumps(task()), "--run-dir", str(tmp_path), "--model", "offline"]
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "model_reported"
    assert len(prompts) == 3 and all("propose_action" not in p["system"] for p in prompts)
    assert len((tmp_path / "model.jsonl").read_text(encoding="utf-8").splitlines()) == 3
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len([event for event in events if event["kind"] == "decision"]) == 3



@pytest.mark.parametrize("skill_id", ["pre.service_version", "exploit.tongda_oa_include_rce"])
def test_real_pilot_card_entire_knowledge_reaches_model_and_receipt_can_be_quoted(
        tmp_path, monkeypatch, capsys, skill_id):
    from agents._model.contract import ModelReply
    from skills.lean import load_card

    actual = load_card(skill_id, cli.ROOT)
    native, calls = native_client(monkeypatch)
    monkeypatch.setattr(task_input, "subprocess_executor", native)
    supplied = task()
    supplied["inputs"].update(target_host="192.0.2.54", port=8080, expected_service="quartz_portal")
    seen = []
    class Client:
        def available(self):
            return True
        def complete(self, **kwargs):
            state = json.loads(kwargs["user"])
            seen.append(state)
            assert state["card"]["body"] == actual["body"]
            assert state["card"]["digest"] == actual["digest"]
            receipts = [event["receipt"] for event in state["history"] if event["kind"] == "receipt"]
            action = ({"kind": "finish", "claim": "This fixture response contains the quoted text", "claimed_verdict": "uncertain",
                       "citations": [{"call_id": receipts[0]["call_id"], "quote": "Quartz Portal"}]}
                      if receipts else {"kind": "call", "request": REQUEST})
            return ModelReply(ok=True, text=json.dumps(action), payload=action, model="offline")
    monkeypatch.setattr(cli, "client_from_env", lambda **_: Client())
    assert cli.main(["--card", skill_id, "--task", json.dumps(supplied), "--run-dir", str(tmp_path),
                     "--model", "offline"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "model_reported" and result.get("status") != "pass"
    assert len(seen) == 2 and len([call for call in calls if call[0] == "request"]) == 1


def test_a_native_http_frame_carries_its_exit_code(monkeypatch):
    """A frame without a code can never become evidence: the receipt check refuses it.

    walk-137 node 7: the engine's own http client printed `agvXXXXend` with no code, so all
    three requests were dropped with RECEIPT_COMMAND_UNCONFIRMED, the verifier was handed an
    empty `calls` list, and the step could only answer UNKNOWN with the include chain green.
    """
    executor, _calls = native_client(monkeypatch)
    argv = lean_http.prepare(REQUEST, SCOPE, "probe123", "/custom/python3")
    outcome = executor(argv, 1)
    assert outcome.stdout.splitlines()[-1] == "probe123end 0"
    complete, code = observe_marker_frame(outcome.stdout, "probe123")
    assert complete and code == 0
