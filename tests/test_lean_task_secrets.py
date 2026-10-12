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


@pytest.mark.parametrize("short", [False, True])
def test_direct_drive_projects_credentials_and_restores_nested_http_values(tmp_path, monkeypatch, short):
    from uuid import uuid4
    from agents._model.contract import ModelReply

    secret = "".join(map(chr, (126, 33))) if short else uuid4().hex
    supplied = task()
    supplied["inputs"]["credential_ref"] = {"user": "operator", "secret": secret}
    native, calls = native_client(monkeypatch, body=("echo:" + secret).encode())
    prompts = []

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            assert secret not in kwargs["user"]
            state = json.loads(kwargs["user"])
            token = state["task"]["inputs"]["credential_ref"]["secret"]
            assert token.startswith("«secret:")
            prompts.append(kwargs)
            receipts = [event["receipt"] for event in state["history"] if event["kind"] == "receipt"]
            action = ({"kind": "finish", "claim": "The response was observed", "claimed_verdict": "pass",
                       "citations": [{"call_id": receipts[0]["call_id"], "quote": "<redacted>"}]}
                      if receipts else {"kind": "call", "request": dict(REQUEST, method="POST", body=token,
                            headers={"X-Credential": token})})
            return ModelReply(ok=True, text=json.dumps(action), payload=action,
                              model="offline:" + secret, error="provider echo:" + secret)

    result = cli.drive(card(), supplied, SCOPE, native, client=Client(), run_dir=tmp_path)
    assert result["status"] == "model_reported", result
    assert len(prompts) == 2
    sent = next(row for row in calls if row[0] == "request")
    assert sent[3] == secret.encode() and sent[4]["X-Credential"] == secret
    assert secret not in json.dumps(result)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert secret not in path.read_text(encoding="utf-8"), path


@pytest.mark.parametrize("style,reason", [
    ("unknown", "LEAN_SECRET_TOKEN_UNKNOWN"),
    ("malformed", "LEAN_SECRET_TOKEN_UNKNOWN"),
    ("composite", "LEAN_SECRET_TOKEN_COMPOSITE"),
])
def test_model_secret_tokens_must_be_known_whole_values_before_dispatch(tmp_path, style, reason):
    from uuid import uuid4
    from agents._model.contract import ModelReply

    supplied = task()
    supplied["inputs"]["credential_ref"] = {"secret": uuid4().hex}
    calls = []

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            token = json.loads(kwargs["user"])["task"]["inputs"]["credential_ref"]["secret"]
            value = {"unknown": "«secret:999»", "malformed": "«secret:oops»",
                     "composite": "prefix-" + token}[style]
            action = {"kind": "call", "request": dict(REQUEST, headers={"X-Test": value})}
            return ModelReply(ok=True, text=json.dumps(action), payload=action, model="offline")

    result = cli.drive(card(), supplied, SCOPE, lambda *args: calls.append(args),
                       client=Client(), run_dir=tmp_path)
    assert result["reason"] == reason and not calls
    assert not (tmp_path / "calls").exists()


def test_token_restore_walks_shell_lists_and_rejects_token_keys():
    from uuid import uuid4

    secret = uuid4().hex
    token = "«secret:1»"
    action = {"kind": "call", "request": {"tool": "shell", "argv": ["client", "--password", token]},
              "nested": [{"value": token}]}
    restored = cli.restore_secrets(action, {token: secret})
    assert restored["request"]["argv"][-1] == secret and restored["nested"][0]["value"] == secret
    assert action["request"]["argv"][-1] == token
    with pytest.raises(ValueError, match="LEAN_SECRET_TOKEN_KEY_UNSUPPORTED"):
        cli.restore_secrets({token: "value"}, {token: secret})


def test_scripted_unknown_token_cannot_reach_transport(tmp_path):
    calls = []
    action = {"kind": "call", "request": dict(REQUEST, body="«secret:1»")}
    result = cli.drive(card(), task(), SCOPE, lambda *args: calls.append(args),
                       actions=[action], run_dir=tmp_path)
    assert result["reason"] == "LEAN_SECRET_TOKEN_UNKNOWN" and not calls


def test_direct_drive_masks_short_secret_in_model_exception(tmp_path):
    secret = "".join(map(chr, (126, 33)))
    supplied = task()
    supplied["inputs"]["credential_ref"] = {"secret": secret}

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            raise RuntimeError("provider failure: " + secret)

    result = cli.drive(card(), supplied, SCOPE, lambda *_: pytest.fail("unexpected dispatch"),
                       client=Client(), run_dir=tmp_path)
    assert result["reason"] == "provider failure: <redacted>"
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert secret not in path.read_text(encoding="utf-8"), path


@pytest.mark.parametrize("private_result", [False, True])
def test_private_result_keeps_control_value_while_persisted_verdict_is_masked(
        tmp_path, monkeypatch, private_result):
    from agents._model.contract import ModelReply

    secret = "".join(map(chr, (112, 97, 115, 115)))
    supplied = task()
    supplied["inputs"]["credential_ref"] = {"user": "operator", "secret": secret}
    native, _ = native_client(monkeypatch)

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            state = json.loads(kwargs["user"])
            assert secret not in kwargs["user"]
            receipts = [event["receipt"] for event in state["history"] if event["kind"] == "receipt"]
            action = ({"kind": "finish", "claim": "Observed page", "claimed_verdict": secret,
                       "citations": [{"call_id": receipts[0]["call_id"], "quote": "Quartz Portal"}]}
                      if receipts else {"kind": "call", "request": REQUEST})
            return ModelReply(ok=True, text=json.dumps(action), payload=action, model="offline")

    result = cli.drive(card(), supplied, SCOPE, native, client=Client(), run_dir=tmp_path,
                       private_result=private_result)
    assert result["status"] == "model_reported"
    assert result["claimed_verdict"] == (secret if private_result else "<redacted>")
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    recorded = next(event["result"] for event in events if event["kind"] == "conclusion")
    assert recorded["claimed_verdict"] == "<redacted>"
    assert recorded["citations"][0]["call_id"] == result["citations"][0]["call_id"]
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert secret not in path.read_text(encoding="utf-8"), path


def test_cli_exit_uses_private_status_before_print_masking(tmp_path, monkeypatch, capsys):
    secret = "".join(map(chr, (109, 111, 100, 101, 108, 95, 114, 101, 112, 111, 114, 116, 101, 100)))
    supplied = task()
    supplied["inputs"]["credential_ref"] = {"secret": secret}
    monkeypatch.setattr(cli, "load_card", lambda *_: card())

    def completed(*args, **kwargs):
        assert kwargs["private_result"] is True
        return {"status": secret, "claimed_verdict": "uncertain"}

    monkeypatch.setattr(cli, "drive", completed)
    assert cli.main(cli_args(tmp_path, supplied, [])) == 0
    assert secret not in capsys.readouterr().out


def test_a_secret_may_sit_inside_a_flat_command_but_not_inside_other_values():
    """占位符：命令文本里可以嵌（`/p «secret:x»`），其他字段仍须独占整个值。

    2026-10-06 walk-65 node 2 实测：扁平形状下整条命令就是一个字符串，密码必然嵌在命令里；
    而 `LEAN_SECRET_TOKEN_COMPOSITE` 是给"密码是独立 argv 项"的旧形状定的 —— 不分场合地要求独占，
    模型就永远发不出带密码的命令（`schtasks /p`、`net use /user:… 密码`、`wmic /password:` 全废），
    而 44/48 全靠这条路。
    """
    import pytest

    token = "«secret:1»"
    mapping = {token: "P@ssw0rd!"}
    flat = {"kind": "call", "request": {"tool": "shell",
                                        "cmd": "schtasks /create /s 10.0.0.9 /u D\\a /p %s /tn t" % token}}
    restored = cli.restore_action(flat, mapping)
    assert restored["request"]["cmd"].endswith("P@ssw0rd! /tn t")
    #: 结构化字段仍严格：把占位符粘进别的字串要拒
    strict = {"kind": "call", "request": {"tool": "http", "method": "GET",
                                          "path": "/x", "body": "pw=" + token}}
    with pytest.raises(ValueError) as caught:
        cli.restore_action(strict, mapping)
    assert "LEAN_SECRET_TOKEN_COMPOSITE" in str(caught.value)
    #: 编造的占位符任何场合都拒
    with pytest.raises(ValueError) as caught:
        cli.restore_action({"kind": "call",
                            "request": {"tool": "shell", "cmd": "x «secret:nope» y"}}, mapping)
    assert "LEAN_SECRET_TOKEN_UNKNOWN" in str(caught.value)


def test_a_card_that_declares_no_materials_ignores_the_extra_ones_instead_of_dying(tmp_path):
    """卡没声明 materials、模型多给了一份 → 忽略并留痕，不许把干成的节点杀掉。

    2026-10-06 walk-66 node 2 实测：那一步真的把 DC 防火墙关掉了（回读里 `状态 关闭`），
    只因为模型顺手复述了一遍用过的域管凭据，整节点以 `LEAN_MATERIALS_UNDECLARED` 停住，
    成果没记账、node 44 因此派不出来。
    """
    from runtime import lean as lean_mod

    card = {"id": "x.y", "digest": "d", "runs_at": "base", "tools": ["shell"]}
    scope = {"host": "10.0.0.5", "port": 80, "protocol": "tcp", "vantage": "base",
             "resources": "whole_endpoint"}
    task = {"node_id": "2", "inputs": {}}
    run = lean_mod.LeanRun(tmp_path, card=card, task=task, scope=scope,
                           executor=lambda argv, timeout: ExecOutcome(0, "", ""))
    result = run.conclude("防火墙已关闭（回读 状态=关闭）", [], "pass",
                          [{"realm": "D", "user": "u", "value": "v", "kind": "password",
                            "source_call": "c", "quote": "q"}])
    assert result["claimed_verdict"] == "pass"
    assert "materials" not in result, "没声明的材料不许进结果（避免被当成供给）"
    assert "materials_ignored" in result, "忽略要留痕，不能静默"


def test_a_materials_card_does_not_demand_materials_when_the_answer_is_not_a_pass(tmp_path):
    """卡声明了 materials，但结论**不是 pass** 时，不带材料是合法的（诚实说"没观测到"）。

    2026-10-06 walk-63 node 5 实测：模型写下"三次回包只有传输标记、没有任何凭据行，无法交付六件套"，
    运行时却以 `LEAN_MATERIALS_INVALID` 停住整节点 —— 错误名还把责任指向模型，而真相是引擎这一问
    把"没给材料"当成了"材料不合法"。只有要判 pass 时材料才是硬要求。
    """
    import pytest

    from runtime import lean as lean_mod

    card = {"id": "x.y", "digest": "d", "runs_at": "base", "tools": ["shell"],
            "materials": ["realm", "user", "value", "kind", "source_call", "quote"]}
    scope = {"host": "10.0.0.5", "port": 80, "protocol": "tcp", "vantage": "base",
             "resources": "whole_endpoint"}
    task = {"node_id": "5", "inputs": {}}
    run = lean_mod.LeanRun(tmp_path, card=card, task=task, scope=scope,
                           executor=lambda argv, timeout: ExecOutcome(0, "", ""))

    result = run.conclude("三轮回包都只有标记行，没有凭据行", [], "uncertain", None)
    assert result["claimed_verdict"] == "uncertain"
    assert "materials" not in result, "没材料的非 pass 结论不该凭空多出 materials"

    #: 真要判 pass 才必须交材料（仍是硬要求）
    with pytest.raises(ValueError) as caught:
        run.conclude("拿到凭据了", [], "pass", None)
    assert "LEAN_MATERIALS_MISSING" in str(caught.value)

    #: 给了材料但不是列表 = 形状错，仍然具名拒绝
    with pytest.raises(ValueError) as caught:
        run.conclude("…", [], "uncertain", "realm=WHOAMIANONY")
    assert "LEAN_MATERIALS_INVALID" in str(caught.value)
