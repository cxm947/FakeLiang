#!/usr/bin/env python3
"""靶场轮次的地基：回滚干净快照 + 核基线（爷爷 2026-10-06：每轮重跑之前都回滚干净快照）。

为什么需要它：这一轮之后"验证的起点"不再取决于"上一轮清干净没有"，而是**一个确定的快照**。
于是真机结果可复现：同一张图、同一份映射表、同一个起点，差别只可能来自引擎或模型。

两件事：

* revert —— 把六台 VM **串行**回滚到指定快照（vmrun 并发会互相锁死：实测 6 个并发把一条 15 分钟
  的超时跑满，而串行 45 秒就全好了）；
* verify —— 核"起点真的能跑"：kali 上没有我们的文件/监听、msfrpcd 在跑、靶点端口开。

实验室事实（部署配置，不是代码）：VM 列表与 vmrun 路径来自 --lab-config，在仓库外。

用法：
  python scripts/lab_round.py revert --snapshot AGV-CLEAN-20261006-v2
  python scripts/lab_round.py verify --remote kali@192.168.52.128 --password kali
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

DEFAULT_LAB_CONFIG = r"E:\Desktop\ai\lab-cleanup-20261005\targets.json"
DEFAULT_SNAPSHOT = "AGV-CLEAN-20261006-v2"

#: kali 上"干净起点"的探针：残留 / 我们的监听 / msfrpcd / 两个靶点端口。
PROBE = (
    "echo AGVAGV-LEFTOVERS; ls -d /tmp/agv* 2>/dev/null; "
    "echo AGVAGV-LISTENERS; (ss -lntp 2>/dev/null || netstat -lntp 2>/dev/null) | grep -E '108[0-9]|109[0-9]'; "
    "echo AGVAGV-MSF; ss -lntp 2>/dev/null | grep -c 55553; "
    "echo AGVAGV-WEB1; timeout 4 bash -c 'cat < /dev/null > /dev/tcp/192.168.52.10/81' && echo open || echo down; "
    "echo AGVAGV-PC1; timeout 4 bash -c 'cat < /dev/null > /dev/tcp/192.168.52.30/8080' && echo open || echo down; "
    "echo AGVAGV-DONE"
)

LABELS = ("LEFTOVERS", "LISTENERS", "MSF", "WEB1", "PC1")


def load_lab(path):
    """实验室配置：vmrun 路径 + 六台 VM 的 vmx。缺文件就是具名拒绝，不猜。"""
    target = Path(path)
    if not target.is_file():
        raise SystemExit("LAB_CONFIG_MISSING: %s" % target)
    data = json.loads(target.read_text(encoding="utf-8"))
    if not data.get("vmrun") or not data.get("vms"):
        raise SystemExit("LAB_CONFIG_INCOMPLETE: %s needs vmrun and vms" % target)
    return data


def vmrun(config, *args, timeout=900):
    done = subprocess.run([config["vmrun"], "-T", "ws", *args], capture_output=True, timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    text = ((done.stdout or b"") + (done.stderr or b"")).decode("utf-8", "replace").strip()
    return done.returncode, text


def revert(config, snapshot, *, only=()):
    """串行：硬关 -> revertToSnapshot -> 无界面起。逐台打印，不做任何等待。"""
    lines = []
    for name, path in config["vms"].items():
        if only and name not in only:
            continue
        stop_rc, _ = vmrun(config, "stop", path, "hard", timeout=300)
        revert_rc, revert_text = vmrun(config, "revertToSnapshot", path, snapshot, timeout=900)
        start_rc, _ = vmrun(config, "start", path, "nogui", timeout=300)
        note = ("(" + revert_text[:60] + ")") if revert_text else ""
        lines.append("%-6s stop=%s revert=%s%s start=%s" % (name, stop_rc, revert_rc, note, start_rc))
    return lines


def parse_probe(text) -> dict:
    """把探针输出按 AGVAGV-<小节> 拆开：{小节: [非空行]}。"""
    found, label = {}, ""
    for line in str(text or "").replace("\r", "").splitlines():
        stripped = line.strip()
        if stripped.startswith("AGVAGV-"):
            label = stripped[len("AGVAGV-"):]
            found[label] = []
            continue
        if label and stripped:
            found[label].append(stripped)
    return found


def verify(*, remote, password) -> list:
    """核基线；返回人读的若干行，最后一行是结论。"""
    from runtime.remote import SshExecutor, parse_remote

    executor = SshExecutor(parse_remote(remote), password=password)
    try:
        outcome = executor(["/bin/sh", "-c", PROBE], 90.0)
    finally:
        executor.close()
    found = parse_probe(getattr(outcome, "stdout", ""))
    leftovers = found.get("LEFTOVERS") or []
    listeners = found.get("LISTENERS") or []
    msf = (found.get("MSF") or ["0"])[0]
    web1 = (found.get("WEB1") or ["?"])[0]
    pc1 = (found.get("PC1") or ["?"])[0]
    lines = ["kali    : 残留=%s 我们的监听=%d msfrpcd=%s"
             % ("无" if not leftovers else "、".join(leftovers[:4]), len(listeners),
                "在跑" if msf.strip() != "0" else "没在跑"),
             "靶点    : web1:81=%s pc1:8080=%s" % (web1, pc1)]
    ready = (not leftovers and not listeners and msf.strip() != "0"
             and web1 == "open" and pc1 == "open")
    lines.append("结论    : " + ("基线就绪" if ready else "基线不对，先别跑"))
    return lines


def round_(name, snapshot, lab_config, start, python, model, verify_facts=False):
    """一轮的起手：回滚干净快照 -> 核基线 -> （可选）把端到端命令发起来。"""
    config = load_lab(lab_config)
    for line in revert(config, snapshot):
        print("回滚 " + line, flush=True)
    for line in verify(remote="kali@192.168.52.128", password="kali"):
        print(line, flush=True)
    home = Path(os.environ.get("CODEX_HOME", ""))
    #: 模型线取 **供应商** 条目（providers.json 里的 deepseek），不取本机 model_router 那条。
    #: 实测 2026-10-06（同一份 payload、同样 reasoning.effort=none）：
    #:   直连 https://api.deepseek.com ：reasoning_tokens=0、1.08s
    #:   过 127.0.0.1:7789 router     ：reasoning_tokens=1156、6.44s（请求体被改写，input 还多 25 token）
    #: 所以"effort=none 关思考"只在直连时成立；经 router 白搭，且慢 6 倍。
    base_url, model_key = "", ""
    providers_path = home / "providers.json"
    if providers_path.is_file():
        try:
            entry = json.loads(providers_path.read_text(encoding="utf-8-sig"))["providers"]["deepseek"]
            base_url, model_key = str(entry.get("base_url") or ""), str(entry.get("api_key") or "")
        except (KeyError, ValueError):
            base_url, model_key = "", ""
    if base_url and model_key:
        print("模型线：%s（直连供应商，绕过本机 model_router）" % base_url, flush=True)
    else:
        #: 退路：老行为（本机 router）。能跑，但 reasoning.effort=none 会被吃掉。
        cfg_path = home / "config.toml"
        text = cfg_path.read_text(encoding="utf-8", errors="ignore") if cfg_path.is_file() else ""
        token = re.search(r'experimental_bearer_token\s*=\s*"(?P<v>[^"]+)"', text)
        base = re.search(r'base_url\s*=\s*"(?P<v>[^"]+)"', text)
        if not (token and base):
            print("模型配置读不到（%s）：自己带 --model-base-url 跑" % cfg_path)
            return 2
        base_url, model_key = base.group("v"), token.group("v")
        print("模型线：%s（本机 router —— 关不掉思考，仅作退路）" % base_url, flush=True)
    temp = os.environ.get("TEMP", "")
    argv = [python, "-u", "scripts/run_plan.py",
            "--graph", "data/inputs/hongri7/Hongri7_v2.txt",
            "--graph-assets", "data/inputs/hongri7/assets.json",
            "--host-map", "data/inputs/hongri7/host_ip_map.csv",
            "--run-root", "output/runs/" + name,
            "--remote", "kali@192.168.52.128", "--password", "kali",
            "--control", "192.168.52.128", "--msf-rpc", "msf:agvpass@192.168.52.128:55553",
            "--credentials", os.path.join(temp, "agv_private_credentials.json"),
            "--materials-dir", os.path.join(temp, "agv_materials"),
            #: ``chat`` = 官方 SDK 那条线（``from openai import OpenAI`` + chat.completions）。
            #: 关思考靠 ``extra_body={"thinking": {"type": "disabled"}}``，只在直连供应商时算数。
            "--model", model, "--model-base-url", base_url, "--model-wire", "chat",
            "--max-nodes", "14", "--max-steps", "12"]
    if verify_facts:
        argv.append("--verify-facts")
    print("命令：" + " ".join(argv), flush=True)
    if not start:
        print("（没带 --start：只把命令打出来）")
        return 0
    env = dict(os.environ, AGV_MODEL_API_KEY=model_key,
               AGV_MODEL_REASONING_EFFORT="none", AGV_MSF_RPC="msf:agvpass@192.168.52.128:55553")
    log = Path("tmp") / (name + ".out")
    handle = open(log, "wb")
    child = subprocess.Popen(argv, stdout=handle, stderr=subprocess.STDOUT, env=env,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    print("已发起：pid=%s 日志=%s" % (child.pid, log), flush=True)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="lab_round.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    back = sub.add_parser("revert", help="串行回滚六台到指定快照")
    back.add_argument("--snapshot", default=DEFAULT_SNAPSHOT)
    back.add_argument("--lab-config", default=DEFAULT_LAB_CONFIG)
    back.add_argument("--only", nargs="*", default=())
    check = sub.add_parser("verify", help="核基线（kali 干净 + 靶点开 + msfrpcd 在跑）")
    check.add_argument("--remote", default="kali@192.168.52.128")
    check.add_argument("--password", default="kali")
    whole = sub.add_parser("round", help="一轮的起手：回滚干净快照 + 核基线（+ --start 直接发起端到端）")
    whole.add_argument("--name", required=True, help="本轮名字（日志与 run-root 都用它）")
    whole.add_argument("--snapshot", default=DEFAULT_SNAPSHOT)
    whole.add_argument("--lab-config", default=DEFAULT_LAB_CONFIG)
    whole.add_argument("--start", action="store_true")
    whole.add_argument("--python", default=sys.executable)
    whole.add_argument("--model", default="deepseek-flash")
    whole.add_argument("--verify-facts", action="store_true",
                        help="每个节点跑完做一次验证回合（判据从图上来、模型自测、机器兜底）")
    args = parser.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    if args.command == "round":
        return round_(args.name, args.snapshot, args.lab_config, bool(args.start),
                      args.python, args.model, verify_facts=bool(args.verify_facts))

    if args.command == "revert":
        for line in revert(load_lab(args.lab_config), args.snapshot, only=tuple(args.only)):
            print(line, flush=True)
        return 0
    for line in verify(remote=args.remote, password=args.password):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
