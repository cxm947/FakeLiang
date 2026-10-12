#!/usr/bin/env python3
"""一轮跑完，交付到底成没成：把 D64 那五条验收读成一张表。

为什么单独一个脚本：判"跨网段交付成没成"要同时看四个地方（回程回执 / 交付命令 / 交付结果 / 收获表），
翻四处容易漏、也容易把"命令跑过了"当成"会话交回来了"。这里一次读完，缺哪条就报哪条。

用法：python scripts/check_delivery.py --run output/runs/walk-52
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))


def relay_rows(run_dir) -> list:
    """一扇门一行：走了哪条路、装没装上（回执是唯一依据）。"""
    rows = []
    folder = Path(run_dir) / "relay"
    for path in sorted(folder.glob("relay-*.json")) if folder.is_dir() else []:
        data = json.loads(path.read_text(encoding="utf-8"))
        rows.append({"file": path.name, "ok": data.get("ok"), "route": data.get("route"),
                     "listen_port": data.get("listen_port"), "connect": data.get("connect"),
                     "attempts": len([s for s in data.get("steps") or [] if s.get("attempt")])})
    return rows


def delivery_commands(run_dir) -> dict:
    """每个节点拿到的 delivery_command（从决策 prompt 的 task 输入里抠出来）。"""
    found = {}
    for node_dir in sorted(Path(run_dir).glob("node*")):
        events = node_dir / "events.jsonl"
        if not events.is_file():
            continue
        for line in events.read_text(encoding="utf-8", errors="replace").splitlines():
            #: events.jsonl 里它是被转义过的（\"delivery_command\"），所以只按裸词找。
            index = line.find("delivery_command")
            if index < 0:
                continue
            tail = line[index:index + 260].replace(chr(92) + chr(34), chr(34)).replace(chr(92) * 2, chr(92))
            found[node_dir.name] = tail[:200]
    return found


def session_rows(run_dir) -> list:
    path = Path(run_dir) / "harvest.jsonl"
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("row_type") == "session" and row.get("kind") in ("console_session", "ssh", "web"):
            rows.append({"logical": row.get("logical"), "host": row.get("host"),
                         "kind": row.get("kind"), "session_id": row.get("session_id"),
                         "session_type": row.get("session_type"), "node": row.get("source_node")})
    return rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="check_delivery.py", description=__doc__)
    parser.add_argument("--run", required=True, help="一轮的目录")
    args = parser.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    run_dir = Path(args.run)
    if not run_dir.is_dir():
        raise SystemExit("RUN_DIR_MISSING: %s" % run_dir)

    print("== 1) 回程门（relay 回执）==")
    relays = relay_rows(run_dir)
    if not relays:
        print("  （没有回执：这一轮还没走到跨网段交付，或者没走 relay 路线）")
    for row in relays:
        print("  %s ok=%s route=%s %s -> %s（%d 次尝试）"
              % (row["file"], row["ok"], row["route"], row["listen_port"], row["connect"],
                 row["attempts"]))

    print("== 2) 交付命令（每个节点拿到的）==")
    commands = delivery_commands(run_dir)
    if not commands:
        print("  （没有节点拿到 delivery_command）")
    for node, command in commands.items():
        bad = ("占位符（web 路线把动作放在 payload_php 里，这里出现是正常的；凭据路线不该是它）"
               if ("agv-entry-ok" in command or not command.strip()) else "像真的") 
        print("  %s: [%s] %s" % (node, bad, command))

    print("== 3) 交付结果与节点结论 ==")
    result_path = run_dir / "plan_result.json"
    if result_path.is_file():
        plan = json.loads(result_path.read_text(encoding="utf-8"))
        for node_id in ("44", "48"):
            row = (plan.get("nodes") or {}).get(node_id)
            if row:
                print("  node %s: %s%s" % (node_id, row.get("status"),
                                           ("（" + str(row.get("reason")) + "）") if row.get("reason") else ""))
        print("  成立：%s" % ("、".join(plan.get("proved") or []) or "无"))
        print("  没成立：%s" % ("、".join(plan.get("stopped") or []) or "无"))
    else:
        print("  （还没有 plan_result.json：这一轮还在跑）")

    print("== 4) 收获表里的会话 ==")
    rows = session_rows(run_dir)
    if not rows:
        print("  （还没有会话行）")
    for row in rows:
        print("  %-8s %-16s %-16s sess=%s type=%s（node %s）"
              % (row["logical"], row["host"], row["kind"], row["session_id"],
                 row["session_type"], row["node"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
