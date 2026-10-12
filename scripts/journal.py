#!/usr/bin/env python3
"""走图日志：把一轮验证写成人读的 txt（爷爷 2026-10-06 要的那种）。

一个 txt 里，每轮一节、每个节点一条，按「planner 给了什么 → 前置齐不齐 → 利用段每一次调用 →
验证结果 → 会话管理结果」的顺序排。它不是新的事实来源：每一行都来自本轮验证自己的产物
（plan_result.json、每个节点的 events.jsonl 与 calls/*、通道账本 channels.jsonl），所以读它
就是读证据，而不是读另一份需要维护的摘要。

验证流程在结尾写 <run>/walk.txt；--journal <file> 再把这一节追加到一个跨轮的汇总文件，这样
一条命令就能看到历轮验证。
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

VERDICT_CN = {"pass": "通过", "unsatisfied": "不满足", "uncertain": "不确定", "": "（未给）"}
STATUS_CN = {"proved": "成立", "stopped": "停住", "blocked": "阻塞",
             "blocked_upstream": "上游未成立", "uncertain": "不确定"}


def _stamp(seconds) -> str:
    try:
        return datetime.fromtimestamp(float(seconds)).strftime("%H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "?"


def _short(value, limit=160) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[:limit] + "…"


def _one_call(node_dir, call_id) -> str:
    """调用一行：命令本身（回执正文留在 calls/<id>/，不搬进来）。"""
    call_path = Path(node_dir) / "calls" / call_id / "call.json"
    if not call_path.is_file():
        return "(调用记录缺失)"
    try:
        record = json.loads(call_path.read_text(encoding="utf-8"))
    except ValueError:
        return "(调用记录不可读)"
    return _short(json.dumps(record.get("argv") or record.get("request") or record,
                             ensure_ascii=False))


def _events(node_dir):
    path = Path(node_dir) / "events.jsonl"
    out = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    return out


def node_section(node_id, *, plan, channels, graph, run_dir) -> list:
    row = (plan.get("nodes") or {}).get(str(node_id)) or {}
    node_dir = Path(row.get("run_dir") or (Path(run_dir) / ("node" + str(node_id))))
    status = STATUS_CN.get(str(row.get("status")), row.get("status") or "-")
    lines = ["", "── node %s · %s · %s" % (node_id, row.get("card") or "-", status)]
    choice = next((item for item in (plan.get("planner") or [])
                   if str(item.get("node")) == str(node_id)), None)
    if choice:
        note = _short(choice.get("note") or "", 120)
        lines.append("   planner 给的下一步：node %s（来源 %s）%s"
                     % (node_id, choice.get("source") or "-", ("：" + note) if note else ""))
        for refusal in choice.get("refusals") or []:
            lines.append("     · 模型被拒一次：%s %s"
                         % (refusal.get("reason_code"), _short(refusal.get("detail"), 100)))
    if graph:
        node = next((item for item in graph.get("nodes") or []
                     if str(item.get("id")) == str(node_id)), None)
        proved = set(str(x) for x in (plan.get("proved") or []))
        for dep in (node or {}).get("dependencies") or []:
            if str(dep.get("type")).upper() != "OR":
                continue
            producers = [str(x) for x in (dep.get("produced_by") or [])]
            done = [x for x in producers if x in proved]
            if done:
                where = "由 node %s 成立" % "、".join(done)
            elif str(node_id) in producers:
                where = "本步自己就是它的产物（候选 %s）" % "、".join(producers)
            else:
                where = "（候选 %s，本轮未成立）" % "、".join(producers)
            lines.append("   前置（OR）：%s → %s" % (_short(dep.get("description"), 70), where))
    block = row.get("verification")
    if isinstance(block, dict) and block.get("state"):
        facts = block.get("facts") or []
        if block.get("state") == "verified":
            tally = {}
            for item in facts:
                tally[item.get("verdict")] = tally.get(item.get("verdict"), 0) + 1
            lines.append("   验证回合：对图上判据逐条自测 —— "
                         + "、".join("%s×%d" % (k, v) for k, v in sorted(tally.items())))
            for item in facts:
                lines.append("     · %s → %s（%s / %s）"
                             % (item.get("ref"), item.get("verdict"), item.get("proof"),
                                item.get("verifier")))
        else:
            lines.append("   验证回合：没验成（%s %s）"
                         % (block.get("state"), _short(block.get("reason"), 80)))
    events = _events(node_dir)
    intents = [e for e in events if e.get("kind") == "intent"]
    receipts = {e.get("call_id"): (e.get("receipt") or {})
                for e in events if e.get("kind") == "receipt"}
    if intents:
        lines.append("   调用（%d 次）：" % len(intents))
        for index, event in enumerate(intents, 1):
            call_id = event.get("call_id") or ""
            receipt = receipts.get(call_id) or {}
            state = receipt.get("status") or "未回执"
            code = receipt.get("returncode")
            lines.append("     %d) [%s] %s → %s%s"
                         % (index, _stamp(event.get("at")), _one_call(node_dir, call_id), state,
                            ("（rc=%s）" % code) if code is not None else ""))
    else:
        lines.append("   调用：无（这一步没有动作，或它是纯判定节点）")
    for event in events:
        if event.get("kind") == "refusal":
            refusal = event.get("refusal") or {}
            lines.append("   · 拒绝回喂：%s %s"
                         % (refusal.get("reason_code"), _short(refusal.get("detail"), 90)))
        if event.get("kind") == "abandon":
            lines.append("   · 作废未决调用：%s（%s）"
                         % (event.get("call_id"), _short(event.get("reason"), 70)))
    concludes = [e for e in events if e.get("kind") == "conclusion"]
    if concludes:
        result = concludes[-1].get("result") or {}
        lines.append("   验证结果：%s（claimed=%s）"
                     % (_short(row.get("reason"), 60) or "-",
                        VERDICT_CN.get(str(result.get("claimed_verdict")),
                                       result.get("claimed_verdict") or "-")))
        if result.get("claim"):
            lines.append("     结论原文：%s" % _short(result.get("claim"), 220))
    else:
        lines.append("   验证结果：本步没有结论（状态 %s，原因 %s）"
                     % (status, _short(row.get("reason"), 80) or "-"))
    if row.get("blocks"):
        lines.append("   挡住了：node %s" % "、".join(str(x) for x in row["blocks"]))
    mine = [c for c in channels if str(c.get("source_node")) == str(node_id)]
    migration = row.get("migration") or {}
    if mine or migration:
        lines.append("   会话管理：")
        for channel in mine:
            lines.append("     · 登记 %s host=%s%s%s%s"
                         % (channel.get("kind"), channel.get("host"),
                            (" priv=" + str(channel.get("privilege")))
                            if channel.get("privilege") else "",
                            (" sess=" + str(channel.get("session_id")))
                            if channel.get("session_id") else "",
                            ("｜" + _short(channel.get("note"), 60))
                            if channel.get("note") else ""))
        if migration:
            extra = ""
            if migration.get("listen_port"):
                extra += " 端口=%s" % migration["listen_port"]
            if migration.get("sessions"):
                extra += " 会话=%s" % "、".join(str(x) for x in migration["sessions"])
            lines.append("     · 迁移：%s（%s）%s"
                         % (migration.get("state") or "-",
                            _short(migration.get("reason"), 60), extra))
    return lines


def render(run_dir, *, graph_path="") -> str:
    run_dir = Path(run_dir)
    plan = json.loads((run_dir / "plan_result.json").read_text(encoding="utf-8"))
    channels = []
    ledger = run_dir / "channels.jsonl"
    if ledger.is_file():
        for line in ledger.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                try:
                    channels.append(json.loads(line))
                except ValueError:
                    continue
    graph = {}
    if graph_path and Path(graph_path).is_file():
        graph = json.loads(Path(graph_path).read_text(encoding="utf-8"))
    proved = plan.get("proved") or []
    lines = ["=" * 78,
             "验证轮次：%s" % run_dir.name,
             "顺序：%s" % " → ".join(str(x) for x in (plan.get("order") or [])),
             "结果：成立 %d 个（%s）｜停住 %s｜阻塞 %s｜上游未成立 %s"
             % (len(proved),
                "、".join(str(x) for x in sorted(proved, key=lambda x: int(x))) or "无",
                "、".join(str(x) for x in (plan.get("stopped") or [])) or "无",
                "、".join(str(x) for x in (plan.get("blocked") or [])) or "无",
                "、".join("%s←%s" % (k, "、".join(v))
                          for k, v in (plan.get("blocked_upstream") or {}).items()) or "无"),
             "=" * 78]
    for node_id in plan.get("order") or []:
        lines += node_section(node_id, plan=plan, channels=channels,
                              graph=graph, run_dir=run_dir)
    lines.append("")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="journal.py", description=__doc__)
    parser.add_argument("--run", required=True, help="一轮验证的目录（含 plan_result.json）")
    parser.add_argument("--graph", default="output/hongri7/json/Hongri7_v2.action_graph.json",
                        help="读前置依赖用的攻击图（没有就不写前置段）")
    parser.add_argument("--journal", default="", help="把这一节追加到这个跨轮汇总 txt")
    parser.add_argument("--show", action="store_true", help="同时打到标准输出")
    args = parser.parse_args(argv)
    graph_path = str(ROOT / args.graph) if args.graph else ""
    text = render(args.run, graph_path=graph_path)
    (Path(args.run) / "walk.txt").write_text(text, encoding="utf-8", newline="\n")
    if args.journal:
        target = Path(args.journal)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(text + "\n")
    if args.show:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
