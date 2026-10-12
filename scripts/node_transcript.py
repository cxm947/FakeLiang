#!/usr/bin/env python3
"""每个节点的模型输出转录 + 两轮逐一对比（爷爷 2026-10-07 口径：改了 A 要知道会不会影响 B）。

用法：
    python scripts/node_transcript.py --run output/runs/walk-70
    python scripts/node_transcript.py --diff walk-69 walk-70          # 只看分叉
    python scripts/node_transcript.py --diff walk-69 walk-70 --node 7

为什么要有它：`events.jsonl` 里本来就有模型的原文，但它是给机器读的 JSONL；人要判断
"这次改卡/改契约，是不是把别的节点带坏了"，需要的是**逐发可读、可对齐**的转录。
转录只做搬运与对齐，不改写任何结论，也照原样保留脱敏后的文本。
"""
from __future__ import annotations

import argparse
import glob
import io
import json
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS = os.path.join(ROOT, "output", "runs")


def _rows(path):
    out = []
    if os.path.exists(path):
        for line in io.open(path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def _clip(text, limit=320):
    text = " ".join(str(text or "").split())
    return text[:limit] + ("…" if len(text) > limit else "")


def _flat(text):
    """模型自己的原文：只把空白压平（好让一次调用占一行），**一个字符都不截**。

    爷爷 2026-10-07 的口径是"记录每一个节点的各次模型输出"，而判断"改了 A 会不会影响 B"要靠
    逐字对比：截断过的原文只能证明"前 320 字一样"，证明不了"模型说的是同一句话"。
    回执那几行仍然截断（原文在 `calls/<id>/stdout.txt` 里，人读转录只需要认出是哪一发）。
    """
    return " ".join(str(text or "").split())


def _clock(at):
    try:
        return time.strftime("%H:%M:%S", time.localtime(float(at)))
    except (TypeError, ValueError):
        return "??:??:??"


def node_ids(run_dir):
    found = []
    for name in os.listdir(run_dir):
        if name.startswith("node") and name[4:].isdigit():
            found.append(int(name[4:]))
    return sorted(found)


def turns(run_dir, node):
    """把一个节点的事件流对成"回合"：发> 模型原文 / 回< 回执 / 拒! 拒绝 / 判: 结论。"""
    directory = os.path.join(run_dir, "node%s" % node)
    events = _rows(os.path.join(directory, "events.jsonl"))
    outputs = {}
    for path in sorted(glob.glob(os.path.join(directory, "calls", "*"))):
        text_path = os.path.join(path, "stdout.txt")
        text = io.open(text_path, encoding="utf-8", errors="replace").read() if os.path.exists(text_path) else ""
        #: 只滤**引擎自己的标记行**（`agv<hex>start` / `agv<hex>end`），不是"以 agv 开头的所有行" ——
        #: 2026-10-07 踩过：值恰好叫 `agv_val_12`，被这个前缀过滤吃掉，我据此得出"回执是空的"的错误结论。
        engine_marker = re.compile(r"^agv[0-9a-z]{4,}(start|end)$")
        keep = [line for line in text.splitlines()
                if line.strip() and not engine_marker.match(line.strip())]
        outputs[os.path.basename(path)] = keep[-3:]
    out, reply = [], ""
    for event in events:
        kind = event.get("kind")
        at = _clock(event.get("at"))
        if kind == "decision":
            answer = event.get("reply") or {}
            reply = str(answer.get("text") or "")
            #: 模型原文全文进转录（不截断）：这一行就是"这一发模型到底说了什么"的记录。
            out.append(("ask", at, _flat(reply)))
        elif kind == "intent":
            request = event.get("request") or {}
            brief = request.get("path") or request.get("cmd") or json.dumps(request, ensure_ascii=False)
            out.append(("send", at, _clip(brief, 200)))
        elif kind == "receipt":
            call_id = str(event.get("call_id") or "")
            tail = outputs.get(call_id, [])
            out.append(("recv", at, "%s | %s" % (event.get("receipt", {}).get("status"),
                                                 _clip(" / ".join(tail), 200))))
        elif kind == "refusal":
            refusal = event.get("refusal", {})
            out.append(("deny", at, "%s | %s" % (refusal.get("reason_code"),
                                                 _clip(refusal.get("detail"), 120))))
        elif kind == "abandon":
            out.append(("abandon", at, _clip(event.get("reason"), 120)))
        elif kind == "conclusion":
            result = event.get("result") or {}
            out.append(("verdict", at, "%s | %s | %s" % (result.get("status"),
                                                         result.get("claimed_verdict"),
                                                         _clip(result.get("claim"), 200))))
        elif kind == "correction":
            out.append(("fix", at, _clip(json.dumps(event.get("feedback") or {}, ensure_ascii=False), 160)))
    return out


def render(run_dir, node):
    lines = ["## node %s" % node, ""]
    for kind, at, text in turns(run_dir, node):
        lines.append("* [%s] %-8s %s" % (at, kind, text))
    return "\n".join(lines) + "\n"


def write_all(run_name):
    run_dir = os.path.join(RUNS, run_name)
    if not os.path.isdir(run_dir):
        print("没有这个 run: " + run_dir)
        return 2
    target = os.path.join(run_dir, "model_outputs.md")
    with io.open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("# %s · 每个节点的模型输出（逐发转录）\n\n" % run_name)
        handle.write("发出去的是模型原文（已脱敏）；send=动作、recv=回执、deny=拒绝、verdict=结论。\n\n")
        for node in node_ids(run_dir):
            handle.write(render(run_dir, node) + "\n")
    print("写好:", target)
    return 0


def diff(run_a, run_b, only=None):
    dir_a, dir_b = os.path.join(RUNS, run_a), os.path.join(RUNS, run_b)
    nodes = sorted(set(node_ids(dir_a)) & set(node_ids(dir_b)))
    if only:
        nodes = [node for node in nodes if node == int(only)]
    forks = 0
    for node in nodes:
        a, b = turns(dir_a, node), turns(dir_b, node)
        same = [item[2] for item in a] == [item[2] for item in b]
        print("node %-3s %s  (%s 发 vs %s 发)" % (node, "一致" if same else "**分叉**", len(a), len(b)))
        if same:
            continue
        forks += 1
        for index in range(max(len(a), len(b))):
            left = a[index] if index < len(a) else ("", "", "(没有)")
            right = b[index] if index < len(b) else ("", "", "(没有)")
            if left[2] == right[2]:
                continue
            print("   第 %d 发起分叉:" % (index + 1))
            print("      %s: %s · %s" % (run_a, left[0], _clip(left[2], 200)))
            print("      %s: %s · %s" % (run_b, right[0], _clip(right[2], 200)))
            break
    print("\n分叉节点数: %d / %d" % (forks, len(nodes)))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="node_transcript.py", description=__doc__)
    parser.add_argument("--run")
    parser.add_argument("--diff", nargs=2, metavar=("A", "B"))
    parser.add_argument("--node")
    args = parser.parse_args(argv)
    if args.diff:
        return diff(args.diff[0], args.diff[1], only=args.node)
    if args.run:
        return write_all(os.path.basename(args.run.rstrip("/\\")))
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
