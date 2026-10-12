"""逐发模型转录：改了 A 之后，还认得出 B 原来那几发说的是什么。"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import node_transcript  # noqa: E402


def test_the_transcript_keeps_the_models_own_words_whole(tmp_path, monkeypatch):
    """模型原文**不许截断**：截断过的原文只能证明"前 320 字一样"，证明不了"改 A 没动 B"。

    爷爷 2026-10-07 的口径：这一轮开始要记录每一个节点的各次模型输出，好判断改了一处之后
    会不会把别处带坏。判断依赖逐字对齐，所以转录里的 `ask` 行必须是全文。
    """
    run = tmp_path / "walk-99"
    node = run / "node7"
    (node / "calls" / "call-1").mkdir(parents=True)
    tail = "TAIL_MARKER"
    long_code = "KEEP" + "x" * 500 + tail
    events = [
        {"kind": "decision", "at": 1,
         "reply": {"text": '{"tool":"code","lang":"python","code":"%s"}' % long_code}},
        {"kind": "intent", "at": 2, "call_id": "call-1",
         "request": {"tool": "code", "name": "python"}},
        {"kind": "receipt", "at": 3, "call_id": "call-1",
         "receipt": {"status": "completed_transport"}},
        {"kind": "conclusion", "at": 4,
         "result": {"status": "model_reported", "claimed_verdict": "pass", "claim": "done"}},
    ]
    (node / "events.jsonl").write_text(
        "\n".join(json.dumps(item, ensure_ascii=False) for item in events) + "\n",
        encoding="utf-8", newline="\n")
    (node / "calls" / "call-1" / "stdout.txt").write_text("real output\n", encoding="utf-8",
                                                          newline="\n")

    monkeypatch.setattr(node_transcript, "RUNS", str(tmp_path))
    assert node_transcript.write_all("walk-99") == 0

    text = (run / "model_outputs.md").read_text(encoding="utf-8")
    assert "## node 7" in text
    assert tail in text, "模型原文被截断了：两轮就没法逐字对齐"
    assert "ask" in text and "recv" in text and "verdict" in text


def test_the_diff_points_at_the_first_diverging_call(tmp_path, monkeypatch, capsys):
    """两轮对齐：同一节点第几发开始不一样，直接指出来（这就是"改了 A 影响 B"的现场）。"""
    for name, first in (("walk-98", "id -u"), ("walk-99", "whoami")):
        node = tmp_path / name / "node12"
        node.mkdir(parents=True)
        events = [
            {"kind": "decision", "at": 1, "reply": {"text": '{"tool":"cmd","cmd":"%s"}' % first}},
            {"kind": "conclusion", "at": 2,
             "result": {"status": "model_reported", "claimed_verdict": "pass", "claim": "ok"}},
        ]
        (node / "events.jsonl").write_text(
            "\n".join(json.dumps(item, ensure_ascii=False) for item in events) + "\n",
            encoding="utf-8", newline="\n")

    monkeypatch.setattr(node_transcript, "RUNS", str(tmp_path))
    assert node_transcript.diff("walk-98", "walk-99") == 0
    out = capsys.readouterr().out
    assert "**分叉**" in out and "第 1 发起分叉" in out
    assert "id -u" in out and "whoami" in out
    assert "分叉节点数: 1 / 1" in out
