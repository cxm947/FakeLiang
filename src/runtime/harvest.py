"""收获表：一轮验证的全部收获，一个文件看全（爷爷 2026-10-06 的口径）。

原来分两处记：channels.jsonl 记会话与通道，credentials.jsonl 记挖到的凭据。两者分开就得两边翻，
而且"我手上有什么"没有一个单一答案。现在统一成 harvest.jsonl：一行一次收获，row_type 说这是哪
一类（session / credential / artifact）。

两类行的形状各自保持原样（会话行还是 runtime.channels 那套字段，凭据行还是 runtime.credentials
那套校验），所以两个读者不必改；新增的只是"它们在同一个文件里"，以及一个能把所有行一次读出来的
入口。旧验证目录（只有 channels.jsonl / credentials.jsonl）继续可读——读的时候兼容，不要求重跑。
"""
from __future__ import annotations

import json
import os
from pathlib import Path

#: The one file a run writes its harvest into.
HARVEST_NAME = "harvest.jsonl"
#: What a run wrote before the two were merged; read-only fallback for older directories.
LEGACY_FILES = (("channels.jsonl", "session"), ("credentials.jsonl", "credential"))
#: The kinds this table knows. A new kind is a value here plus whoever writes it.
ROW_TYPES = ("session", "credential", "artifact")


def path_for(run_dir) -> Path:
    return Path(run_dir) / HARVEST_NAME


def record(run_dir, row_type, row) -> dict:
    """Append one harvest row; the caller owns the row own shape and validation."""
    tagged = dict(row)
    tagged["row_type"] = str(row_type)
    path = path_for(run_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as stream:
        stream.write((json.dumps(tagged, ensure_ascii=False) + "\n").encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())
    return tagged


def _lines(path):
    """(rows, saw_a_bad_line, last_line_unterminated) for one ledger file."""
    if not path.is_file():
        return [], False, False
    text = path.read_text(encoding="utf-8")
    unterminated = bool(text) and not text.endswith("\n")
    rows, bad = [], False
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            bad = True
            continue
        if isinstance(row, dict):
            rows.append(row)
        else:
            bad = True
    return rows, bad, unterminated


def read(run_dir, *, row_type=None, strict=False) -> list:
    """Every harvest row, oldest first; a missing tag counts as the file own kind.

    Rows from the legacy files are tagged on the way out, so a caller never has to know which
    layout it is reading. With ``strict`` a malformed line - or a final line that was never
    terminated, i.e. a write that died mid-row - is an error instead of being skipped: a caller
    whose evidence must be intact (credentials) says so, and one that is walking handles does not.
    """
    path = path_for(run_dir)
    rows, bad, unterminated = [], False, False
    if path.is_file():
        rows, bad, unterminated = _lines(path)
        for row in rows:
            row.setdefault("row_type", "session")
    else:
        for name, kind in LEGACY_FILES:
            part, part_bad, part_unterminated = _lines(Path(run_dir) / name)
            for row in part:
                row.setdefault("row_type", kind)
                rows.append(row)
            bad = bad or part_bad
            unterminated = unterminated or part_unterminated
    if strict and (bad or unterminated):
        raise ValueError("LEDGER_INVALID")
    if row_type is None:
        return rows
    return [row for row in rows if str(row.get("row_type")) == str(row_type)]
