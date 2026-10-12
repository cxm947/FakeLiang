#!/usr/bin/env python3
"""Read checkpoint and boundary status without opening an owner or resending work."""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from orchestration.langgraph_runner import checkpoint_identity


def read_state(root, materials=None):
    path, thread_id = checkpoint_identity(
        root=root, repository=ROOT, materials_dir=materials)
    if not path.is_file():
        raise ValueError("WALK_CHECKPOINT_MISSING")
    serializer = JsonPlusSerializer(pickle_fallback=False)
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
        row = connection.execute(
            "SELECT type, checkpoint FROM checkpoints "
            "WHERE thread_id=? AND checkpoint_ns='' "
            "ORDER BY checkpoint_id DESC LIMIT 1", (thread_id,)).fetchone()
        if row is None:
            raise ValueError("WALK_CHECKPOINT_MISSING")
        checkpoint = serializer.loads_typed((row[0], bytes(row[1])))
        state = dict(checkpoint.get("channel_values") or {})
        initial = state.pop("__start__", None)
        if "walk" not in state and isinstance(initial, dict):
            state = dict(initial, **state)
        pending = connection.execute(
            "SELECT channel, type, value FROM writes "
            "WHERE thread_id=? AND checkpoint_ns='' AND checkpoint_id=? "
            "ORDER BY task_id, idx", (thread_id, checkpoint["id"])).fetchall()
        completed = any(item[0] in {"walk", "route"} for item in pending)
        for channel, kind, value in pending:
            if channel in {
                    "walk", "selected_node_id", "route", "attempts", "exhausted_nodes",
                    "cell", "stop_reason", "active_step", "model_calls",
                    "planner_pending", "run_binding"}:
                state[channel] = serializer.loads_typed((kind, bytes(value)))
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='runtime_progress'").fetchone()
        if exists:
            progress = connection.execute(
                "SELECT checkpoint_id, state FROM runtime_progress "
                "WHERE thread_id=?", (thread_id,)).fetchone()
            if progress and progress[0] == checkpoint.get("id") and not completed:
                value = json.loads(progress[1])
                if not isinstance(value, dict):
                    raise ValueError("WALK_PROGRESS_INVALID")
                state.update(value)
    return path, state


def boundaries(root):
    output = []
    phases = {"before_commit", "committing", "after_commit", "artifacts_saved"}
    for path in sorted(Path(root).glob("node*/events.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row.get("kind") == "commit" and row.get("phase") in phases:
                output.append({"node": path.parent.name,
                               "call_id": str(row.get("call_id") or ""),
                               "phase": row["phase"]})
    receipt_phases = {"receiving", "received", "registering", "registered", "probing", "probed"}
    for path in sorted(Path(root).rglob("delivery/*/plan.json")):
        plan = json.loads(path.read_text(encoding="utf-8"))
        phase = plan.get("receipt_phase")
        if phase in receipt_phases:
            output.append({"delivery_owner": path.parent.name, "phase": phase})
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_root", help="Original run-root path or output/runs label")
    #: 与批次 2 的状态读数一致：材料目录决定 checkpoint 身份，缺省必须是同一个。
    parser.add_argument("--materials-dir",
                        default=str(Path(os.environ["TEMP"]) / "agv_materials"))
    parser.add_argument("--expect-converged", type=int, metavar="N")
    args = parser.parse_args(argv)
    root = Path(args.run_root)
    if not root.is_absolute():
        direct = ROOT / root
        root = direct if direct.is_dir() else ROOT / "output" / "runs" / root
    materials = Path(args.materials_dir).resolve() if args.materials_dir else None
    try:
        path, state = read_state(root.resolve(), materials)
        order = len((state.get("walk") or {}).get("order") or [])
        route = state.get("route") if state.get("route") in {"planner", "step", "done"} else "unknown"
        reason = state.get("stop_reason")
        if reason not in {"converged", "blocked", "budget_exhausted"}:
            reason = ""
        print("order=%s; route=%s; stop_reason=%s" % (order, route, reason))
        print("checkpoint=" + str(path))
        print("boundaries=" + json.dumps(boundaries(root), sort_keys=True))
        if args.expect_converged is not None:
            return 0 if (order == args.expect_converged and route == "done"
                         and reason == "converged") else 2
        return 0
    except (ValueError, OSError, sqlite3.Error, TypeError, KeyError) as error:
        print("CHECKPOINT_UNREADABLE: " + type(error).__name__)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
