"""Reporting: the walk's own ledger — header, per node rows, announced goals, closing tally."""
from __future__ import annotations

import json
import os
from pathlib import Path

from graph import criteria as graph_criteria
from orchestration.graph_view import _node_sort_key, graph_nodes
from orchestration.session_flow import card_declares_delivery
from runtime import session_registry
from runtime.lean import mask_secrets

from agents.planner import service as planning
from .verification import assessment


#: 人读进度日志（爷爷 2026-10-06 的口径：看日志就知道到哪了、哪成了哪没成）。
#: 它不是新的事实来源：每一行都由这一轮自己的产物渲染（journal.node_section）。
WALK_FILE = "walk.txt"

def migration_note(*, recorded):
    """Report the explicit session handoff without launching an implicit migration recipe."""
    if not recorded:
        return None
    return {"state": "registered", "reason": "CONSOLE_SESSION_OBSERVED",
            "handles": [row["channel_id"] for row in recorded],
            "sessions": [row["session_id"] for row in recorded]}


def plan_identity(document, state):
    """Which plan this is, which steps are mandatory, and what each one has to produce.

    A claim of "the whole plan passed" has to say *which* plan and *which* steps (bridge
    2026-10-08): a list of node ids is not a plan, and successes from different shapes of the plan
    are not one trace. The contracts come from the graph itself, the statuses from this round.
    """
    from graph import criteria as graph_criteria

    steps = []
    for node in graph_nodes(document):
        node_id = str(node["id"])
        produced = graph_criteria.to_produce(document, node_id)
        steps.append({"node_id": node_id, "rule": str(node.get("rule_desc") or ""),
                      "must_produce": [str(row.get("fact") or row.get("ref")) for row in produced],
                      "status": str((state.get(node_id) or {}).get("status") or "not_attempted")})
    source = document.get("source_graph") if isinstance(document, dict) else None
    source = source if isinstance(source, dict) else {}
    return {"source": str(source.get("file") or source.get("path") or ""),
            "schema_version": str(document.get("schema_version") or ""),
            "final_goal": [str(item) for item in (document.get("final_goal") or [])],
            "mandatory_steps": steps}


def plan_passed(summary):
    """Judge the recorded plan; stopping scheduling does not establish success."""
    plan = summary.get("plan") or {}
    steps = plan.get("mandatory_steps") or []
    expected = {str(ref) for ref in (plan.get("final_goal") or [])}
    goals = summary.get("final_goal") or []
    return (bool(steps)
            and all(row.get("status") == "proved" for row in steps)
            and bool(expected)
            and {str(row.get("node_id")) for row in goals} == expected
            and all(row.get("established") is True for row in goals)
            and not summary.get("planner_error"))


def undecided_rows(state, root):
    """Everything this round did **not** settle: unverified receipts and unconfirmed deliveries.
    A pass may be claimed next to these, but never instead of
    them (bridge 2026-10-08: 未决与遗留清单必须如实列出)."""
    rows = []
    for node_id, row in state.items():
        verification = row.get("verification") or {}
        if verification.get("receipt_issues"):
            rows.append({"node": node_id, "kind": "receipt",
                         "issues": [str(item) for item in verification["receipt_issues"]]})
        entry = ((row.get("migration") or {}).get("entry") or {})
        if entry and str(entry.get("state") or "") != "registered":
            reason = str(entry.get("reason") or entry.get("state"))
            #: "没东西可交"不是未决：前提类节点本来就不产出会话，声明里也没说要交。
            applicable = (reason != "NO_EXEC_OUTPUT_FACT"
                          and (reason != "NO_REGISTERED_OUTPUT_SESSION"
                               or card_declares_delivery(row.get("card"))))
            if applicable:
                rows.append({"node": node_id, "kind": "delivery", "reason": reason})
        position = row.get("position_error")
        if position:
            rows.append({"node": node_id, "kind": "position",
                         "reason": str(position.get("reason") or "")})
        entry_setup = row.get("entry_setup")
        if isinstance(entry_setup, dict) and str(entry_setup.get("state")) == "failed":
            rows.append({"node": node_id, "kind": "entry",
                         "reason": str(entry_setup.get("reason") or "")})
    return rows


def node_row(*, proved, card, reuse, why, result, run_dir, migration=None, probe_note=""):
    """One node's state row, migration note included.

    The note is not decoration: a proved exec fact whose handle cannot carry a command has been
    handed to the resident console (or the refusal is named), and a reader of the summary has to
    be able to see which of the two happened without reading the per-node directory.
    """
    row = {"status": "proved" if proved else "stopped", "card": card["id"],
           "reused_channel": (reuse or {}).get("channel_id", ""),
           "reuse_reason": why,
           "reason": str(result.get("reason") or ""),
           "claimed_verdict": str(result.get("claimed_verdict") or ""),
           "run_dir": str(run_dir)}
    if migration is not None:
        row["migration"] = migration
    if probe_note:
        row["carrier_probe"] = probe_note
    return row


def walk_header(root, graph_label):
    """人读日志的开头：写一次，后面每个节点追加一段。"""
    return "\n".join(["=" * 78, "验证轮次：%s" % root.name,
                       "攻击图：%s" % graph_label,
                       "（每完成一个节点追加一段；哪成了、哪没成、卡在第几步都在这份里）",
                       "=" * 78, ""])


def walk_node(root, node_id, *, state, planner_notes, order, document, graph_label,
              secrets=()) -> None:
    """把一个节点的人读那一段追加进 ``<run>/walk.txt``，并往标准输出回一短行。

    写之前先按这一轮的已知秘密脱敏：失败原因里可能带着驱动异常原文（里面就有秘密），
    人读日志和标准输出一样不能成为泄露面（2026-10-06 的用例当场抓到过这一条）。
    """
    row = state.get(node_id) or {}
    status = str(row.get("status") or "")
    try:
        import journal
        live = {"nodes": state, "planner": planner_notes,
                "proved": [key for key, item in state.items() if item.get("status") == "proved"],
                "order": list(order)}
        section = journal.node_section(node_id, plan=live, channels=session_registry.snapshot(root),
                                       graph=document, run_dir=root)
        path = root / WALK_FILE
        if not path.exists():
            path.write_text(walk_header(root, graph_label), encoding="utf-8", newline="\n")
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(mask_secrets("\n".join(section), list(secrets)) + "\n")
    except Exception as error:              # 写人看的东西失败，不该拖死一次真跑
        print("walk log skipped: %s" % str(error)[:120], flush=True)
        return
    #: **每收一格就重写一次模型转录**（爷爷 2026-10-07：改了 A 要知道会不会影响 B）。
    #: 原先只在一轮验证收尾那一刻写一次，中途被掐掉就只剩 `events.jsonl`：人没法在两轮之间逐发对齐，
    #: 而这正是"左右影响"唯一能当场抓住的办法。每格重写的代价只是读几个小 JSONL。
    try:
        import node_transcript  # noqa: E402 - same directory, imported late
        node_transcript.write_all(os.path.basename(str(root).rstrip("/\\")))
    except Exception as error:              # 转录失败不该拖死真跑
        print("transcript skipped: %s" % str(error)[:120], flush=True)
    block = row.get("verification") or {}
    verify_note = ""
    if isinstance(block, dict) and block.get("state"):
        if block.get("state") == "verified":
            tally = {}
            for item in block.get("facts") or ():
                tally[item.get("verdict")] = tally.get(item.get("verdict"), 0) + 1
            verify_note = " · 验证 " + "、".join("%s×%d" % (k, v) for k, v in sorted(tally.items()))
        else:
            verify_note = " · 验证未成（%s）" % block.get("state")
    print(mask_secrets("[进度] node %s · %s · %s%s%s"
                       % (node_id, row.get("card") or "-",
                          journal.STATUS_CN.get(status, status or "-"),
                          ("（" + str(row.get("reason")) + "）") if row.get("reason") else "",
                          verify_note),
                       list(secrets)), flush=True)


def announce_goals(root, goals, *, secrets=()) -> None:
    """把终点结论说给人听，并追加进人读日志（walk.txt）。没成立就说得明明白白。"""
    if not goals:
        return
    parts = []
    for row in goals:
        parts.append("%s %s = %s%s" % (row.get("node_id"), row.get("fact") or "-",
                                       "成立" if row.get("established") else "未成立",
                                       "" if row.get("established")
                                       else "（%s）" % str(row.get("reason") or "")[:120]))
    line = mask_secrets("[终点] " + "｜".join(parts), list(secrets))
    print(line, flush=True)
    try:
        with (Path(root) / WALK_FILE).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("\n" + line + "\n")
    except OSError:
        pass


def walk_summary(root, state, *, secrets=()) -> None:
    """跑完（或停下）时给一份一行小账：哪成了、哪没成。"""
    tally = {}
    for row in state.values():
        tally[str(row.get("status"))] = tally.get(str(row.get("status")), 0) + 1
    proved = sorted([key for key, row in state.items() if row.get("status") == "proved"],
                    key=_node_sort_key)
    not_proved = sorted([key for key, row in state.items() if row.get("status") != "proved"],
                        key=_node_sort_key)
    line = mask_secrets("[小结] 成立 %d（%s）｜没成立 %s｜明细 %s"
                        % (len(proved), "、".join(proved) or "无",
                           "、".join("%s=%s" % (key, state[key].get("status"))
                                     for key in not_proved) or "无",
                           "、".join("%s:%d" % (key, value)
                                     for key, value in sorted(tally.items()))), list(secrets))
    print(line, flush=True)
    try:
        with (root / WALK_FILE).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("\n" + line + "\n")
    except OSError:
        pass


def settle_walk(
    *,
    root,
    document,
    graph_label,
    host_map,
    state,
    order,
    planner_notes,
    planner_trace,
    secrets,
    render_journal,
    write_transcripts,
):
    walk_summary(root, state, secrets=secrets)
    goals = assessment.final_goal_rows(
        document,
        state,
        rows=session_registry.snapshot(root),
        host_map=host_map,
    )
    announce_goals(root, goals, secrets=secrets)

    if planner_notes or planner_trace:
        rows = [dict(item, kind="pick") for item in planner_notes]
        rows += [dict(item, kind="call") for item in planner_trace]
        (root / "planner.jsonl").write_text(
            "\n".join(
                json.dumps(item, ensure_ascii=False) for item in rows
            ) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    blocked_upstream = {}
    for node_id, row in state.items():
        linkage = []
        for fact in graph_criteria.node_criteria(document, node_id):
            producers = [
                str(item) for item in (fact.get("produced_by") or [])
            ]
            linkage.append(
                {
                    "ref": str(fact.get("ref") or ""),
                    "producers": producers,
                    "proved_by": [
                        item for item in producers
                        if (state.get(item) or {}).get("status") == "proved"
                    ],
                }
            )
        row["linkage"] = linkage

    for node in graph_nodes(document):
        node_id = str(node["id"])
        if node_id in state:
            continue
        refusal = planning.choice_refusal(
            document, node_id, state, host_map=host_map
        )
        if refusal is None:
            continue
        missing = refusal.get("facts") or []
        missing_refs = {fact["ref"] for fact in missing}
        waiting = sorted(
            {
                producer
                for fact in graph_criteria.node_criteria(document, node_id)
                if fact["ref"] in missing_refs
                for producer in fact["produced_by"]
            }
        )
        blocked_upstream[node_id] = waiting
        state[node_id] = {
            "status": "blocked_upstream",
            "waiting_for": waiting,
            "missing_facts": missing,
        }

    for node_id, row in state.items():
        if row["status"] != "proved":
            row["blocks"] = [
                consumer
                for consumer, waiting in blocked_upstream.items()
                if node_id in waiting
            ]

    pending = [
        str(node["id"]) for node in graph_nodes(document)
        if str(node["id"]) not in state
    ]
    summary = {
        "order": order,
        "planner": planner_notes,
        "nodes": state,
        "not_attempted": pending,
        "proved": sorted(
            key for key, row in state.items() if row["status"] == "proved"
        ),
        "stopped": sorted(
            key for key, row in state.items() if row["status"] == "stopped"
        ),
        "blocked": sorted(
            key for key, row in state.items() if row["status"] == "blocked"
        ),
        "blocked_upstream": blocked_upstream,
        "final_goal": goals,
        "plan": plan_identity(document, state),
        "undecided": undecided_rows(state, root),
        "note": (
            "the model chooses attempts; unavailable premises are reported from "
            "bound fact assessments, independently of producer step status"
        ),
    }
    summary["passed"] = plan_passed(summary)
    exit_code = 0 if summary["passed"] else 2
    summary = mask_secrets(summary, secrets)
    (root / "plan_result.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    try:
        text = render_journal(root, graph_path=graph_label)
        (root / "walk.txt").write_text(
            text, encoding="utf-8", newline="\n"
        )
        with (Path(root).parent / "WALK-JOURNAL.txt").open(
            "a", encoding="utf-8", newline="\n"
        ) as handle:
            handle.write(text + "\n")
        print("走图日志：" + str(root / "walk.txt"))
        write_transcripts(os.path.basename(str(root).rstrip("/\\")))
    except Exception as error:
        print("journal skipped: " + str(error)[:160])

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return exit_code
