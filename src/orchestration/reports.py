"""模拟记录的四份输出与整轮验证。"""

from copy import deepcopy
import json
import os
from pathlib import Path
from uuid import uuid4


KINDS = ("log", "nodes", "state", "summary")
COMPLETE_REQUIRES = ("四份模拟记录均存在且轮编号、内容标识和最终状态版本一致，"
                     "并且最后的 summary.md 明确整轮完整通过" )
SUFFIXES = {
    "state": "state.json",
    "nodes": "nodes.json",
    "log": "log.jsonl",
    "summary": "summary.md",
}


def output_paths(output_dir, graph_name, run_id):
    """取得四份平铺模拟记录的位置。"""
    identifier = run_id["id"] if isinstance(run_id, dict) else str(run_id)
    for component in (str(graph_name), identifier):
        if not component or component in {".", ".."} or any(
            character in component for character in '/\\:*?"<>|'
        ):
            raise ValueError("模拟记录编号不通过")
    root = Path(output_dir)
    return {
        kind: root / f"{graph_name}.{identifier}.{suffix}"
        for kind, suffix in SUFFIXES.items()
    }


def validate_paths(paths):
    """开始前验证位置唯一，已有模拟记录不覆盖。"""
    if set(paths) != set(SUFFIXES):
        raise ValueError("模拟记录清单不通过")
    resolved = [Path(path).resolve() for path in paths.values()]
    if len(set(resolved)) != len(SUFFIXES):
        raise ValueError("模拟记录位置不通过")
    if len({path.parent for path in resolved}) != 1:
        raise ValueError("模拟记录位置不通过")
    for path in resolved:
        if path.exists():
            raise FileExistsError(f"模拟记录已存在：{path.name}")


def _metadata(state):
    return {
        "content_id": state["graph"]["content_id"],
        "run_id": state["run_id"]["id"],
        "state_version": state["state_version"],
        "simulation": True,
        "complete_requires": COMPLETE_REQUIRES,
    }


def _aggregate(state, complete):
    rows = state.get("goals", {}).get("nodes", {})
    values = [row.get("result", "未知") for row in rows.values()]
    if complete and len(values) == 2 and all(value == "通过" for value in values):
        return "通过"
    if complete and len(values) == 2 and all(value == "不通过" for value in values):
        return "不通过"
    return "未知"


def _counts(state):
    counts = {"通过": 0, "不通过": 0, "未知": 0, "未终态": 0}
    for row in state.get("node_states", {}).values():
        if row.get("progress") != "终态" or not row.get("terminal_record"):
            counts["未终态"] += 1
        else:
            counts[row.get("result", "未知")] += 1
    return counts


def _summary(state):
    metadata = _metadata(state)
    outputs = state["outputs"]
    counts = _counts(state)
    lines = [
        "# 模拟验证记录",
        "",
        f"轮编号：`{metadata['run_id']}`",
        f"内容标识：`{metadata['content_id']}`",
        f"最终状态版本：`{metadata['state_version']}`",
        "模拟标记：`true`",
        f"整轮完整：{'通过' if outputs['complete'] else '不通过'}",
        f"目标节点汇总：{state['goals']['result']}",
        f"停止原因：{state.get('stop_reason') or '未知'}",
        "",
        "| 目标节点 | 事实评价 | 终态 | 原因 |",
        "| --- | --- | --- | --- |",
    ]
    for node_id, row in state.get("goals", {}).get("nodes", {}).items():
        fact = row.get("fact_result", row.get("fact_evaluation", "未知"))
        if isinstance(fact, dict):
            fact = fact.get("result", "未知")
        reason = str(row.get("reason", "未知")).replace("|", "／").replace("\n", " ")
        lines.append(f"| {node_id} | {fact} | {row.get('result', '未知')} | {reason} |")
    lines.extend([
        "",
        "| 节点结果 | 数量 |",
        "| --- | ---: |",
        *(f"| {result} | {number} |" for result, number in counts.items()),
        "",
        f"实际尝试数量：{len(state.get('attempts', []))}",
        f"验证完成数量：{sum(bool(row.get('action_completed')) for row in state.get('coverage', {}).values())}",
        "",
        "| 模拟记录 | 位置 | 保存 |",
        "| --- | --- | --- |",
    ])
    for kind in SUFFIXES:
        saved = "通过" if outputs["saved"].get(kind) else "不通过"
        lines.append(f"| {SUFFIXES[kind]} | `{outputs['paths'][kind]}` | {saved} |")
    lines.extend([
        "",
        "缺项：" + ("、".join(outputs["missing"]) or "无"),
        "",
        "完整性验证：" + COMPLETE_REQUIRES + "。",
        "",
        "模拟记录形状：`schema_version`、`simulation`、`nodes`。",
        "事实全部从未知开始，只来自本格 pre／action／post 验证。",
        "`pre` 是数组；逐条包含 `fact_id`、`节点类型`、`result`、`使用的skill`、`返回的结果`。",
        "前提取本节点父 LEAF；全通过才通过，任一不通过则不通过，其余未知。",
        "每条验证另记 `run_id`、`node_id`、`attempt_id`、`fact_version`。",
        "`nodes` 以节点编号为键，每项含 `pre`、`action`、`post`；前提不通过或未知均不进入 action。",
        "`action` 与 `post` 均含 `node_id`、`节点类型`、`result`、`evidence`、`验证该节点的skill`、`返回的结果`。",
        "`action` 的编号为本 AND 节点；`post` 的编号为本节点产出的 OR 事实。",
        "`post.evidence` 只接受 `nodes/{本节点}/action`，并须有本格独立返回依据，不能自引或引用别格。",
        "结果只用通过、不通过、未知。完整形状见 `docs/verification.md`。",
        "",
    ])
    return "\n".join(lines).encode("utf-8")


def _json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _payloads(state):
    metadata = _metadata(state)
    lines = []
    for event in state.get("journal", []):
        entry = deepcopy(event)
        if "state_version" in entry:
            entry["recorded_state_version"] = entry["state_version"]
        entry.update(metadata)
        lines.append(json.dumps(entry, ensure_ascii=False))
    nodes = {
        **metadata,
        "node_states": state.get("node_states", {}),
        "coverage": state.get("coverage", {}),
        "goals": state.get("goals", {}),
        "coverage_objective": state.get("coverage_objective", {}),
        "outputs": {key: value for key, value in state["outputs"].items()
                    if key not in {"attempts", "errors"}},
        "stop_reason": state.get("stop_reason"),
    }
    return {
        "log": (("\n".join(lines) + "\n") if lines else "").encode("utf-8"),
        "nodes": _json_bytes(nodes),
        "state": _json_bytes(state),
        "summary": _summary(state),
    }


def _write_atomic(path, content, *, replace=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / (".verify-" + uuid4().hex + ".tmp")
    created = False
    try:
        with temporary.open("xb") as stream:
            created = True
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        elif os.name == "nt":
            os.rename(temporary, path)
        else:
            os.link(temporary, path)
            temporary.unlink()
        created = False
    finally:
        if created:
            temporary.unlink(missing_ok=True)

def publish(state, paths, writer=None, budget=None):
    """先保存节点记录，最后发布整轮记录；每项至多保存两次。"""
    validate_paths(paths)
    paths = {kind: Path(path) for kind, path in paths.items()}
    state["state_version"] = state.get("state_version", 0) + 1
    maximum = min(2, max(0, int(state.get("limits", {}).get("save_attempts", 2))))
    previous_saves = state.setdefault("counters", {}).get("saves", 0)
    coverage_complete = bool(state.get("outputs", {}).get("coverage_complete", False))
    state["outputs"] = {
        "paths": {kind: str(path) for kind, path in paths.items()},
        "saved": {kind: False for kind in paths},
        "versions": {kind: None for kind in paths},
        "attempts": {kind: 0 for kind in paths},
        "final_state_version": state["state_version"],
        "missing": list(KINDS),
        "coverage_complete": coverage_complete,
        "complete": False,
        "published": False,
        "publication_gate": "summary",
        "complete_requires": COMPLETE_REQUIRES,
        "errors": {},
        "budget_exhausted": False,
    }
    owned, unavailable = set(), set()
    saved_state = None

    def save(kind, content):
        nonlocal saved_state
        outputs = state["outputs"]
        if budget is not None and not budget():
            outputs["budget_exhausted"] = True
            return False
        if outputs["attempts"][kind] >= maximum:
            return False
        outputs["attempts"][kind] += 1
        state["counters"]["saves"] = previous_saves + sum(outputs["attempts"].values())
        try:
            if writer is None:
                _write_atomic(paths[kind], content, replace=kind in owned)
            else:
                writer(paths[kind], content)
            if paths[kind].read_bytes() != content:
                raise OSError("模拟记录保存不通过")
            owned.add(kind)
            outputs["saved"][kind] = True
            outputs["versions"][kind] = state["state_version"]
            if kind == "state":
                saved_state = json.loads(content)
            return True
        except Exception as error:
            outputs["errors"][kind] = {"reason": "保存不通过", "type": type(error).__name__}
            return False

    def prospective():
        candidate = deepcopy(state)
        candidate["outputs"]["saved"] = {kind: kind not in unavailable for kind in paths}
        candidate["outputs"]["versions"] = {
            kind: state["state_version"] if kind not in unavailable else None for kind in paths
        }
        candidate["outputs"]["missing"] = [kind for kind in KINDS if kind in unavailable]
        candidate["outputs"]["published"] = not unavailable
        candidate["outputs"]["complete"] = coverage_complete and not unavailable
        for kind in paths:
            if not state["outputs"]["saved"][kind] and kind not in unavailable:
                candidate["outputs"]["attempts"][kind] += 1
        candidate["counters"]["saves"] = previous_saves + sum(candidate["outputs"]["attempts"].values())
        candidate.setdefault("goals", {})["result"] = _aggregate(candidate, candidate["outputs"]["complete"])
        return candidate

    def refresh_before_summary():
        candidate = prospective()
        if (saved_state is not None and saved_state["counters"] == candidate["counters"]
                and saved_state["outputs"] == candidate["outputs"]):
            return
        if state["outputs"]["attempts"]["state"] < maximum:
            candidate["outputs"]["attempts"]["state"] += 1
            candidate["counters"]["saves"] += 1
            if save("state", _payloads(candidate)["state"]):
                return
        unavailable.add("state")
        state["outputs"]["saved"]["state"] = False
        state["outputs"]["versions"]["state"] = None
        state["outputs"]["errors"]["state"] = {"reason": "保存不通过"}
        state["stop_reason"] = "保存不通过"

    success = True
    for kind in KINDS:
        saved = False
        while state["outputs"]["attempts"][kind] < maximum:
            if kind == "summary":
                refresh_before_summary()
                if state["outputs"]["budget_exhausted"]:
                    break
            payloads = _payloads(prospective())
            if save(kind, payloads[kind]):
                saved = True
                break
            if state["outputs"]["budget_exhausted"]:
                break
        if not saved:
            success = False
            break

    outputs = state["outputs"]
    outputs["missing"] = [kind for kind in KINDS if not outputs["saved"][kind]]
    outputs["published"] = success and not outputs["missing"]
    outputs["complete"] = outputs["published"] and coverage_complete
    state.setdefault("goals", {})["result"] = _aggregate(state, outputs["complete"])
    if not success:
        state["stop_reason"] = "整轮收尾到限" if outputs["budget_exhausted"] else "保存不通过"
        for kind in ("nodes", "state"):
            if kind in owned and outputs["attempts"][kind] < maximum:
                candidate = deepcopy(state)
                candidate["outputs"]["attempts"][kind] += 1
                candidate["counters"]["saves"] += 1
                save(kind, _payloads(candidate)[kind])
        outputs["complete"] = False
        outputs["published"] = False
    return state
