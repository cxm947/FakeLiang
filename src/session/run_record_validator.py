"""编排记录与节点归属验证。"""

from copy import deepcopy
from src.orchestration.model import PASS, UNKNOWN

def new_sessions():
    return {"run": None, "attempts": {}, "references": []}


def start_run(sessions, run_id):
    sessions["run"] = {"id": run_id, "simulation": True,
                       "phase": "planner", "status": "验证中"}


def start_attempt(sessions, run_id, node_id, attempt_id):
    sessions["attempts"][attempt_id] = {"id": attempt_id, "node_id": node_id,
        "run_id": run_id, "simulation": True, "phase": "pre", "status": "验证中"}


def set_phase(sessions, attempt_id, name):
    sessions["attempts"][attempt_id]["phase"] = name


def commit_check(sessions, attempt_id, result):
    sessions["attempts"][attempt_id]["check"] = deepcopy(result)
    sessions["references"].extend(deepcopy(result["changes"]))


def finish_attempt(sessions, attempt_id):
    sessions["attempts"][attempt_id].update(status="终态", saved_position="提交完成")


def finish_run(sessions):
    sessions["run"].update(status="终态", saved_position="整轮收尾")


def check(node_record, run_id, node_id, attempt_id):
    records = node_record.get("sessions", [])
    if not isinstance(records, list):
        return {"result": UNKNOWN, "changes": [], "reason": "模拟记录未知"}
    changes, seen = [], set()
    for record in records:
        if not isinstance(record, dict):
            changes.append({"result": UNKNOWN, "reason": "模拟记录未知"})
            continue
        source_id = record.get("source_id")
        key = (run_id, attempt_id, str(source_id))
        if key in seen:
            continue
        seen.add(key)
        valid = (source_id is not None and record.get("available") is True
                 and record.get("run_id", key[0]) == key[0]
                 and record.get("attempt_id", attempt_id) == attempt_id
                 and record.get("node_id", node_id) == node_id)
        changes.append({"key": list(key), "record": deepcopy(record), "usable": bool(valid),
                        "result": PASS if valid else UNKNOWN,
                        "change": "新增" if valid else "未知"})
    result = PASS if all(item["result"] == PASS for item in changes) else UNKNOWN
    return {"result": result, "changes": changes, "reason": "无变更" if not changes else "模拟记录验证"}

