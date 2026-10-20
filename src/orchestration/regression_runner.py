"""固定模拟记录的四相编排与唯一保存入口。"""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
import time
import uuid

from .model import FAIL, PASS, UNKNOWN, evaluate_fact, prerequisite, validate_graph
from src.session import run_record_validator
from src.agents.executor.simulation import action
from src.agents.planner import build_input, load_planner_prompt, planner
from src.agents.planner.agent import PlannerExhausted, PlannerBudgetExceeded
from src.agents.planner.schema import PlannerInput
from src.agents.planner.validation import ready_nodes
from src.agents.planner.simulation import SimulationChatModel
from langgraph.graph import StateGraph, START, END
from typing import TypedDict
from src.agents.post_verifier import post
from src.agents.pre_verifier import pre
from .reports import output_paths, publish, validate_paths

SUGGESTION_EXTRA = 1
ADMISSION_MULTIPLIER = 1
SCAN_EXTRA = 1
CELL_SECONDS = 30
CLOSE_SECONDS = 10
RUN_SECONDS = 300
ROUND_CLOSE_SECONDS = 10
RECONCILE_ATTEMPTS = 1
SAVE_ATTEMPTS = 2


def default_limits(count):
    return {"suggestions": count + SUGGESTION_EXTRA,
            "admissions": count * ADMISSION_MULTIPLIER, "scans": count + SCAN_EXTRA,
            "cell_seconds": CELL_SECONDS, "close_seconds": CLOSE_SECONDS,
            "run_seconds": RUN_SECONDS, "round_close_seconds": ROUND_CLOSE_SECONDS,
            "reconcile_attempts": RECONCILE_ATTEMPTS, "save_attempts": SAVE_ATTEMPTS}


def _row():
    return {"progress": "未验证", "result": UNKNOWN, "reason": "未验证", "evidence": [],
            "terminal_record": None, "current_evaluation": None, "attempted": False,
            "action_completed": False, "closure_source": None, "time": None}


class _Run:
    def __init__(self, graph, simulation, run_id, limits, clock, started=None, planner_model=None,
                 planner_structured_method=None):
        self.planner_structured_method = planner_structured_method
        suggestions = simulation.get("suggestions", []) if isinstance(simulation, dict) else []
        self.planner_model = planner_model if planner_model is not None else SimulationChatModel(
            responses=[{"next_node_id": value, "status": "finish" if value is None else "continue",
                        "why": "离线建议记录"} for value in suggestions], policy=True)
        self.clock = clock or time.monotonic
        self.started = self.clock() if started is None else started
        self.cell_started = None
        self.close_started = None
        self.round_close_started = None
        self.last_scan = None
        self.configuration = limits or {}
        graph_copy = deepcopy(graph)
        content = json.dumps(graph_copy, sort_keys=True, ensure_ascii=False).encode("utf-8")
        self.state = {
            "run_id": {"id": run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
                       + "-" + uuid.uuid4().hex[:8],
                       "started_at": datetime.now(timezone.utc).isoformat(), "simulation": True},
            "graph": {"document": graph_copy, "version": graph.get("schema_version")
                      if isinstance(graph, dict) else None,
                      "content_id": hashlib.sha256(content).hexdigest(), "simulation": True},
            "coverage_objective": {}, "dependencies": {},
            "plan": {"order": [], "selected": None, "reason": None, "unselected": {},
                     "rejected_suggestions": [], "history": [], "stop_reason": None,
                     "planner_input": None, "planner_output": None, "planner_prompt": None,
                     "mode": "离线模拟模型" if planner_model is None else "注入的 LangChain 模型"},
            "phase": {"name": "planner", "saved_position": "输入验证"},
            "current_node": None, "simulation": deepcopy(simulation), "facts": {},
            "node_states": {}, "attempts": [], "waiting": {}, "pending_result": None,
            "post_records": [], "sessions": run_record_validator.new_sessions(),
            "journal": [], "coverage": {}, "goals": {"nodes": {}, "result": UNKNOWN},
            "counters": {"suggestions": 0, "admissions": 0, "scans": 0,
                         "reconciliations": 0, "saves": 0, "terminal_count": 0,
                         "save_attempts": {}, "reconcile_attempts": {}},
            "limits": default_limits(0), "stop_reason": None, "state_version": 0,
            "outputs": {"coverage_complete": False, "complete": False, "missing": [],
                        "paths": {}, "saved": {}, "final_state_version": None},
        }

    def _save(self, event, change=None, **detail):
        """每次保存先构造完整视图，再以单一引用使记录可见。"""
        updated = deepcopy(self.state)
        if change:
            change(updated)
        updated["coverage"] = {nid: deepcopy(updated["node_states"][nid])
                               for nid in updated["dependencies"].get("and_ids", [])}
        updated["state_version"] += 1
        sequence = len(updated["journal"]) + 1
        updated["counters"]["saves"] += 1
        updated["counters"]["save_attempts"][str(sequence)] = 1
        updated["journal"].append({
            "seq": sequence, "run_id": updated["run_id"]["id"], "simulation": True,
            "event": event, "phase": updated["phase"]["name"],
            "saved_version": updated["state_version"], "elapsed": self.clock() - self.started,
            "node_evaluations": {nid: deepcopy(row["current_evaluation"])
                for nid, row in updated["node_states"].items()
                if row["current_evaluation"] != self.state["node_states"].get(nid, {}).get("current_evaluation")},
            **deepcopy(detail),
        })
        self.state = updated

    def _stop(self, reason):
        def change(state):
            state["stop_reason"] = reason
            state["plan"]["stop_reason"] = reason
            state["goals"]["result"] = UNKNOWN
            state["outputs"]["coverage_complete"] = False
        self._save("未完成", change, reason=reason)

    def initialize(self):
        try:
            dependencies = validate_graph(self.state["graph"]["document"])
            simulation = self.state["simulation"]
            if (not isinstance(simulation, dict) or simulation.get("schema_version") != "1.0"
                    or simulation.get("simulation") is not True
                    or not isinstance(simulation.get("nodes"), dict)):
                raise ValueError("模拟记录验证不通过")
            limits = default_limits(len(dependencies["and_ids"]))
            if set(self.configuration) - set(limits):
                raise ValueError("验证上限不通过")
            limits.update(self.configuration)
            for name, value in limits.items():
                if (isinstance(value, bool) or not isinstance(value, (int, float))
                        or not math.isfinite(value) or value < 0):
                    raise ValueError("验证上限不通过")
                if name not in {"cell_seconds", "close_seconds", "run_seconds", "round_close_seconds"}:
                    if not isinstance(value, int):
                        raise ValueError("验证上限不通过")
            if limits["save_attempts"] < 1:
                raise ValueError("保存上限不通过")
        except (ValueError, TypeError, KeyError):
            self._stop("输入验证不通过")
            return False

        def change(state):
            state["dependencies"] = dependencies
            state["plan"]["planner_prompt"] = load_planner_prompt()
            state["limits"] = limits
            state["coverage_objective"] = {
                "content_id": state["graph"]["content_id"], "all_ids": dependencies["all_ids"],
                "and_ids": dependencies["and_ids"], "goal_ids": dependencies["goal_ids"],
                "requirements": dependencies["requirements"], "sources": dependencies["sources"],
                "leaf_requirements": dependencies["leaf_requirements"],
                "derived_requirements": dependencies["derived_requirements"],
                "order": dependencies["order"], "traversal": "依据节点与边 DFS 验证",
                "stop_rule": "终态编号集合等于冻结清单且无可继续节点与待确认验证",
                "goal_rule": "完整且两个目标节点同为通过或同为不通过，其余未知",
                "limits": deepcopy(limits),
            }
            state["node_states"] = {node: _row() for node in dependencies["all_ids"]}
            state["facts"] = {
                fid: {"id": fid, "result": UNKNOWN, "sources": [], "conflict": False,
                      "version": 0, "references": [], "history": [], "definition": deepcopy(record)}
                for fid, record in dependencies["fact_definitions"].items()
            }
            run_record_validator.start_run(state["sessions"], state["run_id"]["id"])
            state["phase"]["saved_position"] = "事实未知"
            self._refresh(state)
        self._save("输入验证通过", change)
        return True

    def _refresh(self, state):
        deps = state["dependencies"]
        changes = []
        for fid, fact in state["facts"].items():
            evaluated = evaluate_fact(fid, state["facts"], state["node_states"], deps)
            signature = (evaluated["result"], evaluated["reason"], evaluated["evidence"])
            if signature != (fact["result"], fact.get("reason"), fact.get("evidence", [])):
                fact["version"] += 1
                fact.update(evaluated)
                fact["conflict"] = evaluated["reason"] == "事实差异"
                fact["references"] = list(evaluated["evidence"])
                fact["history"].append({"version": fact["version"], **deepcopy(evaluated)})
                changes.append({"fact_id": fid, **deepcopy(evaluated), "version": fact["version"]})
        for _ in range(len(deps["and_ids"])+1):
            changed = False
            for nid in deps["and_ids"]:
                row = state["node_states"][nid]
                historical = row["terminal_record"]
                if not historical:
                    continue
                result, reason = historical["result"], historical["reason"]
                required = prerequisite(nid, state["facts"], state["node_states"], deps, derived_only=True)
                validated_outputs = next((item["facts"] for item in state["post_records"]
                                          if item["commit_id"] == historical.get("commit_id")), [])
                if historical["closure_source"] == "post" and (result == PASS or validated_outputs):
                    if required["result"] != PASS:
                        result, reason = required["result"], required["reason"]
                    elif result == PASS:
                        values = [evaluate_fact(fid, state["facts"], state["node_states"], deps)["result"]
                                  for fid in deps["outputs"][nid]]
                        if any(value != PASS for value in values):
                            result, reason = UNKNOWN, "事实当前评价未知"
                changed = changed or (row["result"], row["reason"]) != (result, reason)
                row["result"], row["reason"] = result, reason
                row["current_evaluation"] = {"result": result, "reason": reason,
                                             "version": state["state_version"] + 1,
                                             "evidence": deepcopy(required["evidence"])}
            if not changed:
                break
        state["coverage"] = {nid: deepcopy(state["node_states"][nid]) for nid in deps["and_ids"]}
        goals = {}
        for nid in deps["goal_ids"]:
            fact = evaluate_fact(nid, state["facts"], state["node_states"], deps)
            required = prerequisite(nid, state["facts"], state["node_states"], deps)
            result = fact["result"] if fact["result"] != UNKNOWN else required["result"]
            goals[nid] = {"fact_evaluation": fact, "fact_result": fact["result"], "result": result,
                          "reason": required["reason"], "evidence": required["evidence"],
                          "terminal": state["node_states"][nid]["progress"] == "终态"}
        state["goals"]["nodes"] = goals
        return changes

    def _context(self):
        return build_input(self.state["graph"]["document"], self.state["node_states"],
                           self.state["post_records"])

    def _admissible(self, node_id):
        return node_id in ready_nodes(PlannerInput.model_validate(self._context()),
            {record["node_id"] for record in self.state["attempts"]})

    def scan(self):
        if self.state["counters"]["scans"] >= self.state["limits"]["scans"]:
            self._stop("扫描到限")
            return False
        changes = []
        def change(state):
            state["phase"]["name"] = "planner"
            state["phase"]["saved_position"] = "事实评价"
            state["counters"]["scans"] += 1
            changes.extend(self._refresh(state))
        self._save("事实评价", change)
        if changes:
            self._save("事实变更", changes=changes)
        planner_input = self._context()
        # 保存完整输入快照，再调用带业务纠错的 Planner 子图。
        self._save("planner输入", lambda state: state["plan"].update(
            planner_input=deepcopy(planner_input)), planner_input=planner_input)
        if self.state["counters"]["suggestions"] >= self.state["limits"]["suggestions"]:
            self._stop("建议到限")
            return False
        attempts = []
        def check_budget():
            if self._round_expired():
                raise PlannerBudgetExceeded("整轮到限")
        try:
            self.last_scan = planner(deepcopy(planner_input), model=self.planner_model,
                admitted={item["node_id"] for item in self.state["attempts"]}, trace=attempts,
                before_attempt=check_budget, structured_method=self.planner_structured_method)
        except PlannerBudgetExceeded:
            self._save("planner预算到限", lambda state: state["plan"].update(planner_attempts=attempts),
                       attempts=attempts)
            self._stop("整轮到限")
            return False
        except PlannerExhausted:
            self._save("planner纠错耗尽", lambda state: state["plan"].update(planner_attempts=attempts),
                       attempts=attempts)
            self._stop("Planner 纠错耗尽")
            return False
        except Exception as error:
            self._save("planner调用异常", lambda state: state["plan"].update(planner_attempts=attempts),
                       error_type=type(error).__name__, attempts=attempts)
            self._stop("Planner 调用异常")
            return False
        def record_attempts(state):
            state["counters"]["suggestions"] += 1
            state["plan"]["planner_attempts"] = deepcopy(attempts)
            state["plan"]["rejected_suggestions"].extend(
                {"suggestion": item["decision"], "reason": item["error"]}
                for item in attempts if item["error"])
        self._save("planner校验", record_attempts, attempts=attempts)
        def choose(state):
            state["plan"]["planner_output"] = deepcopy(self.last_scan)
            state["plan"]["selected"] = self.last_scan["next_node_id"]
            state["plan"]["reason"] = self.last_scan["why"]
            state["plan"]["history"].append({"planner_input": deepcopy(planner_input),
                                              "planner_output": deepcopy(self.last_scan)})
        self._save("节点选择", choose, planner_input=planner_input, planner_output=self.last_scan)
        return True

    def _round_expired(self, reserve=False):
        budget = self.state["limits"]["run_seconds"]
        if reserve:
            budget = max(0, budget - self.state["limits"]["round_close_seconds"])
        return self.clock() - self.started >= budget

    def _closing_expired(self):
        return (self._round_expired() or self.clock() - self.close_started
                >= self.state["limits"]["close_seconds"])

    def _choose(self):
        selected = self.last_scan["next_node_id"]
        def change(state):
            if selected is not None:
                state["plan"]["order"].append(selected)
        self._save("选择", change, node_id=selected, planner_output=self.last_scan)
        return selected

    def _phase(self, name, position):
        def change(state):
            state["phase"] = {"name": name, "saved_position": position}
            if state["current_node"]:
                state["attempts"][-1]["positions"].append(name)
                run_record_validator.set_phase(state["sessions"], state["current_node"]["attempt_id"], name)
        self._save("阶段", change, name=name, position=position)

    def _session_check(self, node_record, node_id, attempt_id):
        return run_record_validator.check(node_record, self.state["run_id"]["id"], node_id, attempt_id)

    def cell(self, node_id):
        if not self._admissible(node_id):
            self._save("节点验证不通过", node_id=node_id)
            return False
        self.cell_started = self.clock()
        record = self.state["simulation"]["nodes"].get(node_id, {})
        if not isinstance(record, dict):
            record = {}
        attempt_id = self.state["run_id"]["id"] + ":" + node_id
        snapshot = {fid: self.state["facts"][fid]["version"]
                    for fid in self.state["dependencies"]["requirements"][node_id]}
        def admit(state):
            state["current_node"] = {"node_id": node_id, "attempt_id": attempt_id}
            state["counters"]["admissions"] += 1
            state["attempts"].append({"node_id": node_id, "attempt_id": attempt_id,
                "run_id": state["run_id"]["id"], "simulation": True, "snapshot": deepcopy(snapshot),
                "positions": [], "action_ran": False, "action_completed": False,
                "simulation_ref": "nodes/" + node_id, "started": self.cell_started - self.started})
            state["node_states"][node_id].update(progress="验证中", attempted=True, reason="验证中")
            run_record_validator.start_attempt(state["sessions"], state["run_id"]["id"], node_id, attempt_id)
        self._save("准入", admit, node_id=node_id, attempt_id=attempt_id, snapshot=snapshot)
        self._phase("pre", "必要验证")
        before = pre({"belongs": node_id in self.state["coverage_objective"]["and_ids"],
                      "duplicate": sum(item["node_id"] == node_id for item in self.state["attempts"]) != 1,
                      "node_id": node_id, "run_id": self.state["run_id"]["id"],
                      "attempt_id": attempt_id, "snapshot": deepcopy(snapshot),
                      "leaf_requirements": self.state["dependencies"]["leaf_requirements"][node_id],
                      "known": {fid: definition["known"] for fid, definition
                                in self.state["dependencies"]["fact_definitions"].items()},
                      "record": deepcopy(record.get("pre"))})
        def save_pre(state):
            state["attempts"][-1]["pre"] = deepcopy(before)
            for index, candidate in enumerate(before["facts"]):
                if not candidate["valid"]:
                    continue
                fid = candidate["fact_id"]
                state["facts"][fid]["sources"].append({**deepcopy(candidate),
                    "id": attempt_id + ":pre:" + str(index), "phase": "pre",
                    "simulation": True, "snapshot": {}, "references": []})
            self._refresh(state)
        self._save("pre", save_pre, result=before)
        timed_out = self.clock() - self.cell_started >= self.state["limits"]["cell_seconds"]
        raw = None
        if before["result"] == PASS and not timed_out and not self._round_expired():
            self._phase("action", "模拟记录读取")
            self._save("模拟记录开始", lambda state: state["attempts"][-1].update(action_ran=True))
            try:
                raw = action({"node_id": node_id, "record": deepcopy(record.get("action"))})
            except Exception:
                raw = {"result": UNKNOWN, "ended": True, "facts": [], "evidence": [], "reason": "模拟记录未知"}
            if not isinstance(raw, dict):
                raw = {"result": UNKNOWN, "ended": True, "facts": [], "evidence": []}
            def pending(state):
                state["pending_result"] = {"node_id": node_id, "attempt_id": attempt_id,
                    "raw": deepcopy(raw), "ended": raw.get("ended", True) is True,
                    "proposed_facts": deepcopy(raw.get("facts", [])), "reconcile_reason": None}
                state["attempts"][-1]["action_completed"] = raw.get("ended", True) is True
                state["node_states"][node_id]["action_completed"] = raw.get("ended", True) is True
            self._save("action", pending, raw=raw)
        else:
            raw = {"result": UNKNOWN, "ended": True, "facts": [], "evidence": []}
        self.close_started = self.clock()
        self._phase("post", "结果验证")
        if self._closing_expired():
            self._stop("收尾到限")
            return False
        timed_out = timed_out or self.clock() - self.cell_started >= self.state["limits"]["cell_seconds"]
        result = post({"node_id": node_id, "run_id": self.state["run_id"]["id"],
            "attempt_id": attempt_id, "pre": deepcopy(before), "raw": deepcopy(raw),
            "snapshot": snapshot, "timed_out": timed_out,
            "outputs": self.state["dependencies"]["outputs"][node_id],
            "fact_versions": {fid: self.state["facts"][fid]["version"]
                              for fid in self.state["dependencies"]["outputs"][node_id]},
            "known": {fid: definition["known"] for fid, definition
                      in self.state["dependencies"]["fact_definitions"].items()},
            "record": deepcopy(record.get("post"))})
        self._save("post验证", lambda state: state["attempts"][-1].update(post_candidate=deepcopy(result)), result=result)
        if self._closing_expired():
            self._stop("收尾到限")
            return False
        pending = self.state["pending_result"]
        if pending and not pending["ended"]:
            used = self.state["counters"]["reconcile_attempts"].get(attempt_id, 0)
            if used >= self.state["limits"]["reconcile_attempts"]:
                self._stop("验证结束未知")
                return False
            reconciled = record.get("reconcile", {})
            ended = (isinstance(reconciled, dict) and reconciled.get("ended") is True
                     and reconciled.get("run_id", self.state["run_id"]["id"]) == self.state["run_id"]["id"]
                     and reconciled.get("node_id", node_id) == node_id
                     and reconciled.get("attempt_id", attempt_id) == attempt_id)
            def reconcile(state):
                state["counters"]["reconciliations"] += 1
                state["counters"]["reconcile_attempts"][attempt_id] = used + 1
                state["pending_result"]["ended"] = ended
                state["pending_result"]["reconcile_reason"] = "通过" if ended else "未知"
                state["pending_result"]["reconciliation"] = deepcopy(reconciled)
                state["attempts"][-1]["action_completed"] = ended
                state["node_states"][node_id]["action_completed"] = ended
            self._save("核对", reconcile, result=PASS if ended else UNKNOWN)
            if not ended:
                self._stop("验证结束未知")
                return False
        if self._closing_expired():
            self._stop("收尾到限")
            return False
        session = self._session_check(record, node_id, attempt_id)
        self._save("模拟记录归属验证", lambda state: state["attempts"][-1].update(session_check=deepcopy(session)), result=session)
        if self._closing_expired():
            self._stop("收尾到限")
            return False
        if not self._commit(node_id, attempt_id, snapshot, result, session):
            return False
        def close(state):
            run_record_validator.finish_attempt(state["sessions"], attempt_id)
            state["attempts"][-1]["committed"] = True
            state["current_node"] = None
            state["pending_result"] = None
            state["phase"] = {"name": "planner", "saved_position": "本格终态"}
            state["counters"]["terminal_count"] = sum(bool(row["terminal_record"])
                                                       for row in state["node_states"].values())
        self._save("本格收尾", close, attempt_id=attempt_id)
        return True

    def _commit(self, node_id, attempt_id, snapshot, result, session):
        commit_id = attempt_id + ":post"
        if any(item.get("commit_id") == commit_id for item in self.state["post_records"]):
            return True
        def change(state):
            record = {"commit_id": commit_id, "node_id": node_id, "attempt_id": attempt_id,
                "run_id": state["run_id"]["id"], "simulation": True, "snapshot": deepcopy(snapshot),
                "result": result["result"], "reason": result["reason"], "evidence": deepcopy(result["evidence"]),
                "facts": deepcopy(result["facts"]), "saved_version": state["state_version"] + 1}
            state["post_records"].append(record)
            for index, candidate in enumerate(result["facts"]):
                fid = candidate["fact_id"]
                state["facts"][fid]["sources"].append({**deepcopy(candidate),
                    "id": commit_id + ":" + str(index), "commit_id": commit_id, "node_id": node_id,
                    "phase": "post",
                    "run_id": state["run_id"]["id"], "attempt_id": attempt_id, "simulation": True,
                    "snapshot": deepcopy(snapshot),
                    "pre_sources": {leaf_id: next(source["id"]
                        for source in state["facts"][leaf_id]["sources"]
                        if source.get("phase") == "pre" and source.get("attempt_id") == attempt_id)
                        for leaf_id in state["dependencies"]["leaf_requirements"][node_id]},
                    "references": list(state["dependencies"]["derived_requirements"][node_id])})
            run_record_validator.commit_check(state["sessions"], attempt_id, session)
            self._terminal(state, node_id, result["result"], result["reason"], result["evidence"], "post", commit_id)
            self._refresh(state)
            state["counters"]["terminal_count"] = sum(bool(row["terminal_record"])
                                                       for row in state["node_states"].values())
        for save_attempt in range(1, min(SAVE_ATTEMPTS, self.state["limits"]["save_attempts"]) + 1):
            if self._closing_expired():
                self._stop("收尾到限")
                return False
            if any(item.get("commit_id") == commit_id for item in self.state["post_records"]):
                return True
            try:
                self._save("提交完成", change, commit_id=commit_id, result=result,
                           session=session, save_attempt=save_attempt)
                return True
            except OSError:
                if any(item.get("commit_id") == commit_id for item in self.state["post_records"]):
                    return True
        self._stop("保存不通过")
        return False

    def _terminal(self, state, node_id, result, reason, evidence, source, commit_id=None):
        row = state["node_states"][node_id]
        if row["terminal_record"]:
            return
        row.update(progress="终态", result=result, reason=reason, evidence=deepcopy(evidence),
                   closure_source=source, time=self.clock() - self.started)
        row["terminal_record"] = {"node_id": node_id, "result": result, "reason": reason,
            "evidence": deepcopy(evidence), "closure_source": source, "commit_id": commit_id,
            "time": row["time"], "version": state["state_version"] + 1}

    def finish(self):
        self.round_close_started = self.clock()
        if self._round_expired():
            self._stop("整轮到限")
            return
        def change(state):
            deps = state["dependencies"]
            remaining = [nid for nid in deps["and_ids"] if not state["node_states"][nid]["terminal_record"]]
            for nid in remaining:
                evaluation = prerequisite(nid, state["facts"], state["node_states"], deps,
                                          derived_only=True)
                self._terminal(state, nid, evaluation["result"] if evaluation["result"] == FAIL else UNKNOWN,
                               evaluation["reason"], evaluation["evidence"], "planner")
                state["node_states"][nid]["missing_facts"] = evaluation["missing"]
                state["node_states"][nid]["sources"] = evaluation["sources"]
            self._refresh(state)
            for nid in deps["goal_ids"]:
                goal = state["goals"]["nodes"][nid]
                self._terminal(state, nid, goal["result"], goal["reason"], goal["evidence"], "planner")
                goal["terminal"] = True
            state["waiting"] = {}
            terminal = {nid for nid, row in state["node_states"].items() if row["terminal_record"]}
            state["counters"]["terminal_count"] = len(terminal)
            complete = (terminal == set(state["coverage_objective"]["all_ids"])
                        and state["pending_result"] is None and self.last_scan["status"] == "finish")
            state["outputs"]["coverage_complete"] = complete
            state["stop_reason"] = "完整收尾" if complete else "未完成"
            state["plan"]["stop_reason"] = state["stop_reason"]
            state["phase"] = {"name": "planner", "saved_position": "整轮收尾"}
            run_record_validator.finish_run(state["sessions"])
        self._save("整轮收尾", change)
        if (self._round_expired() or self.clock() - self.round_close_started
                >= self.state["limits"]["round_close_seconds"]):
            self._stop("整轮收尾到限")

    def execute(self):
        """The outer graph owns iteration; Planner owns its correction subgraph."""
        runtime = self

        class WorkflowState(TypedDict):
            snapshot: dict
            route: str

        def initialize(state):
            ok = runtime.initialize()
            return {"snapshot": runtime.state, "route": "plan" if ok else "stop"}

        def plan(state):
            if runtime._round_expired():
                runtime._stop("整轮到限")
                return {"snapshot": runtime.state, "route": "stop"}
            ok = runtime.scan()
            route = "stop" if not ok else "finish" if runtime.last_scan["status"] == "finish" else "cell"
            return {"snapshot": runtime.state, "route": route}

        def cell(state):
            if runtime._round_expired(reserve=True):
                runtime._stop("整轮到限")
                ok = False
            elif runtime.state["counters"]["admissions"] >= runtime.state["limits"]["admissions"]:
                runtime._stop("准入到限")
                ok = False
            else:
                ok = runtime.cell(runtime._choose())
            return {"snapshot": runtime.state, "route": "plan" if ok else "stop"}

        def finish(state):
            runtime.finish()
            return {"snapshot": runtime.state, "route": "stop"}

        workflow = StateGraph(WorkflowState)
        for name, function in (("initialize", initialize), ("plan", plan), ("cell", cell), ("finish", finish)):
            workflow.add_node(name, function)
        workflow.add_edge(START, "initialize")
        workflow.add_conditional_edges("initialize", lambda state: state["route"], {"plan": "plan", "stop": END})
        workflow.add_conditional_edges("plan", lambda state: state["route"], {"cell": "cell", "finish": "finish", "stop": END})
        workflow.add_conditional_edges("cell", lambda state: state["route"], {"plan": "plan", "stop": END})
        workflow.add_edge("finish", END)
        result = workflow.compile().invoke({"snapshot": self.state, "route": "plan"},
            config={"recursion_limit": max(10, len(self.state["graph"]["document"].get("nodes", [])) * 3 + 5)})
        self.state = result["snapshot"]


def run(graph, simulation, *, output_dir=None, graph_name="graph", run_id=None,
        limits=None, clock=None, writer=None, started=None, planner_model=None,
        planner_structured_method=None):
    """验证固定模拟记录；返回完整状态，不重开既有轮编号。"""
    runtime = _Run(graph, simulation, run_id, limits, clock, started, planner_model,
                   planner_structured_method)
    paths = None
    if output_dir is not None:
        paths = output_paths(output_dir, graph_name, runtime.state["run_id"])
        validate_paths(paths)
    try:
        runtime.execute()
    except (Exception, KeyboardInterrupt):
        runtime._stop("验证未知")
    if paths is not None:
        closing_started = runtime.round_close_started
        if closing_started is None:
            closing_started = runtime.clock()
        def budget():
            return (not runtime._round_expired() and runtime.clock() - closing_started
                    < runtime.state["limits"]["round_close_seconds"])
        return publish(runtime.state, paths, writer=writer, budget=budget)
    return runtime.state
