"""Snapshot evaluation of the real Planner; expected answers never enter prompts."""

from copy import deepcopy
import json
from time import perf_counter

import networkx as nx
from pydantic import Field

from .agent import PlannerExhausted, planner
from .schema import Contract, PlannerInput


class PlannerCase(Contract):
    name: str
    context: PlannerInput
    expected: list[str | None] = Field(min_length=1)
    preferred: list[str] = Field(default_factory=list)


def render_report(report):
    """Keep first-answer quality and concrete failures visible to reviewers."""
    cases = report["cases"]
    first = sum(c["first_attempt_passed"] for c in cases)
    passed = sum(c["outcome"] == "passed" for c in cases)
    requests = sum(c["requests"] for c in cases)
    total = report["planned_cases"]
    lines = ["# Planner 真实模型测试", "",
             f"已测 {len(cases)}/{total}；首答通过 {first}/{len(cases)}；最终通过 {passed}/{len(cases)}；请求 {requests} 次。", "",
             "仅 Planner 调用真实模型；其他阶段由输入快照代替。预期答案仅用于评测，不发给模型。", "",
             "| 场景 | 预期编号 | 最终状态/编号 | 首答通过 | 最终结果 | 请求次数 |",
             "|---|---|---|---|---|---|"]

    def cell(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")

    for case in cases:
        decision = case["decision"]
        choice = f'{decision.get("status", "legacy")} / {decision["next_node_id"]}' if decision else "无有效输出"
        lines.append("| " + " | ".join(map(cell, [case["name"], case["expected"], choice,
                     "是" if case["first_attempt_passed"] else "否", case["outcome"], case["requests"]])) + " |")
    lines.extend(["", "## 具体失败记录", ""])
    errors = 0
    for case in cases:
        for attempt in case["attempts"]:
            if attempt["error"] is None:
                continue
            errors += 1
            context = case["input"]
            decision = attempt["decision"] or {}
            selected = decision.get("next_node_id")
            results = {r["node_id"]: r["结果"] for r in context["previous_results"]}
            parents = {edge["src"]: results.get(edge["src"], "未验证")
                       for edge in context["graph"]["edges"] if edge["dst"] == selected}
            node = next((n for n in context["graph"]["nodes"] if n["id"] == selected), None)
            details = {"当时已验证结果": results, "上一次结果": context["last_result"],
                       "模型输出": decision or attempt["response"],
                       "选中节点类型": node["type"] if node else None,
                       "是否终点": selected in context["graph"]["final_goal"],
                       "图中直接上游及状态": parents, "校验错误": attempt["error"],
                       "测试预期（未发送给模型）": case["expected"]}
            lines.extend([f'### {case["name"]} / 第 {attempt["attempt"]} 次', "", "```json",
                          json.dumps(details, ensure_ascii=False, indent=2), "```", ""])
    if not errors:
        lines.append("本次已完成的请求没有模型输出校验错误。接口异常另见下文及 report.json。")
    for case in cases:
        if case["error"] is not None:
            lines.extend(["", f'接口/运行异常：{case["name"]}：{case["error"]}'])
    return "\n".join(lines) + "\n"


def evaluate_case(case, model, *, structured_method="json_mode"):
    """Use the production graph including its shared two-retry budget."""
    case = PlannerCase.model_validate(case)
    trace, decision = [], None
    started = perf_counter()
    requests = 0

    def count_request():
        nonlocal requests
        requests += 1

    error = None
    try:
        decision = planner(case.context.model_dump(), model=model, trace=trace,
                           structured_method=structured_method, before_attempt=count_request)
        outcome = "passed" if decision["next_node_id"] in case.expected else "unexpected_choice"
    except PlannerExhausted:
        outcome = "exhausted"
    except Exception as exc:
        # Do not serialize provider exception bodies/headers, which can contain secrets.
        outcome = "api_error"
        error = {"type": type(exc).__name__, "status_code": getattr(exc, "status_code", None)}
    return {"name": case.name, "input": case.context.model_dump(),
            "expected": case.expected, "preferred": case.preferred,
            "decision": decision, "outcome": outcome, "error": error,
            "first_attempt_passed": outcome == "passed" and requests == 1,
            "preference_met": (decision["next_node_id"] in case.preferred
                               if decision and case.preferred else None),
            "requests": requests, "seconds": round(perf_counter() - started, 3),
            "attempts": trace}


def sample_cases(graph):
    """Hongri fixture answers are authored independently of ready_nodes()."""
    graph = {"nodes": [{"id": n["id"], "type": n["type"]} for n in graph["nodes"]],
             "edges": [{"src": e["src"], "dst": e["dst"]} for e in graph["edges"]],
             "final_goal": graph["final_goal"]}
    cases = []

    def add(name, passed, failed, unknown, expected, preferred=(), custom_graph=None):
        rows = [{"node_id": n, "结果": status} for nodes, status in
                [(failed, "不通过"), (unknown, "未知"), (passed, "通过")] for n in nodes]
        selected_graph = deepcopy(custom_graph or graph)
        topology = nx.DiGraph()
        topology.add_nodes_from(n["id"] for n in selected_graph["nodes"])
        topology.add_edges_from((e["src"], e["dst"]) for e in selected_graph["edges"])
        positions = {row["node_id"]: i for i, row in enumerate(rows)}
        order = list(nx.lexicographical_topological_sort(topology, key=lambda n: positions.get(n, len(rows))))
        rows.sort(key=lambda row: order.index(row["node_id"]))
        action_rows = [row for row in rows if row["node_id"] not in selected_graph["final_goal"]]
        cases.append(PlannerCase.model_validate({"name": name,
            "context": {"graph": selected_graph, "previous_results": rows,
                        "last_result": action_rows[-1] if action_rows else None},
            "expected": list(expected), "preferred": list(preferred)}).model_dump())

    add("初始两条入口", [], [], [], ["14", "30"])
    add("右侧入口失败选择左侧入口", [], ["30"], [], ["14"])
    add("成功后优先深入但允许换路", ["14"], [], [], ["12", "30"], ["12"])
    left = ["14", "12", "7", "5", "2", "44", "48"]
    expected_left = [["12"], ["7"], ["5"], ["2", "48"], ["44", "48"], ["48"], [None]]
    for end, expected in enumerate(expected_left, 1):
        add(f"左路推进-{end}", left[:end], ["30"], [], expected)
    add("分支48已完成转向2", ["14", "12", "7", "5", "48"], ["30"], [], ["2"])
    add("分支2完成继续44", ["14", "12", "7", "5", "48", "2"], ["30"], [], ["44"])
    right = ["30", "28", "26", "22", "19"]
    for end, expected in enumerate(["28", "26", "22", "19", "5"], 1):
        add(f"右路推进-{end}", right[:end], ["14"], [], [expected])
    add("一条来源失败另一条通过仍可合流", ["14", "12", *right], ["7"], [], ["5"])
    add("中途失败转向另一入口", ["14", "12"], ["7"], [], ["30"])
    add("未知结果不重选并转向另一入口", ["14"], [], ["12"], ["30"])
    add("全部入口失败结束", [], ["14", "30"], [], [None])
    add("全部入口未知结束", [], [], ["14", "30"], [None])
    add("目标成功仍覆盖剩余路径", [*left, "43", "47"], [], [], ["30"])
    add("所有动作完成结束", [*left, *right, "43", "47"], [], [], [None])
    gate_graph = {"nodes": [{"id": n, "type": "AND"} for n in ["a", "b", "c"]],
                  "edges": [{"src": n, "dst": "c"} for n in ["a", "b"]], "final_goal": []}
    add("AND只通过一个仍需另一前置", ["a"], [], [], ["b"], custom_graph=gate_graph)
    add("AND全部通过才可继续", ["a", "b"], [], [], ["c"], custom_graph=gate_graph)
    add("AND一项失败阻断", ["a"], ["b"], [], [None], custom_graph=gate_graph)
    return cases
