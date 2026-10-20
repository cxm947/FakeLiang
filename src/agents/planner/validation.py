"""Three business errors; eligibility is a check, not a production selector."""

from .schema import PlannerDecision, PlannerInput

INVALID = "输出不合法"
UNREADY = "前置条件未满足"
REPEATED = "重复选择"


def blocked_nodes(context: PlannerInput):
    """Infer round-local blocking for validation only; never invent result rows."""
    completed = {row.node_id: row.结果 for row in context.previous_results}
    # Least fixed point: could this action ever be reached if future attempts
    # succeed? This also handles dependency cycles without bootstrapping them.
    possible = {nid for nid, result in completed.items() if result == "通过"}
    parents = {node.id: {e.src for e in context.graph.edges if e.dst == node.id}
               for node in context.graph.nodes}
    changed = True
    while changed:
        changed = False
        for node in context.graph.nodes:
            if node.id in completed or node.id in possible:
                continue
            reachable = (not parents[node.id] or
                         (all(p in possible for p in parents[node.id]) if node.type == "AND"
                          else any(p in possible for p in parents[node.id])))
            if reachable:
                possible.add(node.id)
                changed = True
    return {node.id for node in context.graph.nodes} - set(completed) - possible


def ready_nodes(context: PlannerInput, admitted=()):
    completed = {row.node_id: row.结果 for row in context.previous_results}
    excluded = set(completed) | set(context.graph.final_goal) | set(admitted)
    parents = {node.id: set() for node in context.graph.nodes}
    for edge in context.graph.edges:
        if edge.dst in parents:
            parents[edge.dst].add(edge.src)
    return {node.id for node in context.graph.nodes if node.id not in excluded and (
        not parents[node.id] or
        (all(completed.get(p) == "通过" for p in parents[node.id]) if node.type == "AND"
         else any(completed.get(p) == "通过" for p in parents[node.id])))}


def check_decision(context: PlannerInput, decision: PlannerDecision, admitted=()):
    selected = decision.next_node_id
    eligible = ready_nodes(context, admitted)
    if decision.status == "finish":
        processed = {r.node_id for r in context.previous_results}
        unresolved = {n.id for n in context.graph.nodes} - processed - blocked_nodes(context)
        return ({"category": INVALID, "detail": "仍有满足前提且未验证的节点，不能宣布结束。"}
                if eligible else ({"category": INVALID,
                    "detail": "仍有未验证且不能证明本轮已被前置阻断的动作，不能宣布结束。"}
                    if unresolved else None))
    actions = {n.id for n in context.graph.nodes}
    if selected not in actions:
        return {"category": INVALID, "detail": f"节点 {selected} 不是图中的可执行动作节点。"}
    if selected in {r.node_id for r in context.previous_results} | set(admitted):
        return {"category": REPEATED, "detail": f"节点 {selected} 本轮已处理，不能重复选择。"}
    if selected not in eligible:
        parents = {e.src for e in context.graph.edges if e.dst == selected}
        results = {r.node_id: r.结果 for r in context.previous_results}
        gate = next(n.type for n in context.graph.nodes if n.id == selected)
        return {"category": UNREADY, "detail": f"节点 {selected} 的 {gate} 前提未满足。",
                "parents": {p: results.get(p, "未验证") for p in sorted(parents)}}
    return None
