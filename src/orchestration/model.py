"""节点、事实与模拟记录的验证。"""

from copy import deepcopy
import json
import re

from src.graph.predicates import PARAMETERS, parse_parameters

PASS = "通过"
FAIL = "不通过"
UNKNOWN = "未知"
RESULTS = frozenset((PASS, FAIL, UNKNOWN))
TOP_LEVEL_KEYS = frozenset((
    "schema_version", "final_goal", "inputs", "hosts", "nodes", "edges", "summary",
))


def _normalized_id(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("节点编号验证不通过")
    text = str(value).strip()
    if not re.fullmatch(r"[0-9]+", text):
        raise ValueError("节点编号验证不通过")
    return str(int(text))


def _ordered(values):
    return sorted(set(values), key=int)


def _known(description):
    if not isinstance(description, str):
        raise ValueError("事实验证不通过")
    name = description.strip().removesuffix(".").rstrip().partition("(")[0].strip()
    known = any(label == name for label, _ in PARAMETERS)
    if known:
        try:
            values = parse_parameters(description)
        except (ValueError, TypeError):
            raise ValueError("事实验证不通过") from None
        if not values or any(value == "" for value in values.values()):
            raise ValueError("事实验证不通过")
    return known


def validate_graph(graph):
    """保留原始记录，冻结节点与事实。"""
    if not isinstance(graph, dict) or set(graph) != TOP_LEVEL_KEYS:
        raise ValueError("节点清单验证不通过")
    if graph["schema_version"] != "2.0":
        raise ValueError("节点清单验证不通过")
    if (not isinstance(graph["nodes"], list)
            or not isinstance(graph["final_goal"], list)
            or not isinstance(graph["edges"], list)
            or not isinstance(graph["inputs"], dict)
            or not isinstance(graph["hosts"], list)
            or not isinstance(graph["summary"], dict)):
        raise ValueError("节点清单验证不通过")
    nodes = {}
    for record in graph["nodes"]:
        if not isinstance(record, dict):
            raise ValueError("节点验证不通过")
        node_id = _normalized_id(record.get("id"))
        if (node_id in nodes or not isinstance(record.get("type"), str)
                or record["type"] not in {"AND", "OR"}):
            raise ValueError("节点验证不通过")
        if not isinstance(record.get("description"), str):
            raise ValueError("节点验证不通过")
        nodes[node_id] = deepcopy(record)
        nodes[node_id]["id"] = node_id
    goal_ids = [_normalized_id(value) for value in graph["final_goal"]]
    if (len(goal_ids) != 2 or len(set(goal_ids)) != 2
            or any(goal not in nodes or nodes[goal]["type"] != "OR" for goal in goal_ids)):
        raise ValueError("目标节点验证不通过")
    goal_ids = _ordered(goal_ids)
    and_ids = _ordered(key for key in nodes if key not in goal_ids)
    all_ids = _ordered(nodes)
    definitions, parents, children, dedup = {}, {}, {}, []
    group_records = []
    requirements = {key: [] for key in all_ids}
    outputs = {key: [] for key in and_ids}
    leaf_requirements = {key: [] for key in and_ids}
    derived_requirements = {key: [] for key in all_ids}
    sources = {}
    normalized = {key: {} for key in all_ids}

    def fact(record, owner, direction, index):
        fact_id = _normalized_id(record.get("id"))
        kind, description = record.get("type"), record.get("description")
        if (not isinstance(kind, str) or kind not in {"LEAF", "OR"}
                or not isinstance(description, str)):
            raise ValueError("事实验证不通过")
        if fact_id in nodes and (fact_id not in goal_ids or nodes[fact_id]["type"] != kind
                                 or nodes[fact_id]["description"] != description):
            raise ValueError("事实验证不通过")
        existing = definitions.get(fact_id)
        if existing and (existing["type"] != kind or existing["description"] != description):
            raise ValueError("事实验证不通过")
        if existing is None:
            definitions[fact_id] = {"id": fact_id, "type": kind,
                                    "description": description, "known": _known(description),
                                    "records": [], "references": []}
            sources[fact_id] = []
        definitions[fact_id]["records"].append(deepcopy(record))
        definitions[fact_id]["references"].append(
            {"node_id": owner, "direction": direction, "index": index})
        return fact_id

    for goal in goal_ids:
        fact(nodes[goal], goal, "self", 0)
    for node_id in all_ids:
        node = nodes[node_id]
        dependencies = node.get("dependencies")
        if (not isinstance(dependencies, dict)
                or set(dependencies) != {"parents", "children"}):
            raise ValueError("节点事实验证不通过")
        if node_id in goal_ids and dependencies["children"]:
            raise ValueError("目标节点不能有后继")
        for direction, destination in (("parents", parents), ("children", children)):
            records = dependencies[direction]
            if not isinstance(records, list):
                raise ValueError("节点事实验证不通过")
            destination[node_id] = deepcopy(records)
            kept, seen = [], {}
            for index, record in enumerate(records):
                if not isinstance(record, dict):
                    raise ValueError("节点事实验证不通过")
                reference_id = _normalized_id(record.get("id"))
                if record.get("type") == "AND":
                    if (reference_id not in and_ids
                            or record.get("description") != nodes[reference_id]["description"]):
                        raise ValueError("节点引用验证不通过")
                    if node_id not in goal_ids or direction != "parents":
                        raise ValueError("节点事实验证不通过")
                else:
                    fact(record, node_id, direction, index)
                fact_id = node_id if record.get("type") == "AND" else reference_id
                group = record.get("group", record.get("group_id", fact_id))
                key = (direction, reference_id, json.dumps(group, sort_keys=True, ensure_ascii=False))
                if key in seen:
                    dedup.append({"node_id": node_id, "direction": direction,
                                  "fact_id": reference_id, "group": deepcopy(group),
                                  "index": index, "retained_index": seen[key]})
                    continue
                seen[key] = index
                kept.append(reference_id)
                group_records.append({"node_id": node_id, "direction": direction,
                                      "fact_id": fact_id, "reference_id": reference_id,
                                      "group": deepcopy(group), "index": index})
            normalized[node_id][direction] = kept
        if node_id in and_ids:
            requirements[node_id] = _ordered(normalized[node_id]["parents"])
            leaf_requirements[node_id] = [fid for fid in requirements[node_id]
                                          if definitions[fid]["type"] == "LEAF"]
            derived_requirements[node_id] = [fid for fid in requirements[node_id]
                                             if definitions[fid]["type"] == "OR"]
            outputs[node_id] = [fid for fid in _ordered(normalized[node_id]["children"])
                                if definitions[fid]["type"] == "OR"]
            for fact_id in outputs[node_id]:
                sources[fact_id].append(node_id)
    for fact_id in sources:
        sources[fact_id] = _ordered(sources[fact_id])
    for goal in goal_ids:
        references = normalized[goal]["parents"]
        if any(reference not in and_ids for reference in references):
            raise ValueError("目标节点事实验证不通过")
        if _ordered(references) != sources[goal]:
            raise ValueError("目标节点事实验证不通过")
        requirements[goal] = [goal]
        derived_requirements[goal] = [goal]

    groups = {fid: {"fact_id": fid, "sources": list(ids), "alternatives": []}
              for fid, ids in sources.items()}
    group_index = {}
    for record in group_records:
        fid = record["fact_id"]
        key = (fid, json.dumps(record["group"], sort_keys=True, ensure_ascii=False))
        if key not in group_index:
            group_index[key] = {"group": deepcopy(record["group"]),
                                "sources": [], "references": []}
            groups[fid]["alternatives"].append(group_index[key])
        entry = group_index[key]
        entry["references"].append({key: value for key, value in record.items() if key != "group"})
        if (record["direction"] == "children" and record["node_id"] in and_ids
                and fid in outputs[record["node_id"]]):
            entry["sources"].append(record["node_id"])
        elif record["node_id"] in goal_ids and record["reference_id"] in and_ids:
            entry["sources"].append(record["reference_id"])
    for entry in group_index.values():
        entry["sources"] = _ordered(entry["sources"])

    edges = set()
    for edge in graph["edges"]:
        if not isinstance(edge, dict) or set(edge) != {"src", "dst"}:
            raise ValueError("节点引用验证不通过")
        source, target = _normalized_id(edge["src"]), _normalized_id(edge["dst"])
        if source not in nodes or target not in nodes:
            raise ValueError("节点引用验证不通过")
        edges.add((source, target))
    expected_edges = {(source, target) for target in all_ids
                      for fact_id in requirements[target] for source in sources[fact_id]}
    edge_key = lambda pair: (int(pair[0]), int(pair[1]))
    edge_checks = {"missing": [list(pair) for pair in sorted(expected_edges - edges, key=edge_key)],
                   "extra": [list(pair) for pair in sorted(edges - expected_edges, key=edge_key)]}
    if edges != expected_edges:
        raise ValueError("简化边与前提记录不一致")
    for nid in and_ids:
        groups_for_node = {frozenset(sources[fid]) for fid in derived_requirements[nid]}
        if any(not group for group in groups_for_node):
            raise ValueError("派生前提没有来源")
        if not groups_for_node or all(len(group) == 1 for group in groups_for_node):
            expected_type = "AND"
        elif len(groups_for_node) == 1:
            expected_type = "OR"
        else:
            raise ValueError("混合前提不能用单一 type 表示")
        if nodes[nid]["type"] != expected_type:
            raise ValueError("type 与前提逻辑不一致")
    order, visited = [], set()

    def visit(node_id):
        if node_id in visited:
            return
        visited.add(node_id)
        if node_id in and_ids:
            order.append(node_id)
        upstream = {source for fact_id in requirements[node_id] for source in sources[fact_id]}
        for source in _ordered(upstream):
            visit(source)

    for goal in goal_ids:
        visit(goal)
    for node_id in and_ids:
        visit(node_id)
    return {"and_ids": and_ids, "goal_ids": goal_ids, "all_ids": all_ids,
            "nodes": nodes, "requirements": requirements, "outputs": outputs,
            "leaf_requirements": leaf_requirements, "derived_requirements": derived_requirements,
            "sources": sources, "fact_definitions": definitions, "order": order,
            "parents": parents, "children": children, "dedup": dedup,
            "groups": groups, "group_records": group_records, "edge_checks": edge_checks}


def evaluate_fact(fact_id, facts, node_states, dependencies, seen=None):
    """仅使用当前仍通过验证的事实引用。"""
    fact_id = str(fact_id)
    visited = frozenset(seen or ())
    definitions = dependencies.get("fact_definitions", {})
    if fact_id in visited or not definitions.get(fact_id, {}).get("known", False):
        return {"result": UNKNOWN, "reason": "事实未知", "evidence": []}
    record = facts.get(fact_id, {})
    values, evidence = set(), []
    for index, source in enumerate(record.get("sources", [])):
        source_key = f"source:{fact_id}:{index}"
        if source_key in visited:
            continue
        if (not isinstance(source, dict) or source.get("valid") is not True
                or not isinstance(source.get("result"), str)
                or source["result"] not in {PASS, FAIL}):
            continue
        node_id = source.get("node_id")
        if (not isinstance(node_id, str) or not source.get("run_id")
                or not source.get("attempt_id") or not source.get("evidence")
                or not isinstance(source.get("fact_version"), int)):
            continue
        is_leaf = definitions[fact_id]["type"] == "LEAF"
        if is_leaf:
            if (source.get("phase") != "pre"
                    or fact_id not in dependencies.get("leaf_requirements", {}).get(node_id, [])):
                continue
        elif (source.get("phase") != "post"
                or node_id not in dependencies.get("sources", {}).get(fact_id, [])):
            continue
        references = source.get("references", [])
        snapshot = source.get("snapshot", {})
        if not isinstance(references, list) or not isinstance(snapshot, dict):
            continue
        refs = {str(ref) for ref in references} | {str(ref) for ref in snapshot}
        local_evidence = []
        if is_leaf:
            if refs:
                continue
        else:
            leaf_ids = dependencies.get("leaf_requirements", {}).get(node_id, [])
            pre_sources = source.get("pre_sources", {})
            if not isinstance(pre_sources, dict) or set(pre_sources) != set(leaf_ids):
                continue
            for leaf_id in leaf_ids:
                local = next((item for item in facts.get(leaf_id, {}).get("sources", [])
                              if item.get("id") == pre_sources[leaf_id]), None)
                if (not local or local.get("phase") != "pre" or local.get("valid") is not True
                        or local.get("result") != PASS or not local.get("evidence")
                        or any(local.get(key) != source.get(key)
                               for key in ("run_id", "node_id", "attempt_id"))
                        or local.get("fact_version") != snapshot.get(leaf_id)):
                    break
                local_evidence.append(local["id"])
            if len(local_evidence) != len(leaf_ids):
                continue
            refs.difference_update(leaf_ids)
            refs.update(dependencies.get("derived_requirements", {}).get(node_id, []))
        evaluations = [evaluate_fact(ref, facts, node_states, dependencies, visited | {source_key})
                       for ref in sorted(refs, key=lambda value: (not value.isdigit(), int(value) if value.isdigit() else value))]
        if any(item["result"] != PASS for item in evaluations):
            continue
        values.add(source["result"])
        evidence.extend(local_evidence)
        evidence.append(source.get("id", source.get("commit_id", f"{fact_id}:{index}")))
        for item in evaluations:
            evidence.extend(item["evidence"])
    result = next(iter(values)) if len(values) == 1 else UNKNOWN
    reason = "事实差异" if len(values) > 1 else f"事实{result}"
    return {"result": result, "reason": reason, "evidence": list(dict.fromkeys(evidence))}


def _path_failed(fact_id, facts, node_states, dependencies, seen):
    if fact_id in seen or not dependencies.get("fact_definitions", {}).get(fact_id, {}).get("known", False):
        return False
    current = evaluate_fact(fact_id, facts, node_states, dependencies)
    if current["result"] == FAIL:
        return True
    if current["result"] == PASS or current["reason"] == "事实差异":
        return False
    source_ids = dependencies.get("sources", {}).get(fact_id, [])
    if not source_ids:
        return False
    for node_id in source_ids:
        state = node_states.get(node_id, {})
        result = state.get("current_result", state.get("result", UNKNOWN))
        if state.get("progress") == "终态" and result == FAIL:
            continue
        required = dependencies.get("derived_requirements", {}).get(node_id, [])
        if not any(_path_failed(ref, facts, node_states, dependencies, seen | {fact_id})
                   for ref in required):
            return False
    return True


def prerequisite(node_id, facts, node_states, dependencies, *, derived_only=False):
    """仅评价终态与事实依据，不参与节点选择或准入。"""
    key = "derived_requirements" if derived_only else "requirements"
    required = dependencies.get(key, {}).get(str(node_id), [])
    missing, evidence, impossible = [], [], False
    for fact_id in required:
        evaluated = evaluate_fact(fact_id, facts, node_states, dependencies)
        evidence.extend(evaluated["evidence"])
        if evaluated["result"] != PASS:
            missing.append(fact_id)
        if evaluated["result"] == FAIL or _path_failed(
                fact_id, facts, node_states, dependencies, set()):
            impossible = True
    result = FAIL if impossible else UNKNOWN if missing else PASS
    return {"result": result, "missing": missing,
            "sources": {fact_id: list(dependencies.get("sources", {}).get(fact_id, []))
                        for fact_id in missing},
            "reason": "必要前提不通过" if result == FAIL else f"事实{result}",
            "evidence": list(dict.fromkeys(evidence))}
