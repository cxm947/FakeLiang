"""Read node rows and dependent,prerequisite,-1 edges into one document."""

import csv
import hashlib
import re
from pathlib import Path

from .predicates import parse_parameters
from .logic import incoming_type, prune_dependencies


class GraphFormatError(ValueError):
    """The input cannot describe an unambiguous graph."""


def _node_id(value: str) -> str:
    if not re.fullmatch(r"[0-9]+", value.strip()):
        raise ValueError("expected a nonnegative integer node ID")
    return str(int(value))


HOST_FIELDS = {"host", "source_host", "target_host", "docker"}
RULE = re.compile(r"\s*RULE\s+\d+\s*\((.*)\)\s*")


def _rows(text):
    nodes, edges = {}, set()
    for line_number, line in enumerate(text.lstrip("\ufeff").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = next(csv.reader([line], skipinitialspace=True, strict=True))
            if len(row) == 4:
                raw_id, description, kind, _metric = row
                node_id = _node_id(raw_id)
                if node_id in nodes:
                    raise ValueError(f"duplicate node ID {node_id}")
                kind = "AND" if RULE.fullmatch(description) else kind.strip()
                if kind not in {"LEAF", "OR", "AND"}:
                    raise ValueError(f"unsupported node type {kind!r}")
                nodes[node_id] = {"id": node_id, "type": kind,
                                  "description": description,
                                  "parameters": parse_parameters(description),
                                  "parents": [], "children": []}
            elif len(row) == 3:
                dependent, prerequisite, weight = row
                if weight.strip() != "-1":
                    raise ValueError("expected edge weight -1")
                edges.add((_node_id(prerequisite), _node_id(dependent)))
            else:
                raise ValueError("expected 4 node fields or 3 edge fields")
        except (csv.Error, ValueError) as error:
            raise GraphFormatError(f"line {line_number}: {error}") from error
    if not nodes:
        raise GraphFormatError("input contains no nodes")
    for source, target in sorted(edges, key=lambda pair: tuple(map(int, pair))):
        if source not in nodes or target not in nodes:
            raise GraphFormatError(f"missing endpoint: {source} -> {target}")
        nodes[target]["parents"].append(source)
        nodes[source]["children"].append(target)
    return nodes, edges


def _unique(values, field, node_id):
    values = set(values)
    if len(values) > 1:
        raise GraphFormatError(f"node {node_id}: ambiguous {field}")
    return next(iter(values), None)


def _action_parameters(node, nodes):
    neighbors = [nodes[ref] for ref in node["parents"] + node["children"]]
    parameters = [neighbor["parameters"] for neighbor in neighbors]
    hosts = {value for item in parameters for key, value in item.items()
             if key in HOST_FIELDS}
    if len(hosts) > 2:
        raise GraphFormatError(f"node {node['id']}: more than two hosts")
    if len(hosts) < 2:
        result = {"host": next(iter(hosts), None)}
    else:
        pairs = {(item["source_host"], item["target_host"]) for item in parameters
                 if "source_host" in item and "target_host" in item}
        pair = _unique(pairs, "host roles", node["id"])
        if pair is None:
            effects = [nodes[ref]["parameters"] for ref in node["children"]]
            target = _unique((item.get("target_host", item.get("host"))
                              for item in effects
                              if "host" in item or "target_host" in item),
                             "target host", node["id"])
            if target is None:
                raise GraphFormatError(f"node {node['id']}: ambiguous host roles")
            pair = (next(iter(hosts - {target})), target)
        result = dict(zip(("source_host", "target_host"), pair))
    services = [neighbor["parameters"] for neighbor in neighbors
                if neighbor["description"].partition("(")[0].strip() == "networkServiceInfo"]
    for key in ("service", "protocol", "port"):
        preferred = [item[key] for item in services if key in item]
        values = preferred or [item[key] for item in parameters if key in item]
        result[key] = _unique(values, key, node["id"])
    return result


def _rule_metadata(description):
    match = RULE.fullmatch(description)
    rule_desc = match[1].strip() if match else description
    attack = re.search(r"\s*-\s*(T\d{4}(?:\.\d{3})?)\s*$", rule_desc)
    return {"rule_desc": rule_desc[:attack.start()].strip() if attack else rule_desc,
            "attack_id": attack[1] if attack else None}


def _dependency(node, parameters):
    return {"type": node["type"], "description": node["description"], "id": node["id"],
            **{key: value for key, value in parameters.items() if value is not None}}


def _project_edges(nodes, retained):
    edges = set()
    for source in retained:
        pending, visited = list(nodes[source]["children"]), set()
        while pending:
            target = pending.pop()
            if target in visited:
                continue
            visited.add(target)
            if target in retained:
                edges.add((source, target))
            elif nodes[target]["type"] == "OR":
                pending.extend(nodes[target]["children"])
    return [{"src": source, "dst": target} for source, target in
            sorted(edges, key=lambda pair: tuple(map(int, pair)))]


def read_text(text: str, *, source_file=None, source_sha256=None, original=False) -> dict:
    nodes, original_edges = _rows(text)
    parameters = {key: (_action_parameters(node, nodes) if node["type"] == "AND"
                        else node["parameters"]) for key, node in nodes.items()}
    terminal = {key for key, node in nodes.items()
                if node["type"] == "OR" and not node["children"]}
    retained = terminal | {key for key, node in nodes.items() if node["type"] == "AND"}
    if original:
        retained = set(nodes)
        pruning = {}
    else:
        nodes, pruning = prune_dependencies(nodes, original_edges)
    output_nodes = []
    for key in sorted(retained, key=int):
        node = nodes[key]
        record = {name: node[name] for name in ("id", "type", "description")}
        if not original:
            try:
                record["type"] = incoming_type(key, nodes, retained)
            except ValueError as error:
                raise GraphFormatError(str(error)) from error
        if node["type"] == "AND":
            record.update(_rule_metadata(node["description"]))
        record.update(parameters[key])
        record["dependencies"] = {
            direction: [_dependency(nodes[ref], parameters[ref])
                        for ref in sorted(node[direction], key=int)]
            for direction in ("parents", "children")}
        output_nodes.append(record)
    hosts = sorted({value for node in nodes.values()
                    for key, value in node["parameters"].items() if key in HOST_FIELDS})
    output_edges = _project_edges(nodes, retained)
    return {
        "schema_version": "original-1.0" if original else "2.0",
        "final_goal": sorted(terminal, key=int),
        "inputs": {"graph": {"file": str(source_file) if source_file is not None else None,
                             "format": "txt", "sha256": source_sha256 or
                             hashlib.sha256(text.encode("utf-8")).hexdigest()},
                   "host_map": {"source": None, "records": 0}},
        "hosts": [{"host": host, "ips": []} for host in hosts],
        "nodes": output_nodes,
        "edges": output_edges,
        "summary": {
            "input_nodes": len(nodes), "input_edges": len(original_edges),
            "and_nodes": sum(n["type"] == "AND" for n in nodes.values()), "terminal_or_nodes": len(terminal),
            "output_nodes": len(output_nodes), "hosts": len(hosts), "addresses": 0,
            "pruning": pruning,
            **{f"{name}_dependencies": sum(
                len(node["dependencies"][direction]) for node in output_nodes)
               for name, direction in (("parent", "parents"), ("child", "children"))}},
    }


def read_txt(path: str | Path, *, encoding="utf-8-sig", original=False) -> dict:
    data = Path(path).read_bytes()
    return read_text(data.decode(encoding), source_file=path,
                     source_sha256=hashlib.sha256(data).hexdigest(), original=original)
