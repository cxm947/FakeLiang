"""Build one deterministic 1.2.0 JSON document from the original TXT graph.

The document is a faithful mapping: the source graph stays whole (authoritative), every output
node carries its own text plus its direct parents only (E1), LEAF rows carry the validation
fields a checker can look at (E6), OR rows carry the producers the source graph records (E2).
The 1.2.0 addition is ``final_goal``: the terminal OR node ids, computed here once so every
consumer reads the same list instead of re-deriving it. Runtime prerequisites are derived on
load (graph.rehydrate); they are not stored here.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path

from .cases import extract_fields, select_case
from .host_map import HostIndex
from .parser import Graph, digest, id_key
from .terms import atom_value, rule_description
from .validations import validation_of

#: Fact names whose first argument is the host the goal lands on.
TARGET_FACTS = ("execCode", "netAccess", "getAccount", "attackVectorInjection", "disableFirewall")
_FIELDS = ("source_host", "target_host", "service", "protocol", "port", "vulnerability")


def source_snapshot(path, *, root=None) -> dict:
    """Input block for one source file: display path, format, and the SHA-256 snapshot."""
    resolved = Path(path).resolve()
    if root is not None:
        try:
            name = resolved.relative_to(Path(root).resolve()).as_posix()
        except ValueError:
            name = resolved.as_posix()
    else:
        name = resolved.as_posix()
    return {"file": name, "format": "mulval_txt", "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest()}


def project(graph: Graph, *, hosts=None, host_index=None, inputs=None) -> dict:
    archive = graph.archive()
    graph_hash = digest(archive)
    index = host_index or HostIndex([])
    kept = sorted(graph.actions + graph.terminals, key=id_key)
    diagnostics = list(graph.diagnostics)
    if graph.topological_order() is None:
        diagnostics.append({"code": "cycle_present", "severity": "warning",
                            "detail": "the source graph has a cycle; nothing is simplified away"})
    for nid in sorted(graph.nodes, key=id_key):
        if graph.nodes[nid].type == "OR" and not graph.parents[nid]:
            diagnostics.append({"code": "or_without_provider", "node_ref": nid, "severity": "warning"})
    nodes = []
    for nid in kept:
        raw = graph.nodes[nid]
        dependencies = []
        for parent in sorted(graph.parents[nid], key=id_key):
            row = {"ref": parent, "type": graph.nodes[parent].type,
                   "description": str(graph.nodes[parent].description)}
            if row["type"] == "LEAF":
                row["validation"] = validation_of(graph.nodes[parent].description, index)
            elif row["type"] == "OR":
                row["produced_by"] = sorted(graph.parents[parent], key=id_key)
            dependencies.append(row)
        fields = dict.fromkeys(_FIELDS)
        if raw.type == "AND":
            desc, rule_desc = str(raw.description), rule_description(raw.description)
            selected = select_case(graph, nid)
            if selected["status"] != "matched":
                diagnostics.append({"code": "case_" + selected["status"], "node_ref": nid,
                                    "severity": "warning", "reason": selected["reason"]})
            extracted, _details = extract_fields(graph, nid, selected)
            fields.update(extracted)
            match = re.search(r"\bT\d{4}(?:\.\d{3})?\b", rule_desc)
            attack_id = match[0] if match else None
        else:
            desc, rule_desc, attack_id = str(raw.description), None, None
            fact = graph.facts.get(nid)
            if fact is not None and fact.name in TARGET_FACTS and fact.args:
                fields["target_host"] = atom_value(fact.args[0])
        port = fields["port"]
        if port is not None and (not re.fullmatch(r"[0-9]+", port) or not 1 <= int(port) <= 65535):
            diagnostics.append({"code": "non_transport_port_token", "node_ref": nid, "severity": "info"})
        nodes.append({"id": nid, "type": raw.type, "description": desc, "rule_desc": rule_desc,
                      "attack_id": attack_id, **fields, "dependencies": dependencies})
    dependency_types = Counter(row["type"] for node in nodes for row in node["dependencies"])
    kinds = Counter(row["validation"]["kind"] for node in nodes for row in node["dependencies"]
                    if "validation" in row)
    return {
        "schema_version": "1.2.0",
        "final_goal": list(graph.terminals),
        "inputs": inputs or {"graph_source": {"file": "<memory>", "format": "mulval_txt", "sha256": graph_hash}},
        "source_graph": {"format": "mulval_txt", "graph_hash": graph_hash, **archive},
        "hosts": list(hosts or []),
        "nodes": nodes,
        "diagnostics": diagnostics,
        "summary": {
            "input_nodes": len(graph.nodes), "input_edges": len(graph.weights),
            "and_nodes": len(graph.actions), "terminal_or_nodes": len(graph.terminals),
            "output_nodes": len(nodes),
            "hosts": len(hosts or []), "ips": sum(len(entry["ips"]) for entry in hosts or []),
            "dependency_entries": sum(dependency_types.values()),
            "dependency_types": {kind: dependency_types.get(kind, 0) for kind in ("LEAF", "OR", "AND")},
            "validation_by_kind": dict(sorted(kinds.items())),
            "unknown_leaf_validations": kinds.get("unknown", 0),
        },
    }