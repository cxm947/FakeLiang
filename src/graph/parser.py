"""Read the CSV-like MulVAL TXT dialect used by S1/S2/S3.

Nodes: id,description,type,metric. Edges: destination,source,weight.
Everything here is local data processing; predicate text is never executed.
"""

from __future__ import annotations

import csv
import hashlib
import heapq
import io
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

from .terms import Fact, parse_fact


class GraphFormatError(ValueError):
    pass


def id_key(value: str) -> int:
    return int(value)


def digest(value: object) -> str:
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Node:
    id: str
    description: str
    type: str
    metric: str

    def as_dict(self) -> dict:
        return {"id": self.id, "description": self.description, "type": self.type, "metric": self.metric}


@dataclass
class Graph:
    nodes: dict[str, Node]
    weights: dict[tuple[str, str], str]
    diagnostics: list[dict] = field(default_factory=list)

    def __post_init__(self):
        self.parents = {nid: set() for nid in self.nodes}
        self.children = {nid: set() for nid in self.nodes}
        self.facts: dict[str, Fact] = {}
        for (source, target), _weight in self.weights.items():
            if source not in self.nodes or target not in self.nodes:
                raise GraphFormatError(f"missing endpoint: {source} -> {target}")
            kinds = (self.nodes[source].type, self.nodes[target].type)
            if kinds not in {("LEAF", "AND"), ("OR", "AND"), ("AND", "OR")}:
                raise GraphFormatError(f"unsupported edge types {kinds}: {source} -> {target}; check edge direction")
            self.parents[target].add(source)
            self.children[source].add(target)
        for nid in sorted(self.nodes, key=id_key):
            if self.nodes[nid].type == "AND":
                continue
            try:
                self.facts[nid] = parse_fact(self.nodes[nid].description)
            except ValueError:
                self.diagnostics.append({"code": "unparsed_fact", "node_ref": nid, "severity": "warning"})

    @property
    def actions(self) -> list[str]:
        return sorted((nid for nid, node in self.nodes.items() if node.type == "AND"), key=id_key)

    @property
    def terminals(self) -> list[str]:
        return sorted((nid for nid, node in self.nodes.items() if node.type == "OR" and not self.children[nid]), key=id_key)

    def archive(self) -> dict:
        return {
            "nodes": [self.nodes[nid].as_dict() for nid in sorted(self.nodes, key=id_key)],
            "edges": [{"source": source, "target": target, "weight": self.weights[source, target]}
                      for source, target in sorted(self.weights, key=lambda pair: (id_key(pair[0]), id_key(pair[1])))],
        }

    def topological_order(self) -> list[str] | None:
        indegree = {nid: len(parents) for nid, parents in self.parents.items()}
        queue = [(id_key(nid), nid) for nid, count in indegree.items() if count == 0]
        heapq.heapify(queue)
        order = []
        while queue:
            _, nid = heapq.heappop(queue)
            order.append(nid)
            for child in self.children[nid]:
                indegree[child] -= 1
                if indegree[child] == 0:
                    heapq.heappush(queue, (id_key(child), child))
        return order if len(order) == len(self.nodes) else None


def _node_id(value: str, line: int) -> str:
    if not re.fullmatch(r"\d+", value.strip()):
        raise GraphFormatError(f"line {line}: expected a nonnegative integer node ID")
    return str(int(value.strip()))


def _number(value: str, line: int) -> str:
    value = value.strip()
    try:
        valid = math.isfinite(float(value))
    except ValueError:
        valid = False
    if not valid:
        raise GraphFormatError(f"line {line}: metric/weight must be a finite number")
    return value  # Do not silently discard the original numeric token.


def read_text(text: str, *, edge_order: str = "target-source") -> Graph:
    if edge_order not in {"target-source", "source-target"}:
        raise ValueError("edge_order must be target-source or source-target")
    nodes, weights, diagnostics = {}, {}, []
    reader = csv.reader(io.StringIO(text.lstrip("\ufeff")), skipinitialspace=True, strict=True)
    try:
        for row in reader:
            line = reader.line_num
            if not row or all(not item.strip() for item in row):
                continue
            if len(row) == 4:
                raw_id, description, kind, metric = row
                nid = _node_id(raw_id, line)
                if nid in nodes:
                    raise GraphFormatError(f"line {line}: duplicate node ID {nid}")
                if kind.strip() not in {"AND", "OR", "LEAF"}:
                    raise GraphFormatError(f"line {line}: unsupported node type")
                nodes[nid] = Node(nid, description, kind.strip(), _number(metric, line))
            elif len(row) == 3:
                first, second, weight = row
                a, b = _node_id(first, line), _node_id(second, line)
                pair = (b, a) if edge_order == "target-source" else (a, b)
                weight = _number(weight, line)
                if pair in weights:
                    if weights[pair] != weight:
                        raise GraphFormatError(f"line {line}: conflicting duplicate edge {pair}")
                    diagnostics.append({"code": "duplicate_edge", "severity": "warning", "line": line})
                weights[pair] = weight
            else:
                raise GraphFormatError(f"line {line}: expected 3 (edge) or 4 (node) CSV fields")
    except csv.Error as error:
        raise GraphFormatError(f"line {reader.line_num}: malformed CSV") from error
    if not nodes:
        raise GraphFormatError("input contains no nodes")
    return Graph(nodes, weights, diagnostics)


def read_txt(path: str | Path, *, edge_order: str = "target-source", encoding: str = "utf-8-sig") -> Graph:
    return read_text(Path(path).read_text(encoding=encoding), edge_order=edge_order)
