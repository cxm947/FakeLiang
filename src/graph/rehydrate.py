"""The one loader: a 1.2.0 document -> the runtime view (and never back).

The document is a faithful mapping; the run needs derived facts (per-node prerequisites,
premise/effect refs, the rule case, the goal). They are rebuilt here from the document's own
source_graph with the same pure functions the generator uses, so every entry point reads one
derived section instead of each one inventing its own. Deriving never writes back: the payload
stays untouched and `document_payload` refuses derived keys on the save path.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from .cases import extract_fields, select_case
from .host_map import HostIndex
from .parser import Graph, GraphFormatError, digest, id_key, read_text
from .projector import project
from .protocol import transport_protocol
from .terms import atom_value

SCHEMA_VERSION = "1.2.0"
DOCUMENT_KEYS = ("schema_version", "final_goal", "inputs", "source_graph", "hosts", "nodes",
                 "diagnostics", "summary")
DERIVED_KEY = "semantics"


class GraphContractError(ValueError):
    """Not a 1.2.0 action graph, or the document contradicts its own source_graph."""


class Loaded(dict):
    """Runtime view: document keys, per-node derived facts, and the rebuilt source graph."""

    def __init__(self, view: dict, document: dict, graph: Graph, derived_diagnostics: list[dict]):
        super().__init__(view)
        self.document = document
        self.graph = graph
        self.derived_diagnostics = derived_diagnostics

    @property
    def nodes(self) -> list:
        return list(self.get("nodes") or [])


def _canonical(value):
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise GraphContractError("GRAPH_JSON_INVALID") from error


def _graph_from_source(source) -> Graph:
    required = {"format", "graph_hash", "nodes", "edges"}
    if (
        not isinstance(source, dict)
        or set(source) != required
        or source["format"] != "mulval_txt"
        or not isinstance(source["graph_hash"], str)
        or not source["graph_hash"]
    ):
        raise GraphContractError("GRAPH_SOURCE_INVALID")

    stream = io.StringIO()
    writer = csv.writer(stream)
    identities = {}

    for name, fields in (
        ("nodes", ("id", "description", "type", "metric")),
        ("edges", ("source", "target", "weight")),
    ):
        collection = source[name]
        if not isinstance(collection, list) or (name == "nodes" and not collection):
            raise GraphContractError("GRAPH_SOURCE_INVALID")

        seen = set()
        for row in collection:
            if (
                not isinstance(row, dict)
                or set(row) != set(fields)
                or any(not isinstance(row[key], str) for key in fields)
            ):
                raise GraphContractError("GRAPH_SOURCE_INVALID")

            identity = row["id"] if name == "nodes" else (row["source"], row["target"])
            if identity in seen:
                raise GraphContractError("GRAPH_SOURCE_DUPLICATE: " + name)
            seen.add(identity)
            writer.writerow([row[key] for key in fields])
        identities[name] = seen

    for source_id, target_id in identities["edges"]:
        if source_id not in identities["nodes"] or target_id not in identities["nodes"]:
            raise GraphContractError("GRAPH_SOURCE_DANGLING_EDGE")

    try:
        graph = read_text(stream.getvalue(), edge_order="source-target")
    except (GraphFormatError, csv.Error) as error:
        raise GraphContractError("GRAPH_SOURCE_INVALID: " + str(error)) from error

    archive = graph.archive()
    raw_archive = {
        "nodes": sorted(source["nodes"], key=lambda row: id_key(row["id"])),
        "edges": sorted(
            source["edges"],
            key=lambda row: (id_key(row["source"]), id_key(row["target"])),
        ),
    }
    if _canonical(raw_archive) != _canonical(archive):
        raise GraphContractError("GRAPH_SOURCE_NONCANONICAL")
    if source["graph_hash"] != digest(archive):
        raise GraphContractError("GRAPH_SOURCE_DIGEST_MISMATCH")
    return graph


def _check_projection(payload, graph):
    nodes = payload["nodes"]
    if (
        not isinstance(nodes, list)
        or not nodes
        or any(
            not isinstance(row, dict) or not isinstance(row.get("id"), str)
            for row in nodes
        )
    ):
        raise GraphContractError("GRAPH_PROJECTION_INVALID")

    ids = [row["id"] for row in nodes]
    if len(ids) != len(set(ids)):
        raise GraphContractError("GRAPH_PROJECTION_DUPLICATE")

    try:
        expected = project(
            graph,
            hosts=payload["hosts"],
            host_index=HostIndex(payload["hosts"]),
            inputs=payload["inputs"],
        )
    except (GraphFormatError, TypeError, ValueError, KeyError) as error:
        raise GraphContractError("GRAPH_PROJECTION_INVALID: " + str(error)) from error

    wanted = {row["id"]: row for row in expected["nodes"]}
    if set(ids) != set(wanted):
        raise GraphContractError("GRAPH_PROJECTION_NODE_SET")

    for row in nodes:
        if _canonical(row) != _canonical(wanted[row["id"]]):
            raise GraphContractError("GRAPH_PROJECTION_CHANGED: " + row["id"])

    for key in ("final_goal", "summary"):
        if _canonical(payload[key]) != _canonical(expected[key]):
            raise GraphContractError("GRAPH_PROJECTION_CHANGED: " + key)


def _requires(node_type: str, node_id: str, dependencies: list[dict]) -> list[dict]:
    """Describe premises without treating declarations or producers as observations."""
    if node_type != "AND":
        return []

    return [
        {
            "fact_ref": str(row["ref"]),
            "declaration_kind": (
                "assumption" if row["type"] == "LEAF" else "required_fact"
            ),
            "producer_refs": [str(item) for item in row.get("produced_by", [])],
        }
        for row in dependencies
    ]


def _view_node(node: dict, graph: Graph) -> dict:
    nid = str(node.get("id"))
    if nid not in graph.nodes:
        raise GraphContractError("node " + repr(nid) + " is not in source_graph")
    if graph.nodes[nid].type != str(node.get("type")):
        raise GraphContractError("node " + nid + ": document type " + repr(node.get("type"))
                                 + " != source_graph type " + repr(graph.nodes[nid].type))
    dependencies = node.get("dependencies")
    if not isinstance(dependencies, list):
        raise GraphContractError("node " + nid + " has no dependencies list")
    declared = sorted((str(dependency.get("ref")) for dependency in dependencies), key=id_key)
    parents = sorted(graph.parents[nid], key=id_key)
    if declared != parents:
        raise GraphContractError("node " + nid + ": dependencies " + repr(declared)
                                 + " are not the direct parents " + repr(parents))
    for dependency in dependencies:
        ref, kind = str(dependency.get("ref")), str(dependency.get("type"))
        if kind != graph.nodes[ref].type:
            raise GraphContractError("node " + nid + ": dependency " + ref + " typed " + repr(kind)
                                     + " != source_graph type " + repr(graph.nodes[ref].type))
        if kind == "OR":
            expected = sorted(graph.parents[ref], key=id_key)
            declared_by = sorted((str(item) for item in dependency.get("produced_by") or []), key=id_key)
            if declared_by != expected:
                raise GraphContractError("node " + nid + ": produced_by of " + ref + " " + repr(declared_by)
                                         + " != its direct producers " + repr(expected))
    derived = {"original_id": nid, "premise_refs": parents,
               "effect_refs": sorted(graph.children[nid], key=id_key),
               "requires": _requires(graph.nodes[nid].type, nid, dependencies),
               "case_id": None, "case_status": "not_applicable",
               "case_candidates": [], "details": {}}
    if graph.nodes[nid].type == "AND":
        selected = select_case(graph, nid)
        _, details = extract_fields(graph, nid, selected)
        derived["case_id"] = selected["case_id"]
        derived["case_status"] = selected["status"]
        derived["case_candidates"] = list(selected["candidates"])
        derived["details"] = details
    else:
        fact = graph.facts.get(nid)
        if fact is not None:
            derived["details"] = {"goal": {"predicate": fact.name,
                                           "arguments": [atom_value(argument) for argument in fact.args]}}
    return {**node, DERIVED_KEY: derived}


# Preserve the service spelling separately from its transport.
_WEB_SCHEMES = frozenset({"http", "https"})


def _fold_transport(node):
    if not isinstance(node, dict):
        return node
    value = node.get("protocol")
    spelled = "" if value is None else str(value)
    folded = dict(node, protocol=transport_protocol(value))
    if spelled in _WEB_SCHEMES:
        folded["scheme"] = spelled
    return folded


def load_document(payload: dict) -> Loaded:
    """Validate the archived document before deriving or folding runtime fields."""
    if not isinstance(payload, dict):
        raise GraphContractError("the graph must decode to a JSON object")

    version = payload.get("schema_version")
    if version != SCHEMA_VERSION:
        raise GraphContractError(
            "schema_version is " + repr(version) + "; this build reads "
            + repr(SCHEMA_VERSION) + " - regenerate with scripts/project_graph.py"
        )

    missing = [key for key in DOCUMENT_KEYS if key not in payload]
    if missing:
        raise GraphContractError("missing top-level key(s): " + ", ".join(missing))

    graph = _graph_from_source(payload.get("source_graph"))
    _check_projection(payload, graph)

    view_nodes = [
        _view_node(_fold_transport(node), graph)
        for node in payload["nodes"]
    ]
    derived_diagnostics = []
    for node in view_nodes:
        status = node[DERIVED_KEY]["case_status"]
        if node.get("type") == "AND" and status != "matched":
            derived_diagnostics.append({
                "code": "case_" + str(status),
                "node_ref": node["id"],
                "severity": "warning",
                "detail": "the selector cannot lock a rule case for this node",
            })

    return Loaded({**payload, "nodes": view_nodes}, payload, graph, derived_diagnostics)


def load_file(path) -> Loaded:
    return load_document(json.loads(Path(path).read_text(encoding="utf-8-sig")))


def ensure_view(document) -> Loaded:
    return document if isinstance(document, Loaded) else load_document(document)


def document_payload(loaded: Loaded) -> dict:
    """The save path: whitelisted document keys only, derived section refused."""
    payload = {key: loaded.document[key] for key in DOCUMENT_KEYS if key in loaded.document}
    for node in payload.get("nodes") or []:
        if isinstance(node, dict) and DERIVED_KEY in node:
            raise GraphContractError("derived section leaked into the document")
    return payload
