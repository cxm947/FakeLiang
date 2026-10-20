"""One dependency-based index for both Pre and Action, without execution IO."""

from collections.abc import Mapping, Sequence

import networkx as nx

from src.graph.predicates import parse_parameters
from .execution_session import (SessionRecord, SessionResolution,
                                SessionResolutionFailure)


def resolve_session(document: Mapping, node_id: str, sessions: Sequence[SessionRecord],
                    *, controller_rules: Sequence[str] = (),
                    entry_actors: Mapping[str, str] | None = None) -> SessionResolution:
    """Find parent ORs, then repeat OR <- AND <- OR until execCode is found.

    Input: parser graph document (original or action projection), a graph node
    ID, and registry records for ONE run. Dependencies, not projected edges,
    define ancestry. execCode's host/user are the exact host/privilege key.
    Multiple branches must agree on that key; no host or privilege fallback.

    An execution source is one of exactly two kinds. The exact execCode key is used
    whenever it exists. Only when it does not, a node whose ancestry really reaches a
    located controller actor -- and whose own rule is declared as controller-originated
    in controller_rules -- binds to the run's single active controller entry named by
    entry_actors[actor]. Anything else stays a missing ancestor: an unresolvable key is
    never silently treated as the control end.
    """
    def failure(reason):
        return SessionResolutionFailure(reason=reason, node_id=node_id)

    graph = nx.DiGraph()
    node_rules = {}

    def add(record):
        ident = record["id"]
        # Action projection's top-level type describes its incoming gate;
        # rule_desc still identifies the original AND node.
        kind = "AND" if "rule_desc" in record else record["type"]
        definition = {"kind": kind, "description": record["description"]}
        if (kind not in {"AND", "OR", "LEAF"} or not isinstance(ident, str)
                or not isinstance(record["description"], str)):
            raise ValueError("Invalid node")
        if ident in graph and graph.nodes[ident] != definition:
            raise ValueError("Conflicting node definitions")
        graph.add_node(ident, **definition)
        # The rule text lives only on the top-level record; nested parent/child copies
        # carry none, so it is kept beside the graph rather than inside node attributes.
        if "rule_desc" in record:
            node_rules[ident] = str(record["rule_desc"] or "")
        return ident

    try:
        for record in document["nodes"]:
            ident = add(record)
            for parent in record["dependencies"]["parents"]:
                graph.add_edge(add(parent), ident)
            for child in record["dependencies"]["children"]:
                graph.add_edge(ident, add(child))
        if not nx.is_directed_acyclic_graph(graph):
            return failure("invalid_graph")
    except (KeyError, TypeError, ValueError):
        return failure("invalid_graph")
    if node_id not in graph:
        return failure("node_not_found")
    if len({record.run_id for record in sessions}) > 1:
        return failure("mixed_runs")

    def parents(ident, kind):
        return {parent for parent in graph.predecessors(ident)
                if graph.nodes[parent]["kind"] == kind}

    def parent_ors(ident):
        return parents(ident, "OR") | {
            ancestor for parent in parents(ident, "AND")
            for ancestor in parents(parent, "OR")}

    def controller_actor():
        """Prove the control end as this node's source, or return None.

        Requires: the ancestor set really contains attackerLocated(actor); every hacl
        ancestor originates from that same actor; the node's own rule is declared
        controller-originated. A rule that needs a target-side context therefore never
        reaches here, because its execCode key exists and is used instead.
        """
        actors, hacl_sources = set(), set()
        for ident in nx.ancestors(graph, node_id):
            description = graph.nodes[ident]["description"]
            name = description.partition("(")[0].strip()
            if name == "attackerLocated":
                actors.add(description.partition("(")[2].rstrip(")").strip())
            elif name == "hacl":
                hacl_sources.add(description.partition("(")[2].split(",")[0].strip())
        if len(actors) != 1 or len(hacl_sources) > 1 or not actors <= hacl_sources:
            return None
        # A declared rule prefix may name either the rule text ("Direct Network Access")
        # or the rule identity carried by the description ("RULE 1 (...)").
        texts = (node_rules.get(node_id, ""), graph.nodes[node_id]["description"])
        if not any(text.startswith(prefix) for prefix in controller_rules for text in texts):
            return None
        return next(iter(actors))

    pending, seen, keys = parent_ors(node_id), set(), set()
    while pending:
        ident = pending.pop()
        if ident in seen:
            continue
        seen.add(ident)
        description = graph.nodes[ident]["description"]
        if description.partition("(")[0].strip() == "execCode":
            try:
                parameters = parse_parameters(description)
                keys.add((parameters["host"], parameters["user"]))
            except (KeyError, ValueError):
                return failure("invalid_graph")
        else:
            pending.update(parent_ors(ident))

    if not keys:
        actor = controller_actor()
        session_id = (entry_actors or {}).get(actor) if actor is not None else None
        if session_id is None:
            return failure("ancestor_not_found")
        entry = next((record for record in sessions
                      if record.status == "active"
                      and record.binding_kind == "controller_entry"
                      and record.session_id == session_id), None)
        return entry.reference() if entry is not None else failure("session_not_found")
    if len(keys) != 1:
        return failure("ambiguous_ancestor")
    key = next(iter(keys))
    matches = [record for record in sessions
               if record.status == "active"
               and record.binding_kind == "console_session"
               and (record.host, record.privilege) == key]
    if not matches:
        return failure("session_not_found")
    if len(matches) != 1:
        return failure("ambiguous_session")
    return matches[0].reference()
