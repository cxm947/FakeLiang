"""Conservative semantic reduction; reachability alone is not an OR proof."""

from copy import deepcopy

import networkx as nx


def prune_dependencies(nodes, edges):
    """Remove an OR prerequisite only when another required parent implies it.

    Guarantees contain prerequisites, not predicted execution results. Cyclic
    graphs are preserved unchanged: a circular path cannot witness implication.
    LEAF conditions are retained for pre-verification.
    """
    graph = nx.DiGraph()
    graph.add_nodes_from(nodes)
    graph.add_edges_from(edges)
    removed = []
    cyclic = not nx.is_directed_acyclic_graph(graph)
    if not cyclic:
        while True:
            guarantees = {}
            for nid in nx.lexicographical_topological_sort(graph, key=int):
                parents = list(graph.predecessors(nid))
                inherited = set()
                if parents and nodes[nid]["type"] == "AND":
                    inherited = set.union(*(guarantees[p] for p in parents))
                elif parents and nodes[nid]["type"] == "OR":
                    inherited = set.intersection(*(guarantees[p] for p in parents))
                guarantees[nid] = inherited | {nid}
            candidate = None
            for target in sorted(nodes, key=int):
                if nodes[target]["type"] != "AND":
                    continue
                parents = sorted(graph.predecessors(target), key=int)
                for parent in parents:
                    if nodes[parent]["type"] != "OR":
                        continue
                    witness = next((other for other in parents if other != parent
                                    and parent in guarantees[other]), None)
                    if witness is not None:
                        candidate = (parent, target, witness)
                        break
                if candidate:
                    break
            if candidate is None:
                break
            parent, target, witness = candidate
            graph.remove_edge(parent, target)
            removed.append({"src": parent, "dst": target, "witness": witness})
    result = deepcopy(nodes)
    for nid, node in result.items():
        node["parents"] = sorted(graph.predecessors(nid), key=int)
        node["children"] = sorted(graph.successors(nid), key=int)
    return result, {"removed_dependencies": removed, "cyclic": cyclic,
                    "pruned_edges": graph.number_of_edges()}


def incoming_type(node_id, nodes, retained):
    """Return a single gate only when it exactly represents the parent groups."""
    if nodes[node_id]["type"] == "OR":
        return "OR"

    def producers(nid, visiting):
        if nid in retained:
            return {nid}
        if nid in visiting or nodes[nid]["type"] != "OR":
            raise ValueError(f"node {node_id}: unsupported intermediate dependency {nid}")
        parents = nodes[nid]["parents"]
        if not parents:
            raise ValueError(f"node {node_id}: derived prerequisite {nid} has no producer")
        return set.union(*(producers(p, visiting | {nid}) for p in parents))

    groups = {frozenset(producers(p, set())) for p in nodes[node_id]["parents"]
              if nodes[p]["type"] != "LEAF"}
    if not groups or all(len(group) == 1 for group in groups):
        return "AND"
    if len(groups) == 1:
        return "OR"
    raise ValueError(f"node {node_id}: mixed AND/OR prerequisites cannot be represented by one type")
