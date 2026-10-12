"""Shared graph reading and ordering; the scheduler does not own these."""
from __future__ import annotations

from graph import rehydrate
from orchestration.verification.assessment import _fact_assessment


def graph_nodes(document):
    """Use source-graph action membership and the loader's validated node payloads."""
    view = rehydrate.ensure_view(document)
    nodes = {str(node["id"]): node for node in view.nodes}
    return [nodes[node_id] for node_id in view.graph.actions]


def needs(document, node_id):
    """Read alternative producers for each direct OR premise from the complete graph."""
    from graph import criteria

    return [list(fact["produced_by"])
            for fact in criteria.node_criteria(document, node_id)
            if fact["type"] == "OR"]


def flat_producers(document, node_id):
    """Read producer relationships for traversal and reporting, never as proof."""
    from graph.parser import id_key

    return sorted({producer for group in needs(document, node_id) for producer in group},
                  key=id_key)


def _node_sort_key(value):
    """节点号排序：本项目的节点号是数字，测试/别的图可能给名字 —— 名字排在数字后面，不炸。"""
    text = str(value)
    return (0, int(text), "") if text.isdigit() else (1, 0, text)


def satisfied(document, node_id, state, *, host_map=None):
    """Require observed TRUE premises; a producer's step status is not fact evidence."""
    from graph import criteria

    return all(_fact_assessment(document, fact["ref"], state,
                                host_map=host_map)["verdict"] == "TRUE"
               for fact in criteria.node_criteria(document, node_id))
