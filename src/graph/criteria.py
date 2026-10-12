"""这一步要证明什么：从图自己的依赖里算出判据清单（验证层的输入）。

2026-10-06（爷爷口径 D62）：攻击图**已经**给每条 LEAF 依赖带了机器判据 ——

    hacl(pc1,dc,tcp,445)              -> validation.kind = network_reachability
    networkServiceInfo(dc,smb,...)    -> service_exposure
    ttpExists(dc,smb,...)             -> capability
    hasAccount(dc,domain_administrator,...) -> credential
    isFirewall(pc2,flase)             -> environment_fact

但运行时一次都没读过它（全仓只有 graph/projector.py 在编译时数了一遍写进 summary）。于是"这一步
成没成"实际是卡片自称 + 模型自称，账本里那行 MODEL_CLAIM_NOT_MACHINE_VERIFIED 就是这件事的诚实写法。

这个模块只做一件事：把"这一步要证明的事实清单 + 每条的判据"算出来给验证阶段用。判据仍然只是判据 ——
它不决定谁来判；谁判由验证层定（模型先判、机器只在能真正证伪的地方兜底）。
"""

from __future__ import annotations

from .host_map import HostIndex
from .parser import id_key
from .rehydrate import ensure_view
from .terms import atom_value
from .validations import validation_of

# Categories describe facts; they do not establish checker availability.
VALIDATION_KINDS = (
    "network_reachability", "service_exposure", "capability", "credential",
    "environment_fact", "mount_share", "unknown",
)


def fact_row(document, ref):
    """Read one fact from the complete source graph."""
    view = ensure_view(document)
    graph = view.graph
    ref = str(ref)
    if ref not in graph.nodes or graph.nodes[ref].type == "AND":
        raise ValueError("CRITERIA_FACT_UNKNOWN: " + ref)

    raw = graph.nodes[ref]
    fact = graph.facts.get(ref)
    validation = validation_of(raw.description, HostIndex(view["hosts"]))
    return {
        "ref": ref,
        "type": raw.type,
        "fact": raw.description,
        "predicate": fact.name if fact else None,
        "arguments": [atom_value(argument) for argument in fact.args] if fact else [],
        "signature": fact.signature if fact else None,
        "declaration_kind": "assumption" if raw.type == "LEAF" else "derived_fact",
        "produced_by": sorted(graph.parents[ref], key=id_key) if raw.type == "OR" else [],
        "consumed_by": sorted(graph.children[ref], key=id_key),
        "validation_kind": validation["kind"],
        "validation_fields": validation["fields"],
    }


def _step(document, node_id):
    view = ensure_view(document)
    node_id = str(node_id)
    if node_id not in view.graph.nodes or view.graph.nodes[node_id].type != "AND":
        raise ValueError("CRITERIA_NODE_UNKNOWN: " + node_id)
    return view, node_id


def node_criteria(document, node_id) -> list:
    """Return all direct premises in stable source-graph order."""
    view, node_id = _step(document, node_id)
    return [
        fact_row(view, ref)
        for ref in sorted(view.graph.parents[node_id], key=id_key)
    ]


def to_produce(document, node_id) -> list:
    """Return every output, including intermediate facts omitted by the projection."""
    view, node_id = _step(document, node_id)
    return [
        fact_row(view, ref)
        for ref in sorted(view.graph.children[node_id], key=id_key)
    ]
