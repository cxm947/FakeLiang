"""Fact verdicts: this round's registered observations combine into one verdict per fact.

A producer's own step status never establishes a fact; only current evidence does.
"""
from __future__ import annotations

from orchestration.evidence import _evidence_context


def _machine_inconclusive(reason) -> bool:
    """Allow model fallback only when the machine has no applicable evidence."""
    text = str(reason or "")

    # Explicit delivery failures are never an absence-of-checker fallback.
    # Missing identity evidence must not be repaired by a model TRUE either.
    if text.startswith("EXEC_DELIVERY_") or text in {
        "EXEC_IDENTITY_UNOBSERVED",
        "EXEC_IDENTITY_CALL_UNRECORDED",
    }:
        return False

    return text in {
        "NO_REGISTERED_OUTPUT_SESSION",
        "CHECKER_UNAVAILABLE",
        "NO_APPLICABLE_RECEIPT",
    } or text.startswith("RECEIPT_")


def proof_of(node, result):
    """Read the executor's provisional pass claim; final acceptance requires the fact gate."""
    if not isinstance(result, dict):
        return False
    if result.get("status") != "model_reported":
        return False
    if str(result.get("claimed_verdict") or "") != "pass":
        return False
    if result.get("rejections") or result.get("pending_calls"):
        return False
    return bool(result.get("citations"))


def _unknown_fact(reason="FACT_UNCONFIRMED"):
    return {"verdict": "UNKNOWN", "checker": None, "proof": "partial",
            "evidence": [], "binding_epoch": None, "reason": reason}


def _record_assessment(verification, ref, *, graph_hash, binding_epoch):
    """Read only checker assessments bound to this graph and execution context."""
    if not isinstance(verification, dict):
        return _unknown_fact()
    if (verification.get("graph_hash") != graph_hash
            or verification.get("binding_epoch") != binding_epoch):
        return _unknown_fact("FACT_CONTEXT_MISMATCH")
    item = (verification.get("assessments") or {}).get(str(ref))
    if not isinstance(item, dict):
        return _unknown_fact()
    verdict = item.get("verdict")
    if verdict == "UNKNOWN":
        return _unknown_fact(str(item.get("reason") or "FACT_UNCONFIRMED"))
    if verdict not in ("TRUE", "FALSE", "UNRESOLVED_CONFLICT"):
        return _unknown_fact("FACT_ASSESSMENT_INVALID")
    if not isinstance(item.get("checker"), str) or not item["checker"].strip():
        return _unknown_fact("FACT_CHECKER_MISSING")
    if item.get("binding_epoch") != binding_epoch:
        return _unknown_fact("FACT_CONTEXT_MISMATCH")
    if verdict == "TRUE" and item.get("proof") != "sufficient":
        return _unknown_fact("FACT_PROOF_INSUFFICIENT")
    if verdict == "FALSE" and item.get("proof") != "necessary":
        return _unknown_fact("FACT_PROOF_INSUFFICIENT")
    evidence = item.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return _unknown_fact("FACT_EVIDENCE_MISSING")
    for record in evidence:
        if (not isinstance(record, dict)
                or not isinstance(record.get("call_id"), str)
                or not record["call_id"].strip()
                or record.get("fact_ref") != str(ref)
                or record.get("graph_hash") != graph_hash
                or record.get("binding_epoch") != binding_epoch):
            return _unknown_fact("FACT_EVIDENCE_BINDING_INVALID")
    return dict(item, evidence=[dict(record) for record in evidence])


def _fact_assessment(document, ref, state, *, host_map=None):
    """Combine applicable observations; producer status never establishes a fact."""
    from graph import criteria as graph_criteria

    fact = graph_criteria.fact_row(document, ref)
    graph_hash, epoch = _evidence_context(document, host_map)
    owners = fact["produced_by"] if fact["type"] == "OR" else list(state)
    checked = []
    for owner in owners:
        verification = (state.get(str(owner)) or {}).get("verification") or {}
        if verification.get("node_id") != str(owner):
            continue
        assessment = _record_assessment(
            verification, ref, graph_hash=graph_hash, binding_epoch=epoch)
        if assessment["verdict"] != "UNKNOWN":
            checked.append((str(owner), assessment))
    verdicts = {item["verdict"] for _, item in checked}
    if not verdicts:
        return _unknown_fact()
    if "UNRESOLVED_CONFLICT" in verdicts or {"TRUE", "FALSE"} <= verdicts:
        verdict, proof = "UNRESOLVED_CONFLICT", "partial"
    elif "TRUE" in verdicts:
        verdict, proof = "TRUE", "sufficient"
    else:
        verdict, proof = "FALSE", "necessary"
    relevant = [(owner, item) for owner, item in checked
                if verdict == "UNRESOLVED_CONFLICT" or item["verdict"] == verdict]
    return {"verdict": verdict, "checker": "combined_registered_assessments",
            "proof": proof, "binding_epoch": epoch,
            "evidence": [record for _, item in relevant for record in item["evidence"]],
            "supporting_nodes": [owner for owner, _ in relevant],
            "reason": "" if verdict == "TRUE" else "FACT_" + verdict}


def _fact_gate(*, document, node_id, verification, host_map=None):
    """Every output needs sufficient current evidence; UNKNOWN is not success."""
    from graph import criteria as graph_criteria

    graph_hash, epoch = _evidence_context(document, host_map)
    produced = graph_criteria.to_produce(document, node_id)
    required = graph_criteria.node_criteria(document, node_id)
    assessments = {
        row["ref"]: _record_assessment(
            verification, row["ref"], graph_hash=graph_hash, binding_epoch=epoch)
        for row in produced + required
    }
    denied = [ref for ref, item in assessments.items() if item["verdict"] == "FALSE"]
    conflicts = [ref for ref, item in assessments.items()
                 if item["verdict"] == "UNRESOLVED_CONFLICT"]
    missing = [row["ref"] for row in produced
               if assessments[row["ref"]]["verdict"] != "TRUE"]
    proved = bool(produced) and not denied and not conflicts and not missing
    source_call = ""
    if proved:
        source_call = assessments[produced[0]["ref"]]["evidence"][0]["call_id"]
    return {"proved": proved,
            "status": "proved" if proved else "failed" if denied else "unconfirmed",
            "reason": "" if proved else
                      "VERIFICATION_DENIED" if denied else
                      "VERIFICATION_CONFLICT" if conflicts else
                      "OUTPUT_FACT_UNCONFIRMED",
            "denied": denied, "unconfirmed": missing,
            "source_call": source_call}


def final_goal_rows(document, state, *, rows=(), host_map=None):
    """Evaluate terminal facts from checker evidence, independently of session rows."""
    from graph import criteria as graph_criteria

    goals = [str(item) for item in (document.get("final_goal") or [])]
    if not goals:
        return []
    out = []
    for node_id in goals:
        fact = graph_criteria.fact_row(document, node_id)
        assessment = _fact_assessment(document, node_id, state, host_map=host_map)
        established = assessment["verdict"] == "TRUE"
        arguments = fact.get("arguments") or []
        out.append({"node_id": node_id, "fact": fact["fact"],
                    "target": str(arguments[0]) if arguments else "",
                    "producers": list(fact["produced_by"]),
                    "proved_producers": list(assessment.get("supporting_nodes") or [])
                                       if established else [],
                    "session": "",
                    "declaration": fact, "assessment": assessment,
                    "established": established,
                    "reason": "" if established else
                              str(assessment.get("reason") or "FACT_UNCONFIRMED")})
    return out
