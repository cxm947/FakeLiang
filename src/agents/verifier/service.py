"""Verification service: one node's premises get a verdict from this round's receipts."""
from __future__ import annotations

import json

from agents.verifier.prompts import RETRY_PREFIX, RETRY_SUFFIX

from orchestration.evidence import _evidence_context, _registered_receipts
from orchestration.verification.assessment import _machine_inconclusive, _unknown_fact
from agents.verifier.backstops import (
    _exec_code_criterion,
    _net_access_criterion,
    backstop_exec_code,
    backstop_reachability,
)
from runtime import session_registry
from runtime.lean import mask_secrets


def _verification_sources(document, node_id, scope, *, host_map, position_host,
                          carrier=None, proxy=()):
    """Bind only an exact declared source address to the selected execution position."""
    from graph import criteria as graph_criteria

    if proxy or not position_host or not scope.get("vantage"):
        return {}
    sources = set()
    for row in graph_criteria.node_criteria(document, node_id):
        if row.get("signature") != "hacl/4":
            continue
        source = ((row.get("validation_fields") or {}).get("from") or {}).get("term")
        if not source:
            continue
        if carrier is not None and carrier.get("logical") != source:
            continue
        if str(host_map.get(source) or source) == str(position_host):
            sources.add(str(source))
    return {scope["vantage"]: sources.pop()} if len(sources) == 1 else {}


def _credit_verify_claims(verdict_facts, by_call):
    """Credit only the quotes that are really in the cited receipt; drop the rest **by name**.

    One wrongly-quoted fact is that fact's problem, not the whole turn's. walk-158 node 26 measured
    the cost of the blunt version: the produced fact cited a real receipt line (`uid=0(root)`), two
    premises cited the *command text* instead of its output, the turn was refused outright, and the
    step that had worked went from "established" to "no evidence at all".
    """
    claims, dropped = {}, []
    for item in verdict_facts:
        if item["call_id"]:
            call = by_call.get(item["call_id"])
            if call is None or (item["quote"] not in call["stdout"]
                                and item["quote"] not in call["stderr"]):
                dropped.append(str(item["ref"]))
                continue
        claims[item["ref"]] = dict(item, claimed_verifier=item["verifier"], verifier="model")
    return claims, dropped


def verify_node(
        *, client, document, node_id, run_dir, root, executor=None, host_map=None,
        secrets=(), source_bindings=None, environments=None, role_accounts=None,
        delivery=None, expected_delivery_owner=None) -> dict:
    """Keep model claims separate from concrete checker assessments."""
    from copy import deepcopy

    from graph import criteria as graph_criteria
    from agents.verifier import runner as verify_mod

    # Keep the delivery's caller-owned evidence fixed across model verification.
    delivery = deepcopy(delivery)

    graph_hash, epoch = _evidence_context(document, host_map)
    calls, receipt_issues = _registered_receipts(run_dir)
    consumed = graph_criteria.node_criteria(document, node_id)
    produced = graph_criteria.to_produce(document, node_id)
    task = verify_mod.verification_task(
        document, node_id, harvest=session_registry.snapshot(root), calls=calls,
        graph_criteria=consumed, must_produce=produced,
        host_map=host_map, source_bindings=source_bindings,
        role_accounts=role_accounts)
    task["calls"] = [
        {
            "call_id": call["call_id"],
            "request": call["request"],
            "scope": call["scope"],
            "stdout": call["stdout"],
            "stderr": call["stderr"],
        }
        for call in calls
    ]
    task["receipt_issues"] = receipt_issues
    expected = [row["ref"] for row in task["facts"]]
    claims, claim_error = {}, ""
    model_assessments = {}

    if callable(getattr(client, "complete", None)):
        try:
            from runtime import model_log

            reply = model_log.complete_logged(
                client, run_dir=run_dir, task="verify", system=verify_mod.SYSTEM,
                user=json.dumps(task, ensure_ascii=False), secrets=secrets)
            if not getattr(reply, "ok", False):
                raise ValueError(
                    str(getattr(reply, "error", "") or "MODEL_REPLY"))
            payload = getattr(reply, "payload", None)
            if not isinstance(payload, dict):
                payload = json.loads(getattr(reply, "text", "") or "{}")

            try:
                verdict = verify_mod.read_verdict(
                    payload, expected_refs=expected,
                    credited_calls=[call["call_id"] for call in calls])
            except ValueError as shape_error:
                model_log.record(
                    run_dir, task="verify", source="verify_shape_retry",
                    metadata=mask_secrets(
                        {"error": str(shape_error)[:200]}, secrets))
                retry = model_log.complete_logged(
                    client, run_dir=run_dir, task="verify",
                    system=(
                        verify_mod.SYSTEM
                        + RETRY_PREFIX
                        + str(shape_error)[:200]
                        + RETRY_SUFFIX
                    ),
                    user=json.dumps(task, ensure_ascii=False),
                    secrets=secrets)
                if not getattr(retry, "ok", False):
                    raise ValueError(
                        str(getattr(retry, "error", "") or "MODEL_REPLY"))
                payload = getattr(retry, "payload", None)
                if not isinstance(payload, dict):
                    payload = json.loads(getattr(retry, "text", "") or "{}")
                verdict = verify_mod.read_verdict(
                    payload, expected_refs=expected,
                    credited_calls=[call["call_id"] for call in calls])

            refs = [item["ref"] for item in verdict["facts"]]
            if len(refs) != len(set(refs)):
                raise ValueError("VERIFY_REF_DUPLICATE")

            by_call = {call["call_id"]: call for call in calls}
            claims, dropped = _credit_verify_claims(verdict["facts"], by_call)
            if dropped:
                claim_error = (
                    "VERIFY_QUOTE_NOT_IN_RECEIPT: " + ",".join(dropped))

            model_assessments = {
                ref: {
                    "verdict": "TRUE",
                    "checker": "model",
                    "proof": "sufficient",
                    "binding_epoch": epoch,
                    "reason": "",
                    "evidence": [{
                        "call_id": row["call_id"],
                        "quote": row["quote"],
                        "fact_ref": ref,
                        "graph_hash": graph_hash,
                        "binding_epoch": epoch,
                    }],
                }
                for ref, row in claims.items()
                if row["verdict"] == "TRUE"
                and row["proof"] == "sufficient"
                and row["call_id"] in by_call
                and str(row.get("quote") or "").strip()
            }
        except (ValueError, OSError, RuntimeError, AttributeError) as error:
            claims = {}
            claim_error = str(error)[:300]
    else:
        claim_error = "NO_MODEL"

    assessments, facts, backstops = {}, [], {}
    for row in task["facts"]:
        ref = row["ref"]
        assessment = _unknown_fact("CHECKER_UNAVAILABLE")
        criterion = _net_access_criterion(row, consumed)
        probe = None

        if criterion is not None:
            probe = backstop_reachability(
                row=criterion, receipts=calls, host_map=host_map,
                source_bindings=source_bindings)
        else:
            exec_criterion = _exec_code_criterion(row)
            if exec_criterion is not None:
                probe = backstop_exec_code(
                    criterion=exec_criterion,
                    sessions=session_registry.snapshot(root),
                    host_map=host_map,
                    node_id=node_id,
                    environments=environments,
                    observations=session_registry.observations(root),
                    delivery=delivery,
                    expected_delivery_owner=expected_delivery_owner,
                )

        if probe is not None:
            backstops[ref] = probe
            assessment = _unknown_fact(
                probe["reason"] or "FACT_UNCONFIRMED")
            if probe["verdict"] == "TRUE":
                assessment = {
                    "verdict": "TRUE",
                    "checker": probe["checker"],
                    "proof": "sufficient",
                    "binding_epoch": epoch,
                    "reason": "",
                    "evidence": [
                        dict(
                            item,
                            fact_ref=ref,
                            graph_hash=graph_hash,
                            binding_epoch=epoch,
                        )
                        for item in probe["evidence"]
                    ],
                }
            elif (
                ref in model_assessments
                and _machine_inconclusive(probe.get("reason"))
            ):
                assessment = dict(model_assessments[ref])
        elif ref in model_assessments:
            assessment = dict(model_assessments[ref])

        assessments[ref] = assessment
        facts.append({
            "ref": ref,
            "verdict": assessment["verdict"],
            "proof": assessment["proof"],
            "verifier": assessment["checker"] or None,
            "claimed_verdict": (claims.get(ref) or {}).get("verdict"),
            "model_claim": claims.get(ref),
            "reason": assessment["reason"],
        })

    return {
        "state": (
            "verified"
            if not claim_error or any(
                item["verdict"] != "UNKNOWN"
                for item in assessments.values())
            else "refused"
        ),
        "reason": claim_error,
        "node_id": str(node_id),
        "graph_hash": graph_hash,
        "binding_epoch": epoch,
        "facts": facts,
        "assessments": assessments,
        "model_claims": claims,
        "backstops": backstops,
        "receipt_issues": receipt_issues,
    }
