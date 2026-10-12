"""Match one grounded rule instance, preserving host/account variable binding."""

from __future__ import annotations

from collections import Counter

from .parser import Graph, id_key
from .rule_catalog import CASES, PATTERNS
from .terms import Fact, atom_value, is_variable, term_key


def unify(pattern: Fact, actual: Fact, bindings: dict) -> dict | None:
    if pattern.signature != actual.signature:
        return None
    result = dict(bindings)
    for expected, value in zip(pattern.args, actual.args):
        if expected == "_":
            continue
        if is_variable(expected):
            if expected in result and term_key(result[expected]) != term_key(value):
                return None
            result[expected] = value
        elif term_key(expected) != term_key(value):
            return None
    return result


def _match_case(case, head, facts, *, budget=2048):
    head_pattern, patterns = PATTERNS[case.id]
    if Counter(f.signature for _, f in facts) != Counter(
        f.signature for f in patterns
    ):
        return [], False

    bindings = unify(head_pattern, head, {})
    if bindings is None:
        return [], False

    # Premise references follow template order, not node-id order.
    states = [(0, frozenset(), bindings, [])]
    solutions, visited = [], 0

    while states:
        visited += 1
        if visited > budget:
            # Completed solutions remain useful, but the search is incomplete.
            return solutions, True

        index, used, current, refs = states.pop()
        if index == len(patterns):
            def resolve(term):
                return current.get(term) if is_variable(term) else term

            pairs = [
                (resolve(left), resolve(right))
                for left, right in case.different
            ]
            if all(
                left is not None
                and right is not None
                and term_key(left) != term_key(right)
                for left, right in pairs
            ):
                solution = {
                    "bindings": dict(current),
                    "premise_refs": list(refs),
                }
                if solution not in solutions:
                    solutions.append(solution)
            continue

        for position, (ref, fact) in enumerate(facts):
            if position in used:
                continue
            matched = unify(patterns[index], fact, current)
            if matched is not None:
                states.append((
                    index + 1,
                    used | {position},
                    matched,
                    [*refs, ref],
                ))

    return solutions, False


def select_case(graph: Graph, action: str) -> dict:
    refs = sorted(graph.parents[action], key=id_key)
    outputs = sorted(graph.children[action], key=id_key)
    base = {
        "status": "unknown",
        "case_id": None,
        "candidates": [],
        "reason": None,
        "bindings": {},
        "premise_refs": [],
    }

    if len(outputs) != 1 or any(
        ref not in graph.facts for ref in refs + outputs
    ):
        return {
            **base,
            "reason": "unparsed_context_or_non_single_effect",
        }

    facts = [(ref, graph.facts[ref]) for ref in refs]

    # Ground dif/2 declarations are checked even when exporters retain them.
    if any(
        fact.signature == "dif/2"
        and term_key(fact.args[0]) == term_key(fact.args[1])
        for _, fact in facts
    ):
        return {**base, "reason": "false_explicit_dif"}

    facts = [
        (ref, fact)
        for ref, fact in facts
        if fact.signature != "dif/2"
    ]

    choices, exhausted = [], False
    for item in CASES:
        solutions, over_budget = _match_case(
            item, graph.facts[outputs[0]], facts,
        )
        exhausted |= over_budget
        choices.extend(
            {"case_id": item.id, **solution}
            for solution in solutions
        )

    # An incomplete search cannot establish uniqueness.
    if exhausted:
        return {
            **base,
            "candidates": choices,
            "reason": "match_budget_exceeded",
        }
    if len(choices) == 1:
        return {
            **base,
            **choices[0],
            "status": "matched",
            "candidates": choices,
        }
    if choices:
        return {
            **base,
            "status": "ambiguous",
            "candidates": choices,
            "reason": "multiple_bindings_or_cases",
        }
    return {
        **base,
        "reason": "signature_value_or_binding_mismatch",
    }


def extract_fields(graph: Graph, action: str, match: dict) -> tuple[dict, dict]:
    """Extract roles from the selected binding and its template-ordered premises."""
    fields = dict.fromkeys((
        "source_host", "target_host", "service",
        "protocol", "port", "vulnerability",
    ))
    outputs = sorted(graph.children[action], key=id_key)
    details = {
        "case_status": match["status"],
        "case_candidates": list(match["candidates"]),
        "premises": [
            {
                "ref": ref,
                "type": graph.nodes[ref].type,
                "fact": graph.nodes[ref].description,
            }
            for ref in sorted(graph.parents[action], key=id_key)
        ],
        "outputs": [
            {"ref": ref, "fact": graph.nodes[ref].description}
            for ref in outputs
        ],
    }
    if match["status"] != "matched":
        return fields, details

    head = graph.facts[outputs[0]]
    fields["target_host"] = atom_value(head.args[0])
    if head.name in {"execCode", "getAccount", "attackVectorInjection"}:
        details["target_privilege"] = atom_value(
            head.args[-1] if head.name == "getAccount" else head.args[1]
        )

    details["bindings"] = dict(match["bindings"])
    details["premise_refs"] = list(match["premise_refs"])
    facts = [
        (ref, graph.facts[ref])
        for ref in match["premise_refs"]
    ]

    def sole(*signatures):
        found = [
            fact
            for _, fact in facts
            if fact.signature in signatures
        ]
        if len(found) > 1:
            raise ValueError(
                "CASE_FIELD_AMBIGUOUS: " + ",".join(signatures)
            )
        return found[0] if found else None

    acl = sole("hacl/4")
    service = sole("networkServiceInfo/5")
    ttp = sole("ttpExists/5", "ttpExists/6")
    source_exec = sole("execCode/2")
    previous_exec = [
        (ref, fact)
        for ref, fact in facts
        if fact.signature == "execCode/2"
    ]

    if acl is not None:
        fields.update(
            source_host=atom_value(acl.args[0]),
            protocol=atom_value(acl.args[2]),
            port=atom_value(acl.args[3]),
        )
    elif source_exec is not None:
        fields["source_host"] = atom_value(source_exec.args[0])

    if service is not None:
        fields.update(
            service=atom_value(service.args[1]),
            protocol=atom_value(service.args[2]),
            port=atom_value(service.args[3]),
        )
    elif head.name in {"netAccess", "attackVectorInjection"}:
        fields.update(
            protocol=atom_value(head.args[-2]),
            port=atom_value(head.args[-1]),
        )

    if ttp is not None:
        has_vulnerability = len(ttp.args) == 6
        if has_vulnerability:
            fields["vulnerability"] = atom_value(ttp.args[1])
        if fields["service"] is None:
            fields["service"] = atom_value(
                ttp.args[2 if has_vulnerability else 1]
            )
        details.update(
            handle_range=atom_value(ttp.args[-3]),
            technique=atom_value(ttp.args[-2]),
            tactic=atom_value(ttp.args[-1]),
        )

    if previous_exec:
        details["source_privileges"] = [
            {
                "host": atom_value(fact.args[0]),
                "privilege": atom_value(fact.args[1]),
            }
            for _, fact in previous_exec
        ]

    for ref, fact in facts:
        arguments = list(map(atom_value, fact.args))
        if fact.signature == "pathExists/4":
            details["path"] = {
                "host": arguments[0],
                "path": arguments[1],
                "access": arguments[2],
                "privilege": arguments[3],
            }
        elif fact.signature == "nfsMount/5":
            details["mount"] = {
                "target_host": arguments[0],
                "path": arguments[1],
                "service": arguments[2],
                "access": arguments[3],
                "source_host": arguments[4],
            }
        elif fact.signature == "isDocker/2":
            details["container"] = {
                "host": arguments[0],
                "container": arguments[1],
            }
        elif fact.signature == "isFirewall/2":
            # Preserve the source literal, including 'flase'.
            details["firewall_state"] = arguments[1]
        elif fact.signature in {"hasAccount/4", "weakAccount/4", "getAccount/4"}:
            details.setdefault("accounts", []).append({
                "host": arguments[0],
                "user": arguments[1],
                "privilege": arguments[3],
                "credential_fact_ref": ref,
            })
        elif fact.signature == "leakAccount/3":
            details.setdefault("accounts", []).append({
                "host": arguments[1],
                "user": arguments[0],
                "privilege": arguments[2],
                "credential_fact_ref": ref,
            })
        elif fact.signature == "inCompetent/3":
            details["injection_user"] = arguments[0]

    return fields, details
