"""LEAF validation fields (E6): what a checker can look at - never a claim of truth.

Kinds and fields are the frozen mapping (unchanged since 1.1.0; specs/003 spec section 1):
network_reachability /
service_exposure / credential / capability / environment_fact / mount_share / unknown.
Signatures without a mapping stay explicit 'unknown' instead of being defaulted true.
"""

from __future__ import annotations

from .terms import atom_value, parse_fact

ENVIRONMENT_FACTS = ("isFirewall", "isDocker", "pathExists", "attackerLocated", "inCompetent")


def _host(hosts, term: str) -> dict:
    return hosts.entry(term) if hosts is not None else {"term": term}


def validation_of(description: str, hosts=None) -> dict:
    """Map one LEAF node's text to {"kind", "fields"}; unresolvable text stays 'unknown'."""
    try:
        fact = parse_fact(description)
    except ValueError:
        return {"kind": "unknown", "fields": {"predicate": None, "raw": str(description)}}
    name, args = fact.name, [atom_value(argument) for argument in fact.args]
    count = len(args)
    if name == "hacl" and count == 4:
        return {"kind": "network_reachability", "fields": {"from": _host(hosts, args[0]), "to": _host(hosts, args[1]),
                                                           "protocol": args[2], "port": args[3]}}
    if name == "networkServiceInfo" and count == 5:
        return {"kind": "service_exposure", "fields": {"host": _host(hosts, args[0]), "service": args[1],
                                                       "protocol": args[2], "port": args[3], "privilege": args[4]}}
    if name == "nfsMount" and count == 5:
        return {"kind": "mount_share", "fields": {"host": _host(hosts, args[0]), "path": args[1], "service": args[2],
                                                  "permission": args[3], "server": _host(hosts, args[4])}}
    if name in ("hasAccount", "weakAccount") and count == 4:
        return {"kind": "credential", "fields": {"host": _host(hosts, args[0]), "user": args[1],
                                                 "secret": args[2], "privilege": args[3]}}
    if name == "leakAccount" and count == 3:
        return {"kind": "credential", "fields": {"user": args[0], "host": _host(hosts, args[1]),
                                                 "privilege": args[2]}}
    if name == "ttpExists" and count == 5:
        return {"kind": "capability", "fields": {"host": _host(hosts, args[0]), "object": None, "software": args[1],
                                                 "side": args[2], "capability": args[3], "tactic": args[4]}}
    if name == "ttpExists" and count == 6:
        return {"kind": "capability", "fields": {"host": _host(hosts, args[0]), "object": args[1], "software": args[2],
                                                 "side": args[3], "capability": args[4], "tactic": args[5]}}
    if name in ENVIRONMENT_FACTS:
        return {"kind": "environment_fact", "fields": {"predicate": name, "arguments": args}}
    return {"kind": "unknown", "fields": {"predicate": name, "arguments": args}}