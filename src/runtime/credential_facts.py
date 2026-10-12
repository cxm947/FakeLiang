"""Direct graph account facts and credential bindings."""
from __future__ import annotations

import re

from graph.terms import atom_value, is_variable, parse_fact
from runtime.credential_source import _error




FACT_FIELDS = ("logical", "graph_user", "symbol", "privilege")
ACCOUNT_FACT = re.compile(r"^\s*(get|has)Account\s*\(", re.IGNORECASE)


def graph_symbols(document) -> dict:
    """Which credential symbol the graph puts beside each account role.

    ``getAccount(host,user,symbol,privilege)`` names both the account *and* the material, and a
    deployment declares the material once. Without that link the verifier sees a dumped
    ``WHOAMIANONY\\Administrator`` and a fact that wants ``lab_domain_credential``, and the
    honest answer stays UNKNOWN (measured 2026-10-08, walk-139 node 5). This reads the graph's
    own account facts, so the link comes from the scenario rather than from a guess.
    """
    texts = []
    for node in (document or {}).get("nodes") or []:
        texts.append(node.get("description"))
        #: 账号事实写在依赖（或它引用的 OR 节点）里，不在节点自己的规则描述里。
        texts.extend(text for text, _producers in _dependencies(document, node))
    pairs = {}
    for description in texts:
        text = str(description or "")
        if not ACCOUNT_FACT.match(text):
            continue
        values = _fact(text, "getAccount") or _fact(text, "hasAccount")
        if not values:
            continue
        _host, user, symbol, _privilege = values
        pairs.setdefault(user, [])
        if symbol not in pairs[user]:
            pairs[user].append(symbol)
    return {user: sorted(symbols) for user, symbols in pairs.items()}


def _fact(description, name):
    text = str(description or "")
    try:
        fact = parse_fact(text)
    except ValueError:
        if text.lstrip().split("(", 1)[0].strip() == name:
            _error("FACT_INVALID")
        return None
    if fact.name != name:
        return None
    if len(fact.args) != 4 or any(is_variable(term) for term in fact.args):
        _error("FACT_INVALID")
    values = tuple(atom_value(term) for term in fact.args)
    if not all(values):
        _error("FACT_INVALID")
    return values


def _dependencies(document, node):
    """Resolve direct dependency labels, including OR nodes supplied by reference."""
    nodes = {str(item.get("id")): item for item in document.get("nodes") or []}
    for dependency in node.get("dependencies") or []:
        referred = nodes.get(str(dependency.get("ref")), {})
        description = dependency.get("description") or referred.get("description") or ""
        producers = [str(item) for item in dependency.get("produced_by") or []]
        if not producers and referred.get("type") == "OR":
            producers = [str(item.get("ref")) for item in referred.get("dependencies") or []
                         if item.get("type") == "AND"]
        yield description, producers


def produced_facts(document, node_id):
    """Deduplicate getAccount/4 in consumer produced_by and producer OR representations."""
    found = []
    for node in document.get("nodes") or []:
        for description, producers in _dependencies(document, node):
            if str(node_id) in producers:
                fact = _fact(description, "getAccount")
                if fact is not None and fact not in found:
                    found.append(fact)
        if node.get("type") == "OR":
            producers = [str(item.get("ref")) for item in node.get("dependencies") or []
                         if item.get("type") == "AND"]
            if str(node_id) in producers:
                fact = _fact(node.get("description"), "getAccount")
                if fact is not None and fact not in found:
                    found.append(fact)
    return found


def _bindings(document, node):
    target = str(node.get("target_host") or "")
    acquired, accounts = [], []
    for description, producers in _dependencies(document, node):
        fact = _fact(description, "getAccount")
        if fact is not None:
            acquired.append((fact, producers))
        fact = _fact(description, "hasAccount")
        if fact is not None and fact[0] == target:
            accounts.append(fact)
    bindings = []
    for fact, producers in acquired:
        if fact[0] == target or any(account[1:] == fact[1:] for account in accounts):
            bindings.append((fact, producers))
    # A proved credential on the same logical host also binds its declared hasAccount fact.
    bindings.extend((account, []) for account in accounts)
    if not target or not bindings:
        _error("BINDING_MISSING")
    return bindings
