"""The supported predicate signatures and their positional parameter names."""

# Arity distinguishes the two ttpExists signatures without a special case.
PARAMETERS = {
    # Primitive predicates.
    ("inCompetent", 3): ("_user", "_host", "_perm"),
    ("hacl", 4): ("_src", "_dst", "_prot", "_port"),
    ("attackerLocated", 1): ("_host",),
    ("networkServiceInfo", 5): ("_host", "_program", "_protocol", "_port", "_user"),
    ("ttpExists", 6): ("_machine", "_vulID", "_program", "_range", "_tech", "_tactics"),
    ("ttpExists", 5): ("_machine", "_program", "_range", "_tech", "_tactics"),
    ("nfsMount", 5): ("_dst", "_dstpath", "_software", "_perm", "_sec"),
    ("leakAccount", 3): ("_user", "_host", "_perm"),
    ("hasAccount", 4): ("_host", "_user", "_passwd", "_perm"),
    ("pathExists", 4): ("_host", "_path", "_writable", "_perm"),
    ("isDocker", 2): ("_host", "_docker"),
    ("weakAccount", 4): ("_host", "_user", "_passwd", "_perm"),
    ("isFirewall", 2): ("_host", "_state"),
    # Derived predicates.
    ("execCode", 2): ("_host", "_user"),
    ("netAccess", 3): ("_machine", "_protocol", "_port"),
    ("attackVectorInjection", 4): ("_host", "_user", "_protocol", "_port"),
    ("getAccount", 4): ("_host", "_user", "_passwd", "_perm"),
    ("disableFirewall", 1): ("_host",),
}

PARAMETER_NAMES = {
    "_host": "host", "_machine": "host", "_src": "source_host", "_dst": "target_host",
    "_program": "service", "_protocol": "protocol", "_prot": "protocol", "_port": "port",
    "_user": "user", "_passwd": "credential", "_perm": "perm", "_writable": "writable",
    "_path": "path", "_docker": "docker", "_state": "state", "_vulID": "vuln_id",
    "_range": "scope", "_tech": "technique", "_tactics": "tactic", "_software": "software",
    "_dstpath": "dst_path", "_sec": "security", "_object": "object",
}


def parse_parameters(description: str) -> dict[str, str]:
    """Bind comma-separated arguments; unfamiliar labels keep only their text.

    This input format uses flat arguments, not nested terms or quoted commas.
    Bindings use public field names; descriptions retain the original values.
    """
    label = description.strip().removesuffix(".").rstrip()
    name, opening, arguments = label.partition("(")
    name = name.strip()
    if not any(predicate == name for predicate, _ in PARAMETERS):
        return {}
    if not opening or not arguments.endswith(")"):
        raise ValueError(f"malformed predicate {name}")
    values = [value.strip() for value in arguments[:-1].split(",")]
    names = PARAMETERS.get((name, len(values)))
    if names is None or any(not value for value in values):
        raise ValueError(f"invalid arguments for {name}: got {len(values)}")
    parameters = {PARAMETER_NAMES[parameter]: value[1:-1]
                  if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0] else value
                  for parameter, value in zip(names, values)}
    roles = {"host", "source_host", "target_host"}
    hosts = {value for name, value in parameters.items() if name in roles}
    if len(hosts) == 1:
        parameters = {"host": hosts.pop(),
                      **{name: value for name, value in parameters.items() if name not in roles}}
    return parameters


def credential_candidates(graph) -> list[str]:
    """Credential material names the graph declares; never a secret value."""
    found = set()
    for node in graph.get("nodes", []):
        dependencies = node.get("dependencies", {}) or {}
        for item in [node, *(dependencies.get("parents") or []),
                     *(dependencies.get("children") or [])]:
            value = item.get("credential")
            if not value and item.get("description"):
                try:
                    value = parse_parameters(item["description"]).get("credential")
                except (ValueError, TypeError):
                    value = None
            if value and str(value).strip():
                found.add(str(value).strip())
    return sorted(found)
