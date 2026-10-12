"""TCP reachability evidence from registered receipts."""
from __future__ import annotations


REACHABILITY_PROBE = ["nmap", "--unprivileged", "-Pn", "-n", "-sT", "--reason",
                      "-p", "{port}", "-oX", "-", "{host}"]


def backstop_reachability(*, row, executor=None, rows=(), host_map=None, timeout=90.0,
                          receipts=(), source_bindings=None) -> dict:
    """Check existing TCP receipts; never select a carrier or execute a probe.

    source_bindings maps an execution-layer vantage identifier to its established
    graph source host. It must not come from model output or guessed aliases.
    """
    import xml.etree.ElementTree as ET
    from graph.protocol import transport_protocol

    unknown = {"state": "unknown", "verdict": "UNKNOWN", "quote": "", "checker": None,
               "vantage": "", "evidence": [], "reason": "NO_APPLICABLE_RECEIPT"}
    if row.get("signature") != "hacl/4":
        return dict(unknown, reason="CHECKER_UNAVAILABLE")
    fields = row.get("validation_fields") or {}
    source = (fields.get("from") or {}).get("term")
    target = (fields.get("to") or {}).get("term")
    protocol = transport_protocol(fields.get("protocol"))
    try:
        port = int(str(fields.get("port")))
    except (ValueError, TypeError):
        return dict(unknown, reason="REACHABILITY_FIELDS_INVALID")
    if not source or not target or protocol != "tcp" or not 1 <= port <= 65535:
        return dict(unknown, reason="REACHABILITY_FIELDS_INVALID")
    address = str((host_map or {}).get(str(target)) or target)
    bindings = source_bindings or {}
    expected = [part.format(port=str(port), host=address) for part in REACHABILITY_PROBE]
    reason = "NO_APPLICABLE_RECEIPT"

    for call in receipts:
        scope = call["scope"]
        vantage = scope.get("vantage")
        if bindings.get(vantage) != str(source):
            reason = "SOURCE_BINDING_UNAVAILABLE"
            continue
        if (scope.get("host") != address or str(scope.get("port")) != str(port)
                or scope.get("protocol") != "tcp"):
            reason = "RECEIPT_TARGET_MISMATCH"
            continue
        request = call["request"]
        if (request.get("tool") != "tool" or request.get("name") != expected[0]
                or request.get("args") != expected[1:]):
            reason = "RECEIPT_REQUEST_NOT_TCP_PROBE"
            continue
        try:
            root = ET.fromstring(call["output"])
        except ET.ParseError:
            reason = "RECEIPT_XML_INVALID"
            continue
        if root.tag != "nmaprun":
            reason = "RECEIPT_XML_INVALID"
            continue
        scans = root.findall("scaninfo")
        finished = root.find("./runstats/finished")
        if (len(scans) != 1 or scans[0].get("type") != "connect"
                or scans[0].get("protocol") != "tcp"
                or scans[0].get("services") != str(port)
                or finished is None or finished.get("exit") != "success"):
            reason = "RECEIPT_SCAN_UNCONFIRMED"
            continue
        matching = []
        for host in root.findall("host"):
            if not any(item.get("addr") == address for item in host.findall("address")):
                continue
            matching.extend(item for item in host.findall("./ports/port")
                            if item.get("protocol") == "tcp"
                            and item.get("portid") == str(port))
        if len(matching) != 1:
            reason = "RECEIPT_PORT_NOT_UNIQUE"
            continue
        state = matching[0].find("state")
        if state is None or state.get("state") != "open":
            reason = "PORT_NOT_OPEN"
            continue
        return {"state": "connected", "verdict": "TRUE", "checker": "registered_tcp_open",
                "quote": call["stdout"], "vantage": vantage, "reason": "",
                "evidence": [{"call_id": call["call_id"],
                              "request_digest": call["request_digest"],
                              "scope": dict(scope),
                              "source_binding": {"vantage": vantage, "source_host": str(source)},
                              "artifacts": dict(call["receipt"]["artifacts"])}]}
    return dict(unknown, reason=reason)


def _net_access_criterion(row, consumed):
    """Bind a netAccess output to its unique direct, source-bearing premise."""
    from graph.protocol import transport_protocol

    if row.get("signature") != "netAccess/3":
        return row if row.get("signature") == "hacl/4" else None
    arguments = row.get("arguments") or []
    if len(arguments) != 3:
        return None
    target, protocol, port = map(str, arguments)
    matches = []
    for premise in consumed:
        fields = premise.get("validation_fields") or {}
        if (premise.get("signature") == "hacl/4"
                and (fields.get("to") or {}).get("term") == target
                and transport_protocol(fields.get("protocol")) == transport_protocol(protocol)
                and str(fields.get("port")) == port):
            matches.append(premise)
    return dict(matches[0], ref=row["ref"]) if len(matches) == 1 else None
