"""Execution identity and privilege evidence."""
from __future__ import annotations

import re


EXEC_CODE_SIGNATURE = "execCode/2"


def _exec_code_criterion(row):
    """An execCode output is a claim about an execution identity, and nothing less."""
    if row.get("signature") != EXEC_CODE_SIGNATURE:
        return None
    arguments = [str(part) for part in (row.get("arguments") or [])]
    if len(arguments) != 2 or not all(arguments):
        return None
    return {"ref": str(row.get("ref")), "logical": arguments[0], "privilege": arguments[1]}


def _observed_privilege(identity, privilege):
    """Compare a declared privilege with the identity the session actually reported."""
    if not isinstance(identity, dict):
        return False, "EXEC_IDENTITY_UNOBSERVED"
    uid = str(identity.get("uid") or "").strip()
    user = str(identity.get("user") or "").strip().lower()
    if not uid and not user:
        return False, "EXEC_IDENTITY_UNOBSERVED"
    wanted = str(privilege or "").strip().lower()
    if not wanted:
        return False, "EXEC_PRIVILEGE_UNDECLARED"
    if wanted == "root":
        return (uid == "0", "EXEC_IDENTITY_NOT_ROOT")
    if wanted == "system":
        return (user.endswith("\\system") or "nt authority" in user, "EXEC_IDENTITY_NOT_SYSTEM")
    normal = re.sub(r"[^a-z0-9]", "", wanted)
    return (bool(normal) and normal in re.sub(r"[^a-z0-9]", "", user),
            "EXEC_IDENTITY_ACCOUNT_MISMATCH")


def backstop_exec_code(
        *, criterion, sessions=(), host_map=None, node_id="", environments=None,
        observations=(), delivery=None, expected_delivery_owner=None):
    """Confirm an execCode output from attributable identity evidence.

    Explicit deliveries use only their retained carrier and their own identity
    snapshot. Without a delivery context, retain the existing node-owned
    observation/session paths.
    """
    from copy import deepcopy
    import re

    def unknown(reason, *, state="unknown", **details):
        return {
            "state": state,
            "verdict": "UNKNOWN",
            "checker": None,
            "evidence": [],
            "reason": reason,
            **details,
        }

    def binding(item):
        if not isinstance(item, dict):
            return None
        fields = (
            "channel_id", "kind", "session_id", "session_type",
            "platform", "host", "logical", "uuid",
        )
        return dict(
            {key: str(item.get(key) or "") for key in fields},
            endpoint=deepcopy(item.get("endpoint")),
        )

    address = str(
        (host_map or {}).get(criterion["logical"]) or criterion["logical"])
    declared_environment = str(
        (environments or {}).get(criterion["logical"]) or "")

    # None means no delivery context. Empty/malformed supplied contexts must
    # fail closed rather than fall back to an older source_node match.
    delivery_mode = (
        delivery is not None or expected_delivery_owner is not None
    )

    if delivery_mode:
        owner = str(expected_delivery_owner or "")
        if not re.fullmatch(r"delivery-[0-9a-f]{32}", owner):
            return unknown("EXEC_DELIVERY_OWNER_UNCONFIRMED")

        if not isinstance(delivery, dict):
            return unknown("EXEC_DELIVERY_RECEIPT_MISSING")

        receipt_node = str(delivery.get("node_id") or "")
        receipt_owner = delivery.get("delivery_owner")
        if receipt_node and receipt_node != str(node_id):
            return unknown("EXEC_DELIVERY_NODE_MISMATCH")
        if receipt_owner and receipt_owner != owner:
            return unknown("EXEC_DELIVERY_OWNER_MISMATCH")
        if not receipt_node or not receipt_owner:
            return unknown("EXEC_DELIVERY_ATTRIBUTION_UNCONFIRMED")
        if (
            delivery.get("state") != "completed"
            or delivery.get("matched") is not True
            or delivery.get("registered") is not True
        ):
            return unknown("EXEC_DELIVERY_NOT_COMPLETED")

        carrier = str(delivery.get("carrier") or "")
        if not carrier:
            return unknown("EXEC_DELIVERY_CARRIER_MISSING")

        candidates = [
            row for row in sessions or ()
            if str(row.get("channel_id") or "") == carrier
        ]
        if not candidates:
            return unknown("EXEC_DELIVERY_CARRIER_NOT_CURRENT")
        if len(candidates) != 1:
            return unknown(
                "EXEC_DELIVERY_CARRIER_AMBIGUOUS", state="ambiguous")

        row = candidates[0]
        if row.get("lifecycle") == "revoked":
            return unknown("EXEC_DELIVERY_BINDING_REVOKED")
        if row.get("kind") != "console_session":
            return unknown("EXEC_DELIVERY_CARRIER_INVALID")

        current_binding = binding(row)
        if not current_binding["uuid"]:
            return unknown("EXEC_DELIVERY_INCARNATION_UNCONFIRMED")

        endpoint = current_binding["endpoint"]
        if (
            not isinstance(endpoint, dict)
            or set(endpoint) != {"host", "port", "ssl"}
            or not isinstance(endpoint["host"], str)
            or not endpoint["host"]
            or type(endpoint["port"]) is not int
            or not 1 <= endpoint["port"] <= 65535
            or type(endpoint["ssl"]) is not bool
            or not current_binding["session_id"]
            or current_binding["session_type"] not in ("shell", "meterpreter")
            or not current_binding["platform"]
            or not current_binding["host"]
        ):
            return unknown("EXEC_DELIVERY_BINDING_INCOMPLETE")

        retained = delivery.get("retained_session")
        if binding(retained) != current_binding:
            return unknown("EXEC_DELIVERY_RETAINED_BINDING_MISMATCH")

        observed = delivery.get("carrier_observation")
        if not isinstance(observed, dict):
            return unknown("EXEC_DELIVERY_IDENTITY_SNAPSHOT_MISSING")
        if str(observed.get("carrier") or "") != carrier:
            return unknown("EXEC_DELIVERY_OBSERVATION_CARRIER_MISMATCH")
        if observed.get("binding") != current_binding:
            return unknown("EXEC_DELIVERY_OBSERVATION_BINDING_MISMATCH")
        if observed.get("state") != "alive":
            return unknown("EXEC_DELIVERY_CARRIER_UNOBSERVED")
        if not str(observed.get("call_id") or "").strip():
            return unknown("EXEC_DELIVERY_PROBE_CALL_UNRECORDED")

        identity = observed.get("identity")
        if not isinstance(identity, dict) or not identity:
            return unknown("EXEC_DELIVERY_IDENTITY_SNAPSHOT_MISSING")

        identity_call_id = str(
            observed.get("identity_call_id") or "").strip()
        if not identity_call_id:
            return unknown("EXEC_DELIVERY_IDENTITY_CALL_UNRECORDED")
        if str(identity.get("call_id") or "").strip() != identity_call_id:
            return unknown("EXEC_DELIVERY_IDENTITY_CALL_MISMATCH")

        observed_host = str(
            (host_map or {}).get(str(row.get("host")))
            or row.get("host") or "")
        if observed_host != address:
            return unknown("EXEC_DELIVERY_HOST_MISMATCH")

        # Do not fill missing current fields from row["identity"] or assume
        # that missing environment evidence means host execution.
        observed_environment = str(identity.get("environment") or "")
        if not observed_environment:
            return unknown("EXEC_DELIVERY_ENVIRONMENT_UNOBSERVED")
        if observed_environment != (declared_environment or "host"):
            return unknown("EXEC_DELIVERY_ENVIRONMENT_MISMATCH")

        matched, why = _observed_privilege(identity, criterion["privilege"])
        if not matched:
            return unknown(
                "EXEC_DELIVERY_IDENTITY_UNCONFIRMED",
                identity_reason=why,
            )

        evidence = [{
            "call_id": identity_call_id,
            "session_id": str(row.get("session_id") or ""),
            "channel_id": carrier,
            "uuid": current_binding["uuid"],
            "host": observed_host,
            "logical": criterion["logical"],
            "node_id": str(node_id),
            "delivery_owner": owner,
            "observed_identity": {
                "uid": identity.get("uid"),
                "user": identity.get("user"),
                "hostname": identity.get("hostname"),
                "environment": identity.get("environment"),
            },
            "observed_at": identity.get("at"),
        }]
        return {
            "state": "observed",
            "verdict": "TRUE",
            "checker": "session_observed_identity",
            "evidence": evidence,
            "reason": "",
        }

    # No explicit delivery: preserve the existing node-owned evidence paths.
    reason = "NO_REGISTERED_OUTPUT_SESSION"
    evidence = []

    for row in observations or ():
        if str(row.get("source_node") or "") != str(node_id):
            continue
        observed_logical = str(row.get("logical") or "")
        observed_host = str(
            (host_map or {}).get(observed_logical) or observed_logical)
        if observed_host != address:
            continue
        if str(row.get("environment") or "host") != (
                declared_environment or "host"):
            reason = "EXEC_ENVIRONMENT_MISMATCH"
            continue
        matched, why = _observed_privilege(
            row.get("identity"), criterion["privilege"])
        if not matched:
            reason = why
            continue
        evidence.append({
            "call_id": str(row.get("evidence_call_id") or ""),
            "session_id": "",
            "channel_id": str(row.get("channel_id") or ""),
            "host": observed_host,
            "logical": criterion["logical"],
            "observed_identity": dict(row.get("identity") or {}),
            "observed_at": row.get("at"),
            "context_id": row.get("context_id"),
        })

    for row in sessions or ():
        if str(row.get("source_node") or "") != str(node_id):
            continue
        observed_host = str(
            (host_map or {}).get(str(row.get("host")))
            or row.get("host") or "")
        if row.get("kind") != "console_session" or observed_host != address:
            continue
        if row.get("lifecycle") == "revoked":
            continue
        identity = row.get("identity")
        if not isinstance(identity, dict):
            reason = "EXEC_IDENTITY_UNOBSERVED"
            continue
        inside = str(identity.get("environment") or "host") == "container"
        if inside != (declared_environment == "container"):
            reason = "EXEC_ENVIRONMENT_MISMATCH"
            continue
        matched, why = _observed_privilege(identity, criterion["privilege"])
        if not matched:
            reason = why
            continue
        evidence.append({
            "call_id": str(identity.get("call_id") or ""),
            "session_id": str(row.get("session_id") or ""),
            "channel_id": str(row.get("channel_id") or ""),
            "host": observed_host,
            "logical": criterion["logical"],
            "observed_identity": {
                "uid": identity.get("uid"),
                "user": identity.get("user"),
                "hostname": identity.get("hostname"),
                "environment": identity.get("environment"),
            },
            "observed_at": identity.get("at"),
        })

    if not evidence:
        return unknown(reason)
    if len(evidence) > 1:
        return unknown("EXEC_EVIDENCE_AMBIGUOUS", state="ambiguous")
    if not evidence[0]["call_id"]:
        return unknown("EXEC_IDENTITY_CALL_UNRECORDED")
    return {
        "state": "observed",
        "verdict": "TRUE",
        "checker": "session_observed_identity",
        "evidence": evidence,
        "reason": "",
    }
