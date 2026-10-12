"""Prepare, receive, and cancel explicitly declared session deliveries."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import time
from uuid import uuid4

from runtime import msfservice, session_io, session_registry, sessions
from runtime.redact import collect_secrets, mask_secrets


from .session_delivery_plan import _save_delivery_plan



def _delivery_matches(root, plan, listing):
    """Choose only callbacks attributable to this delivery's own handler."""
    expected = plan["declaration"]["expected"]
    fresh = [(str(sid), info) for sid, info in listing.items()
             if str(sid) not in plan["before"] and isinstance(info, dict)]
    matches = [(sid, info) for sid, info in fresh
               if all(info.get(key) == value for key, value in expected.items())]
    local = expected.get("tunnel_local")
    if isinstance(local, str) and local.strip():
        correlated = [info for _, info in fresh
                      if info.get("tunnel_local") == local]
        if any(any(info.get(key) != value for key, value in expected.items())
               for info in correlated):
            raise ValueError("SESSION_DELIVERY_HANDLER_CONFLICT")
        platforms = {str(info.get("platform") or "").lower()
                     for info in correlated if info.get("platform")}
        if len(platforms) > 1:
            raise ValueError("SESSION_DELIVERY_HANDLER_CONFLICT")
        if matches:
            for path in sorted((Path(root) / "delivery").glob("*/plan.json")):
                if path.parent.name == plan["owner"]:
                    continue
                other = json.loads(path.read_text(encoding="utf-8"))
                if other.get("state") in ("cleaned", "not_started"):
                    continue
                other_expected = (other.get("declaration") or {}).get("expected") or {}
                if (other.get("endpoint") == plan["endpoint"]
                        and other_expected.get("tunnel_local") == local):
                    raise ValueError("SESSION_DELIVERY_OWNER_CONFLICT")
    elif len(matches) > 1:
        raise ValueError("SESSION_DELIVERY_AMBIGUOUS")

    def order(item):
        sid = item[0]
        return (0, int(sid), sid) if re.fullmatch(r"[0-9]+", sid) else (1, 0, sid)

    return sorted(matches, key=order)


def _repeat_callbacks(matches, selected):
    fields = ("uuid", "type", "session_host", "tunnel_local", "platform")
    return [dict(session_id=sid, **{key: info.get(key) for key in fields})
            for sid, info in matches if sid != selected]


def finish_session_delivery(
        *, executor, plan, rpc_conf, root, host, logical,
        privilege, node_id, timeout=40.0):
    """Match a delivery and obtain fresh identity on its retained carrier."""
    from copy import deepcopy

    from runtime import session_registry
    from runtime.runner import ownership

    owner = str(plan.get("owner") or "")
    if not re.fullmatch(r"delivery-[0-9a-f]{32}", owner):
        return {
            "state": "unknown",
            "reason": "SESSION_DELIVERY_OWNER_INVALID",
        }

    directory = Path(root) / "delivery" / owner
    receipt = None

    def unresolved(reason):
        return any(marker in str(reason) for marker in (
            "CHANNEL_CALL_UNRESOLVED",
            "NativeIdentityUnconfirmed",
        ))

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

    def valid_evidence(details, frozen_binding):
        if not isinstance(details, dict) or not isinstance(
                frozen_binding, dict):
            return False
        identity = details.get("identity")
        if not isinstance(identity, dict) or not identity:
            return False
        identity_call_id = str(
            details.get("identity_call_id") or "").strip()
        return bool(
            frozen_binding.get("uuid")
            and details.get("carrier") == frozen_binding["channel_id"]
            and details.get("binding") == frozen_binding
            and details.get("state") == "alive"
            and str(details.get("call_id") or "").strip()
            and identity_call_id
            and str(identity.get("call_id") or "").strip()
                == identity_call_id
        )


    def probe_recovery(row, frozen_binding):
        """Inspect original associated call records before allowing another probe."""
        from copy import deepcopy
        calls = {}
        try:
            for directory in (Path(root) / "session-calls").glob("*"):
                path = directory / "intent.json"
                if not path.is_file():
                    continue
                intent = json.loads(path.read_text(encoding="utf-8"))
                if intent.get("association") != owner:
                    continue
                if intent.get("binding_id") != frozen_binding["channel_id"]:
                    return "unknown", None
                if intent.get("phase") == "before_commit":
                    continue
                receipt_path = directory / "receipt.json"
                if not receipt_path.is_file():
                    return "unknown", None
                result = json.loads(receipt_path.read_text(encoding="utf-8"))
                if (result.get("call_id") != intent.get("call_id")
                        or result.get("binding_id") != intent.get("binding_id")
                        or result.get("association") != owner
                        or result.get("confirmed") is not True
                        or result.get("command_rc") != 0):
                    return "unknown", None
                calls[intent["call_id"]] = result
            if not calls:
                return "not_executed", None
            observation, identity = row.get("observation") or {}, row.get("identity") or {}
            call_id, identity_id = str(observation.get("call_id") or ""), str(identity.get("call_id") or "")
            proof = {"carrier": frozen_binding["channel_id"], "binding": deepcopy(frozen_binding),
                     "state": observation.get("state"), "reason": observation.get("reason"),
                     "at": observation.get("at"), "call_id": call_id,
                     "identity_call_id": identity_id, "identity": deepcopy(identity)}
            if call_id in calls and identity_id in calls and valid_evidence(proof, frozen_binding):
                return "finished", proof
        except (OSError, ValueError, TypeError, KeyError):
            pass
        return "unknown", None

    try:
        deadline = session_io._deadline(timeout)

        def remaining():
            value = deadline - time.monotonic()
            if value <= 0:
                raise ValueError("SESSION_DELIVERY_DEADLINE")
            return value

        with ownership(directory / ".plan-owner"):
            plan = json.loads(
                (directory / "plan.json").read_text(encoding="utf-8"))
            if plan.get("owner") != owner:
                raise ValueError("SESSION_DELIVERY_PLAN_MISMATCH")
            if str(plan.get("node_id") or "") != str(node_id):
                raise ValueError("SESSION_DELIVERY_NODE_MISMATCH")

            if plan.get("state") in ("delivered", "delivered_unobserved"):
                cached = plan.get("delivery_receipt")
                if not isinstance(cached, dict):
                    raise ValueError("SESSION_DELIVERY_RECEIPT_MISSING")
                if cached.get("delivery_owner") != owner:
                    raise ValueError("SESSION_DELIVERY_OWNER_MISMATCH")
                if str(cached.get("node_id") or "") != str(node_id):
                    raise ValueError("SESSION_DELIVERY_NODE_MISMATCH")

                # Old receipts cannot be upgraded using the current shared
                # row's identity. Keep their original evidence unchanged.
                if cached.get("state") == "completed":
                    frozen_binding = binding(cached.get("retained_session"))
                    if (
                        not frozen_binding
                        or cached.get("carrier")
                            != frozen_binding["channel_id"]
                        or not valid_evidence(
                            cached.get("carrier_observation"), frozen_binding)
                    ):
                        return dict(
                            deepcopy(cached),
                            state="unknown",
                            reason=(
                                "SESSION_DELIVERY_IDENTITY"
                                "_SNAPSHOT_UNCONFIRMED"
                            ),
                        )
                return deepcopy(cached)

            if plan.get("state") != "prepared":
                raise ValueError("SESSION_DELIVERY_PLAN_NOT_ACTIVE")
            original_phase = str(plan.get("receipt_phase") or "")
            saved_receipt = deepcopy(plan.get("delivery_receipt"))
            until = plan.get("receive_deadline_at")
            if until is None:
                until = time.time() + float(timeout)
                plan["receive_deadline_at"] = until
            if not isinstance(until, (int, float)) or isinstance(until, bool):
                raise ValueError("SESSION_DELIVERY_DEADLINE_INVALID")
            deadline = time.monotonic() + max(0.0, until - time.time())
            if not original_phase:
                plan["receipt_phase"] = "receiving"
            _save_delivery_plan(root, plan)

            call = session_io.rpc_call(
                host=rpc_conf.get("rpc_host", ""),
                port=rpc_conf.get("rpc_port", 0),
                user=rpc_conf.get("rpc_user", ""),
                password=rpc_conf.get("rpc_password", ""),
                timeout=remaining(),
            )
            expected = plan["declaration"]["expected"]
            if expected.get("session_host") != str(host):
                raise ValueError("SESSION_DELIVERY_HOST_MISMATCH")

            listing = {}
            while time.monotonic() < deadline:
                listing = call("session.list", deadline=deadline)
                if not isinstance(listing, dict) or listing.get("error"):
                    raise ValueError("SESSION_DELIVERY_LIST_UNCONFIRMED")

                matches = _delivery_matches(root, plan, listing)
                if not matches:
                    if original_phase in ("received", "registering", "registered", "probing", "probed"):
                        raise ValueError("SESSION_DELIVERY_RECEIVED_BINDING_CHANGED")
                    time.sleep(min(
                        0.2, max(0.0, deadline - time.monotonic())))
                    continue

                selected = matches[0]
                if original_phase in ("received", "registering", "registered", "probing", "probed"):
                    received = (saved_receipt or {}).get("received_session") or {}
                    selected = next((item for item in matches
                                     if item[0] == received.get("session_id")), None)
                    if selected is None:
                        raise ValueError("SESSION_DELIVERY_RECEIVED_BINDING_CHANGED")
                sid, info = selected
                if original_phase in ("received", "registering", "registered", "probing", "probed"):
                    frozen = (saved_receipt or {}).get("received_session") or {}
                    if (not isinstance(saved_receipt, dict)
                            or saved_receipt.get("sessions") != [sid]
                            or not frozen.get("uuid")
                            or frozen.get("uuid") != str(info.get("uuid") or "")):
                        raise ValueError("SESSION_DELIVERY_RECEIVED_BINDING_CHANGED")
                received_type = str(info.get("type") or "")
                receipt = {
                    "state": "unknown",
                    "reason": (
                        "SESSION_DELIVERY_MATCHED"
                        "_REGISTRATION_UNCONFIRMED"
                    ),
                    "node_id": str(node_id),
                    "delivery_owner": owner,
                    "matched": True,
                    "registered": False,
                    "sessions": [sid],
                    "callback_selection": "lowest_session_id",
                    "repeat_callbacks": _repeat_callbacks(matches, sid),
                    "session_types": {sid: received_type},
                    "received_session": {
                        "endpoint": dict(plan["endpoint"]),
                        "session_id": sid,
                        "session_type": received_type,
                        "uuid": str(info.get("uuid") or ""),
                        "host": str(info.get("session_host") or ""),
                    },
                }
                if isinstance(saved_receipt, dict) and original_phase in (
                        "received", "registering", "registered", "probing", "probed"):
                    receipt = deepcopy(saved_receipt)
                else:
                    plan.update(receipt_phase="received", delivery_receipt=receipt)
                    _save_delivery_plan(root, plan)
                alive = False
                probe_state = "unknown"
                observed = "SESSION_DELIVERY_REGISTRATION_UNCONFIRMED"
                confirmed_probe = None

                try:

                    saved_phase = plan.get("receipt_phase")
                    row = None
                    if saved_phase in ("registered", "probing", "probed"):
                        frozen = binding(receipt.get("retained_session"))
                        current = [item for item in session_registry.snapshot(root)
                                   if frozen and item.get("channel_id") == frozen["channel_id"]]
                        if len(current) != 1 or binding(current[0]) != frozen:
                            raise ValueError("SESSION_DELIVERY_CARRIER_BINDING_CHANGED")
                        row = current[0]
                    elif saved_phase == "registering":
                        registry = session_registry._registry(root)
                        matching = [item for item in registry["sessions"].values()
                                    if item.get("source_call") == owner
                                    and item.get("session_id") == sid
                                    and item.get("uuid") == str(info.get("uuid") or "")]
                        dropped = [item for item in registry.get("dropped", [])
                                   if item.get("source_call") == owner
                                   and item.get("source_node") == str(node_id)]
                        if dropped:
                            if len(dropped) != 1 or matching:
                                raise ValueError("SESSION_DELIVERY_REGISTRATION_AMBIGUOUS")
                            retained = registry["sessions"].get(dropped[0].get("kept"))
                            if not retained:
                                raise ValueError("SESSION_DELIVERY_REGISTRATION_ASSOCIATION_LOST")
                            matching = [retained]
                        if len(matching) > 1:
                            raise ValueError("SESSION_DELIVERY_REGISTRATION_AMBIGUOUS")
                        if matching:
                            row = dict(matching[0], registry_root=str(Path(root).resolve()))
                            if row.get("lifecycle") == "revoked":
                                raise ValueError("SESSION_DELIVERY_CARRIER_BINDING_CHANGED")
                    if row is None:
                        plan.update(receipt_phase="registering", delivery_receipt=receipt)
                        _save_delivery_plan(root, plan)
                        row = sessions.register_session(
                            root, endpoint=plan["endpoint"], session_id=sid,
                            logical=str(logical), source_node=str(node_id), source_call=owner,
                            capabilities=plan["declaration"]["capabilities"], expected=expected,
                            timeout=remaining(), privilege_term=str(privilege or ""))

                    # Registration may return an older retained carrier.
                    # Freeze that exact binding; retries may not replace it.
                    frozen_binding = binding(row)
                    carrier = frozen_binding["channel_id"]
                    if not carrier:
                        raise ValueError("SESSION_ROW_INCOMPLETE")

                    receipt.update(
                        registered=True,
                        carrier=carrier,
                        retained_session=dict(
                            deepcopy(frozen_binding),
                            source_node=str(row.get("source_node") or ""),
                            source_call=str(row.get("source_call") or ""),
                        ),
                    )

                    if plan.get("receipt_phase") not in ("probing", "probed"):
                        plan.update(receipt_phase="registered", delivery_receipt=receipt)
                        _save_delivery_plan(root, plan)
                    if original_phase in ("probing", "probed"):
                        recovery_state, proof = probe_recovery(row, frozen_binding)
                        if recovery_state == "unknown":
                            raise ValueError("SESSION_DELIVERY_PROBE_UNCONFIRMED")
                        if recovery_state == "finished":
                            confirmed_probe = proof
                            alive, observed, probe_state = True, str(proof.get("reason") or "SESSION_PROBE_CONFIRMED"), "alive"
                    for attempt in range(3):
                        if confirmed_probe is not None:
                            break
                        remaining()

                        if attempt:
                            current = [
                                item
                                for item in session_registry.snapshot(root)
                                if item.get("channel_id") == carrier
                            ]
                            if len(current) != 1:
                                raise ValueError(
                                    "SESSION_DELIVERY_CARRIER_STALE")
                            row = current[0]

                        if (
                            row.get("lifecycle") == "revoked"
                            or binding(row) != frozen_binding
                        ):
                            raise ValueError(
                                "SESSION_DELIVERY_CARRIER_BINDING_CHANGED")
                        if not row.get("endpoint") or not row.get("session_id"):
                            raise ValueError("SESSION_ROW_INCOMPLETE")

                        # A new target for every attempt prevents earlier
                        # partial/successful outputs leaking into this one.
                        probe_evidence = {}
                        plan.update(receipt_phase="probing", delivery_receipt=receipt)
                        _save_delivery_plan(root, plan)
                        association = session_io.CALL_ASSOCIATION.set(owner)
                        try:
                            alive, observed = sessions.probe(
                                row, timeout=remaining(), require_identity=True,
                                evidence_out=probe_evidence)
                        finally:
                            session_io.CALL_ASSOCIATION.reset(association)
                        observed = str(observed)

                        if observed == "CONSOLE_SESSION_GONE":
                            alive = False
                            probe_state = "dead"
                            break
                        if unresolved(observed):
                            alive = False
                            break

                        if alive:
                            if not valid_evidence(
                                    probe_evidence, frozen_binding):
                                alive = False
                                observed = (
                                    "SESSION_DELIVERY_IDENTITY"
                                    "_SNAPSHOT_UNCONFIRMED"
                                )
                                break
                            confirmed_probe = deepcopy(probe_evidence)
                            probe_state = "alive"
                            break
                        recovery_state, proof = probe_recovery(row, frozen_binding)
                        if recovery_state != "not_executed":
                            break

                except msfservice.MsfSessionMissing as error:
                    alive = False
                    probe_state = "dead"
                    observed = type(error).__name__ + ": " + str(error)
                except (
                    ValueError, OSError, RuntimeError,
                    msfservice.MsfUnreachable,
                ) as error:
                    alive = False
                    observed = type(error).__name__ + ": " + str(error)

                receipt["observation"] = observed

                if receipt["registered"]:
                    if confirmed_probe is not None:
                        receipt["carrier_observation"] = confirmed_probe
                    else:
                        receipt["carrier_observation"] = {
                            "carrier": receipt["carrier"],
                            "state": probe_state,
                            "reason": observed,
                        }

                    if alive and confirmed_probe is not None:
                        receipt.update(
                            state="completed",
                            reason=(
                                "SESSION_DELIVERY_MATCHED_REGISTERED"
                                "_CARRIER_OBSERVED"
                            ),
                        )
                    elif probe_state == "dead":
                        receipt.update(
                            state="failed",
                            reason=(
                                "SESSION_DELIVERY_MATCHED_REGISTERED"
                                "_SESSION_GONE: " + observed
                            ),
                        )
                    elif unresolved(observed):
                        receipt["reason"] = (
                            "SESSION_DELIVERY_MATCHED_REGISTERED"
                            "_PROBE_BLOCKED_UNRESOLVED: " + observed
                        )
                    else:
                        receipt["reason"] = (
                            "SESSION_DELIVERY_MATCHED_REGISTERED"
                            "_PROBE_UNCONFIRMED: " + observed
                        )
                else:
                    receipt.update(
                        state="failed" if probe_state == "dead" else "unknown",
                        reason=(
                            "SESSION_DELIVERY_MATCHED"
                            "_REGISTRATION_UNCONFIRMED: " + observed
                        ),
                    )

                plan["receipt_phase"] = "probed"
                plan.update(
                    state=(
                        "delivered"
                        if receipt["state"] == "completed"
                        else "delivered_unobserved"
                    ),
                    delivery_receipt=receipt,
                )
                _save_delivery_plan(root, plan)
                return receipt

            receipt = delivery_no_match_receipt(
                plan,
                listing if isinstance(listing, dict) else {},
                executor=executor,
            )
            receipt.update(node_id=str(node_id), delivery_owner=owner)
            plan.update(
                state="delivery_no_match",
                delivery_receipt=receipt,
            )
            _save_delivery_plan(root, plan)
            return receipt

    except msfservice.MsfSessionMissing:
        raise
    except (
        ValueError, OSError, RuntimeError, msfservice.MsfUnreachable
    ) as error:
        detail = type(error).__name__ + ": " + str(error)
        if receipt is not None:
            return dict(
                receipt,
                state="unknown",
                reason=(
                    str(
                        receipt.get("reason")
                        or "SESSION_DELIVERY_UNCONFIRMED"
                    )
                    + "; SESSION_DELIVERY_PERSISTENCE_UNCONFIRMED: "
                    + detail
                ),
                persistence_reason=detail,
            )
        return {
            "state": "unknown",
            "reason": "SESSION_DELIVERY_UNCONFIRMED: " + detail,
            "node_id": str(node_id),
            "delivery_owner": owner,
        }






def delivery_no_match_receipt(plan, listing, *, executor=None):
    """Say *why* nothing matched: which new sessions showed up, and whether the listener is up.

    "No callback" and "a callback whose fields did not line up" are different problems -- one is
    about starting the helper, the other about the expectation itself -- and a bare
    `SESSION_DELIVERY_NO_MATCH` cannot tell them apart. Measured 2026-10-08: roughly 40% of whole
    rounds missed the callback while an isolated replay worked every time, and the receipt kept
    none of the evidence that would separate the two.
    """
    expected = dict(((plan.get("declaration") or {}).get("expected")) or {})
    fields = ("type", "session_host", "tunnel_local", "tunnel_peer")
    fresh = []
    for sid, info in (listing or {}).items():
        if str(sid) in (plan.get("before") or []) or not isinstance(info, dict):
            continue
        fresh.append(dict({"session_id": str(sid)},
                          **{key: info.get(key) for key in fields}))
    receipt = {"state": "unknown", "reason": "SESSION_DELIVERY_NO_MATCH",
               "expected": expected, "new_sessions": fresh}
    handler = ((plan.get("declaration") or {}).get("handler")) or {}
    port = handler.get("lport")
    if executor is not None and port:
        #: The listener is ours to check: if it is gone, waiting longer could never have helped.
        try:
            probe = executor(["/bin/sh", "-c", "ss -lnt | grep -c ':%d '" % int(port)], 15.0)
            receipt["listener_lines"] = str(getattr(probe, "stdout", "") or "").strip()
        except (OSError, RuntimeError, ValueError) as error:
            receipt["listener_error"] = type(error).__name__
    return receipt
