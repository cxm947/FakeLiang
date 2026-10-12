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
from .session_delivery_finish import finish_session_delivery, delivery_no_match_receipt

def begin_session_delivery(*, executor, rpc_conf, root, node="",
                           target_host="", timeout=120.0, declaration=None):
    """Prepare an explicit delivery plan without synthesizing its payload, position, or ports."""
    from runtime.runner import ownership
    required = {"prepare", "cleanup", "resources", "expected", "capabilities", "command"}
    if not isinstance(declaration, dict) or not required.issubset(declaration):
        raise ValueError("SESSION_DELIVERY_DECLARATION_REQUIRED")
    if (not isinstance(declaration["prepare"], list) or not declaration["prepare"]
            or not isinstance(declaration["cleanup"], list) or not declaration["cleanup"]
            or not isinstance(declaration["expected"], dict)
            or declaration["expected"].get("session_host") != str(target_host)
            or declaration["expected"].get("type") not in ("shell", "meterpreter")
            or not isinstance(declaration["command"], str) or not declaration["command"].strip()):
        raise ValueError("SESSION_DELIVERY_DECLARATION_INVALID")
    #: Recognise a delivery by a correlation the runtime itself controls: the console's own
    #: incarnation when it exposes one, or the reserved handler port it came back to.
    if not any(isinstance(declaration["expected"].get(key), str)
               and declaration["expected"][key].strip()
               for key in ("uuid", "exploit_uuid", "tunnel_local")):
        raise ValueError("SESSION_DELIVERY_CORRELATION_REQUIRED")
    call = session_io.rpc_call(
        host=rpc_conf.get("rpc_host", ""), port=rpc_conf.get("rpc_port", 0),
        user=rpc_conf.get("rpc_user", ""), password=rpc_conf.get("rpc_password", ""), timeout=timeout)
    before = call("session.list")
    if not isinstance(before, dict) or before.get("error"):
        raise ValueError("SESSION_DELIVERY_BASELINE_UNCONFIRMED")
    owner = "delivery-" + uuid4().hex
    plan = {"owner": owner, "before": list(before), "declaration": declaration,
            "command": declaration["command"], "node_id": str(node), "state": "declared",
            "endpoint": {"host": call.endpoint.host, "port": call.endpoint.port,
                         "ssl": call.endpoint.ssl}}
    encoded = json.dumps(plan, ensure_ascii=False, sort_keys=True, allow_nan=False)
    redactions = collect_secrets(plan, [rpc_conf.get("rpc_password") or ""])
    if mask_secrets(encoded, redactions) != encoded:
        raise ValueError("SESSION_DELIVERY_PLAN_CONTAINS_SECRET")
    directory = Path(root) / "delivery" / owner
    failure = None
    with ownership(directory / ".plan-owner"):
        _save_delivery_plan(root, plan)
        try:
            session_registry.reserve_resources(root, owner=owner, resources=declaration["resources"])
        except (ValueError, OSError) as error:
            plan.update(state="not_started", reason=str(error))
            _save_delivery_plan(root, plan)
            raise
        plan["state"] = "preparing"
        _save_delivery_plan(root, plan)
        try:
            for index, step in enumerate(declaration["prepare"]):
                receipt = session_io._delivery_action(executor, root, owner, "prepare-" + str(index), step,
                                           secrets=(rpc_conf.get("rpc_password"),))
                if not receipt["confirmed"] or receipt["command_rc"] != 0:
                    raise ValueError("SESSION_DELIVERY_PREPARATION_UNCONFIRMED")
        except (ValueError, OSError, RuntimeError, msfservice.MsfUnreachable) as error:
            plan.update(state="preparation_unconfirmed", reason=str(error))
            _save_delivery_plan(root, plan)
            failure = error
        else:
            handler = declaration.get("handler")
            if not handler:
                plan["state"] = "prepared"
                _save_delivery_plan(root, plan)
            else:
                #: The listener must live in the console this run already talks to, or the
                #: session it catches would never be visible to the acceptance step.
                try:
                    plan.update(handler_phase="before_commit",
                                handler_deadline_at=time.time() + min(60.0, float(timeout)))
                    _save_delivery_plan(root, plan)
                    plan["handler_phase"] = "committing"
                    _save_delivery_plan(root, plan)
                    started = call("module.execute", "exploit", "multi/handler",
                                   {"PAYLOAD": str(handler["payload"]),
                                    "LHOST": str(handler["lhost"]),
                                    "LPORT": int(handler["lport"]),
                                    "ExitOnSession": False},
                                   deadline=session_io._deadline(max(0.001, plan["handler_deadline_at"] - time.time())))
                except (ValueError, OSError, RuntimeError,
                        msfservice.MsfUnreachable) as error:
                    plan.update(state="handler_unconfirmed", reason=str(error))
                    _save_delivery_plan(root, plan)
                    failure = error
                else:
                    plan["handler_phase"] = "after_commit"
                    plan["handler_job"] = (started or {}).get("job_id")
                    plan["state"] = "prepared"
                    _save_delivery_plan(root, plan)
    if failure is not None:
        cancel_session_delivery(executor=executor, plan=plan, rpc_conf=rpc_conf, root=root)
        raise failure
    return plan


def cancel_session_delivery(*, executor, plan, rpc_conf, root):
    """Recover the registered cleanup plan and never replay an unsettled cleanup call."""
    from runtime.runner import ownership
    owner = str(plan.get("owner") or "")
    if not re.fullmatch(r"delivery-[0-9a-f]{32}", owner):
        return {"state": "unknown", "reason": "SESSION_DELIVERY_OWNER_INVALID"}
    directory = Path(root) / "delivery" / owner
    receipts = []
    try:
        with ownership(directory / ".plan-owner"):
            stored = json.loads((directory / "plan.json").read_text(encoding="utf-8"))
            if stored.get("owner") != owner:
                raise ValueError("SESSION_DELIVERY_PLAN_MISMATCH")
            if stored.get("state") in ("cleaned", "not_started"):
                return {"state": "completed", "receipts": stored.get("cleanup_receipts", [])}
            steps = (stored.get("declaration") or {}).get("cleanup")
            if not isinstance(steps, list) or not steps:
                raise ValueError("SESSION_DELIVERY_CLEANUP_REQUIRED")
            job_id = stored.get("handler_job")
            if type(job_id) is int and rpc_conf:
                try:
                    call = session_io.rpc_call(
                        host=rpc_conf.get("rpc_host", ""),
                        port=rpc_conf.get("rpc_port", 0), user=rpc_conf.get("rpc_user", ""),
                        password=rpc_conf.get("rpc_password", ""), timeout=30.0)
                    call("job.stop", job_id, deadline=session_io._deadline(30.0))
                    stored["handler_stopped"] = True
                except (ValueError, OSError, RuntimeError, msfservice.MsfUnreachable) as error:
                    stored["handler_stop_reason"] = str(error)[:200]
                _save_delivery_plan(root, stored)
            stored["state"] = "cleaning"
            _save_delivery_plan(root, stored)
            for index, step in enumerate(steps):
                receipt = session_io._delivery_action(executor, root, owner, "cleanup-" + str(index), step,
                                           secrets=(rpc_conf.get("rpc_password"),))
                receipts.append(receipt)
                if not receipt["confirmed"] or receipt["command_rc"] != 0:
                    raise ValueError("SESSION_RESOURCE_CLEANUP_UNCONFIRMED")
            session_registry.release_resources(root, owner=owner, receipts=receipts)
            stored.update(state="cleaned", cleanup_receipts=receipts)
            _save_delivery_plan(root, stored)
    except (ValueError, OSError, RuntimeError, msfservice.MsfUnreachable) as error:
        return {"state": "unknown", "reason": str(error), "receipts": receipts}
    return {"state": "completed", "receipts": receipts}


def undo_relay_delivery(carrier, facts, *, timeout=60.0):
    """Release only what this plan owns on the pivot: the forward we installed and the file we sent.

    A settled session keeps its route -- its traffic still flows through it -- so this belongs to
    the failure path. Each step carries its own receipt: one step failing is reported as that step
    failing, never as "cleaned up" (the external review's rule for owned resources, 2026-10-08).
    """
    from runtime import relay as relay_mod

    receipts = []
    port = int((facts or {}).get("pivot_port") or 0)
    if port:
        listing = session_io.call_bound(carrier, {"tool": "msf", "cmd": "portfwd list"}, timeout)
        index = relay_mod.portfwd_index(str(getattr(listing.get("outcome"), "stdout", "") or ""), port)
        if index:
            removed = session_io.call_bound(
                carrier, {"tool": "msf", "cmd": " ".join(relay_mod.portfwd_delete_argv(index))},
                timeout)
            receipts.append({"step": "portfwd-delete", "confirmed": bool(removed.get("confirmed")),
                             "command_rc": removed.get("command_rc")})
        else:
            receipts.append({"step": "portfwd-delete", "confirmed": True,
                             "note": "no forward on that port"})
    remote = str((facts or {}).get("remote_stager") or "")
    if remote:
        cleaned = session_io.call_bound(
            carrier, {"tool": "cmd", "cmd": "del %s %s.b64 >nul 2>&1 & echo cleaned"
                      % (remote, remote)}, timeout)
        receipts.append({"step": "pivot-file", "confirmed": bool(cleaned.get("confirmed")),
                         "command_rc": cleaned.get("command_rc")})
    return receipts
