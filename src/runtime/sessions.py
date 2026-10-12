"""Register exact bindings and observe whether sessions remain usable."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import time
from uuid import uuid4

from runtime import msfservice, session_identity, session_io, session_registry


from .session_registration import (
    WEB_ENTRY_PROBE, _identity, register_web_position, register_session, revoke_session,
)

def _probe_web_entry(row, executor, *, deadline, observation):
    """Send one framed command through the entry client; the entry's own answer is the proof.

    A web entry is a leftover resource, not a connection (external review 2026-10-08): the row
    says where it is and how this run talks to it, and **every** use -- this one included -- has to
    observe it again. A client that cannot reach it says so and the step that wanted the position
    is refused; nothing here replays the chain that planted the entry.
    """
    if executor is None:
        observation["reason"] = "SESSION_PROBE_OBSERVER_REQUIRED"
    else:
        try:
            call = session_io.position_call(row, {"tool": "cmd",
                                       "cmd": str(row.get("probe_command") or WEB_ENTRY_PROBE)},
                                 executor=executor,
                                 timeout=max(0.1, deadline - time.monotonic()))
            #: 探针自己的退出码也算证据：入口能回帧但命令没跑成（例如命令被拼坏）时，
            #: 这条位置**不能用**（2026-10-08 真机 node 26：节点靠"帧齐了"就放行，进去每条命令 127）。
            if call["confirmed"]:
                observation.update(state="alive", reason="WEB_ENTRY_CONFIRMED",
                                   call_id=call["marker"])
            else:
                observation["reason"] = ("WEB_ENTRY_UNCONFIRMED"
                                         if call["framed"] else "WEB_ENTRY_UNCONFIRMED: no frame")
                if call["framed"]:
                    observation["command_rc"] = call["command_rc"]
        except (OSError, ValueError, RuntimeError) as error:
            observation["reason"] = type(error).__name__ + ": " + str(error)
    root = row.get("registry_root")
    #: 没有观测者时**不写账本**：这条位置不是"死了"，只是这个进程（常驻探活没有控制端的入口
    #: 客户端）看不见它。把它记成不可用会让后面真正能用的那一步被挡掉。
    if root and executor is not None:
        def update(value):
            found = value["sessions"].get(row["channel_id"])
            if found is None or found.get("lifecycle") == "revoked":
                raise ValueError("SESSION_BINDING_STALE")
            found["observation"] = observation
        session_registry._mutate(root, update)
    return observation["state"] == "alive", observation["reason"]
def probe(
        row, executor=None, *, timeout=30.0,
        require_identity=False, evidence_out=None):
    """Prove session I/O and optionally publish this probe's identity evidence.

    The default return value remains (alive, reason). Requesting evidence
    forces a fresh identity read. Evidence is published only after the
    registered binding has been checked during the registry update.
    """
    from copy import deepcopy

    if evidence_out is not None:
        if not isinstance(evidence_out, dict):
            raise ValueError("SESSION_PROBE_EVIDENCE_TARGET_INVALID")
        evidence_out.clear()

    row = deepcopy(row)
    need_identity = bool(require_identity or evidence_out is not None)
    deadline = session_io._deadline(timeout)
    observation = {
        "state": "unknown",
        "at": time.time(),
        "reason": "SESSION_PROBE_UNCONFIRMED",
    }

    if str(row.get("session_type") or "") in ("web", "entry"):
        if need_identity:
            return False, "SESSION_PROBE_IDENTITY_UNSUPPORTED"
        return _probe_web_entry(
            row, executor, deadline=deadline, observation=observation)

    def binding(item):
        fields = (
            "channel_id", "kind", "session_id", "session_type",
            "platform", "host", "logical", "uuid",
        )
        return dict(
            {key: str(item.get(key) or "") for key in fields},
            endpoint=deepcopy(item.get("endpoint")),
        )

    frozen_binding = binding(row)

    def check_shape(info):
        if (
            str(info.get("type") or "") != frozen_binding["session_type"]
            or str(info.get("uuid") or "") != frozen_binding["uuid"]
        ):
            raise ValueError("SESSION_BINDING_CHANGED")
        if need_identity and (
            str(info.get("session_host") or "") != frozen_binding["host"]
            or str(info.get("platform") or "") != frozen_binding["platform"]
        ):
            raise ValueError("SESSION_BINDING_CHANGED")

    identity = {}
    confirmed_identity = {}
    previous_identity = row.get("identity")
    recorded = (
        isinstance(previous_identity, dict)
        and bool(str(previous_identity.get("user") or "").strip())
        and bool(str(previous_identity.get("call_id") or "").strip())
    )
    native_identity_started = False

    try:
        if need_identity:
            if not row.get("registry_root"):
                raise ValueError("SESSION_BINDING_UNREGISTERED")
            if not frozen_binding["uuid"]:
                raise ValueError("SESSION_INCARNATION_UNCONFIRMED")

        client = msfservice.client_for(
            session_io._endpoint(row["endpoint"]), deadline=deadline)
        info = msfservice.session_shape(
            client, row["session_id"], deadline=deadline)
        check_shape(info)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("SESSION_PROBE_DEADLINE")

        if str(row.get("session_type") or "") == "meterpreter":
            commands = (
                ("getuid", "sysinfo")
                if need_identity or not recorded
                else ("getuid",)
            )
            native_identity_started = True
            answered = session_identity.observe_native_identity(
                row, deadline=deadline, commands=commands)

            if need_identity or not recorded:
                identity = deepcopy(answered or {})

            call_id = str((answered or {}).get("call_id") or "").strip()
            if answered and call_id:
                confirmed_identity = deepcopy(answered)
                observation.update(
                    state="alive",
                    reason="CONSOLE_IDENTITY_CONFIRMED",
                    call_id=call_id,
                )
        else:
            receipt = session_io.call_bound(
                row,
                {"tool": "cmd", "cmd": "echo agv-session-probe"},
                remaining,
            )
            if receipt["confirmed"] and receipt["command_rc"] == 0:
                observation.update(
                    state="alive",
                    reason="SESSION_PROBE_CONFIRMED",
                    call_id=receipt["call_id"],
                )

                if need_identity or not recorded:
                    try:
                        answered = session_identity.observe_identity(
                            row, deadline=deadline)
                        identity = deepcopy(answered or {})
                        if answered and str(
                                answered.get("call_id") or "").strip():
                            confirmed_identity = deepcopy(answered)
                    except msfservice.MsfSessionMissing:
                        raise
                    except session_identity.NativeIdentityUnconfirmed:
                        raise
                    except (
                        OSError, ValueError, RuntimeError,
                        msfservice.MsfUnreachable,
                    ) as error:
                        reason = type(error).__name__ + ": " + str(error)
                        observation["identity_reason"] = reason
                        if "CHANNEL_CALL_UNRESOLVED" in reason:
                            observation.update(
                                state="unknown", reason=reason)

        if need_identity and observation["state"] == "alive":
            if not confirmed_identity:
                observation.update(
                    state="unknown",
                    reason="SESSION_PROBE_IDENTITY_UNCONFIRMED",
                )
            else:
                # Also check the remote incarnation after the identity read.
                # The registry check below separately guards local rebinding.
                if deadline - time.monotonic() <= 0:
                    raise ValueError("SESSION_PROBE_DEADLINE")
                info = msfservice.session_shape(
                    client, row["session_id"], deadline=deadline)
                check_shape(info)

    except msfservice.MsfSessionMissing:
        identity = {}
        confirmed_identity = {}
        observation.update(
            state="dead", reason="CONSOLE_SESSION_GONE")
    except session_identity.NativeIdentityUnconfirmed as error:
        # Preserve the existing diagnostic/history behavior, but do not
        # publish a confirmed delivery snapshot from partial evidence.
        identity = dict(error.partial_identity)
        confirmed_identity = {}
        reason = type(error).__name__ + ": " + str(error)
        observation.update(
            state="unknown",
            reason=reason,
            identity_reason=reason,
        )
        if error.failed_call_id:
            observation["failed_call_id"] = error.failed_call_id
    except (
        OSError, ValueError, RuntimeError, msfservice.MsfUnreachable
    ) as error:
        identity = {}
        confirmed_identity = {}
        reason = type(error).__name__ + ": " + str(error)
        observation.update(state="unknown", reason=reason)
        if native_identity_started:
            observation["identity_reason"] = reason

    root = row.get("registry_root")
    if root:
        def update(value):
            found = value["sessions"].get(row["channel_id"])
            if found is None or found.get("lifecycle") == "revoked":
                raise ValueError("SESSION_BINDING_STALE")
            if binding(found) != frozen_binding:
                raise ValueError("SESSION_BINDING_CHANGED")

            found["observation"] = deepcopy(observation)
            if identity:
                found["identity"] = deepcopy(identity)

        session_registry._mutate(root, update)

    # Nothing is emitted before the checked registry update succeeds.
    if (
        evidence_out is not None
        and observation["state"] == "alive"
        and confirmed_identity
    ):
        evidence_out.update(deepcopy({
            "carrier": frozen_binding["channel_id"],
            "binding": frozen_binding,
            "state": "alive",
            "reason": observation["reason"],
            "at": observation["at"],
            "call_id": str(observation.get("call_id") or ""),
            "identity_call_id": str(
                confirmed_identity.get("call_id") or "").strip(),
            "identity": confirmed_identity,
        }))

    return observation["state"] == "alive", observation["reason"]






def carry_handles(source, target, *, executor):
    """Carry confirmed bindings unchanged; never choose by privilege or replace identity."""
    carried, unavailable = [], []
    for row in session_registry.snapshot(source):
        alive, reason = probe(row, executor)
        if not alive:
            unavailable.append([row["channel_id"], reason])
            continue
        copied = {key: value for key, value in row.items() if key != "registry_root"}
        copied["observation"] = {"state": "alive", "at": time.time(), "reason": reason}
        def update(value):
            current = value["sessions"].get(copied["channel_id"])
            if current is not None:
                if current.get("lifecycle") == "revoked":
                    raise ValueError("SESSION_REVOKED_BINDING")
                fields = ("endpoint", "session_id", "uuid", "host", "logical", "session_type",
                          "platform", "source_node", "source_call", "capacity", "shell_ready")
                if any(current.get(field) != copied.get(field) for field in fields):
                    raise ValueError("SESSION_BINDING_RELABELLED")
            value["sessions"][copied["channel_id"]] = copied
        session_registry._mutate(target, update)
        carried.append([row["channel_id"], reason])
    return carried, unavailable, []
