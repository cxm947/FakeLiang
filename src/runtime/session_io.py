"""Execute bound actions and preserve their intent and completion records."""
from __future__ import annotations

from contextvars import ContextVar
from graph.files import atomic_write
from dataclasses import asdict
import json
import math
import os
from pathlib import Path
import time
from uuid import uuid4

from runtime import channels, dispatch, msfservice, session_registry
from runtime.markers import call_marker
from runtime.redact import collect_secrets, mask_secrets
from runtime.runner import new_call_id, observe_marker_frame


CALL_ASSOCIATION = ContextVar("session_call_association", default="")

SHELL_CHANNEL_STEP = 0.3

#: Only a shell answers this with the bare word; the meterpreter interpreter answers
#: `[-] Unknown command: echo agvCHREADY`, which is not the word and keeps us waiting.
SHELL_CHANNEL_MARKER = "agvCHREADY"
SHELL_CHANNEL_ATTEMPTS = 4


def _deadline(timeout):
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("SESSION_TIMEOUT_INVALID")
    return time.monotonic() + float(timeout)


def _endpoint(value):
    public = {key: value[key] for key in ("host", "port", "ssl")}
    endpoint = msfservice.endpoint_from_env()
    if public != {"host": endpoint.host, "port": endpoint.port, "ssl": endpoint.ssl}:
        raise ValueError("SESSION_ENDPOINT_MISMATCH")
    return endpoint


def rpc_call(*, host="", port=0, user="", password="", timeout=90.0):
    """Create a deadline-aware RPC callable without an endpoint-blind executor cache."""
    if host and port and user and password:
        endpoint = msfservice.Endpoint(host=host, port=port, user=user, password=password, ssl=False)
    else:
        configured = msfservice.endpoint_from_env()
        endpoint = msfservice.Endpoint(
            host=host or configured.host, port=port or configured.port,
            user=user or configured.user, password=password or configured.password, ssl=configured.ssl)
    def call(method, *params, deadline=None):
        until = _deadline(timeout) if deadline is None else deadline
        client = msfservice.client_for(endpoint, deadline=until)
        return msfservice.call(client, method, *params, deadline=until)
    call.endpoint = endpoint
    return call


def ensure_console(*, host="", port=0, user="", password="", timeout=120.0):
    """Check the configured console without implicitly restarting it or destroying sessions."""
    try:
        call = rpc_call(
            host=host,
            port=port,
            user=user,
            password=password,
            timeout=timeout,
        )
        call("session.list")
        return {
            "state": "ready",
            "restarted": False,
            "host": call.endpoint.host,
            "port": call.endpoint.port,
            "note": "console RPC confirmed",
        }
    except (ValueError, OSError, RuntimeError, msfservice.MsfUnreachable) as error:
        return {
            "state": "unavailable",
            "restarted": False,
            "note": type(error).__name__ + ": " + str(error),
        }


def call_bound(binding, request, timeout):
    """Bind one declared action, preserve raw capture, and record its completion evidence."""
    root = binding.get("registry_root")
    if not root:
        raise ValueError("SESSION_RECORDING_ROOT_REQUIRED")
    deadline = _deadline(timeout)
    call_id = new_call_id() + "-" + uuid4().hex
    marker = call_marker(call_id)
    action = dispatch.bind_console(request, binding, marker=marker)
    directory = Path(root) / "session-calls" / call_id
    directory.mkdir(parents=True, exist_ok=False)
    redactions = list(collect_secrets({"request": request}))
    redactions.append(_endpoint(binding["endpoint"]).password)
    def safe(value):
        return json.loads(mask_secrets(json.dumps(value, ensure_ascii=False), redactions))
    intent = safe({"call_id": call_id, "binding_id": binding["channel_id"],
                   "request": request, "action": action, "at": time.time(),
                   "association": CALL_ASSOCIATION.get(), "phase": "before_commit",
                   "deadline_at": time.time() + max(0.0, deadline - time.monotonic())})
    with (directory / "intent.json").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(intent, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("SESSION_CALL_DEADLINE")
    intent["phase"] = "committing"
    atomic_write(directory / "intent.json",
                 (json.dumps(intent, ensure_ascii=False) + "\n").encode("utf-8"), force=True)
    outcome = channels.console_call(binding, action, remaining)
    intent["phase"] = "after_commit"
    atomic_write(directory / "intent.json",
                 (json.dumps(intent, ensure_ascii=False) + "\n").encode("utf-8"), force=True)
    completion = action["completion"]
    if completion is None:
        #: A native console command has no frame to close: what it printed is its answer,
        #: and the read loop ends on the deadline rather than on a marker.
        framed, command_rc = bool(str(outcome.stdout or "").strip()), 0
        confirmed = bool(framed and not outcome.timed_out and not outcome.tool_error
                         and outcome.read_stop in (None, "quiet"))
    else:
        framed, command_rc = observe_marker_frame(outcome.stdout, completion["marker"])
        confirmed = bool(framed and outcome.read_stop == "end_marker"
                         and not outcome.timed_out and not outcome.tool_error)
    receipt = safe({"call_id": call_id, "binding_id": binding["channel_id"],
                    "outcome": asdict(outcome), "confirmed": confirmed,
                    "association": CALL_ASSOCIATION.get(),
                    "command_rc": command_rc if confirmed else None, "at": time.time()})
    with (directory / "receipt.json").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(receipt, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return {"outcome": outcome, "confirmed": confirmed, "marker": marker,
            "command_rc": command_rc if confirmed else None, "call_id": call_id}


def _frame_body(text, marker) -> str:
    """Return only the body of one complete framed call."""
    if not marker:
        return ""
    lines = str(text or "").replace("\r", "").splitlines()
    starts = [index for index, line in enumerate(lines) if line.strip() == marker + "start"]
    ends = [index for index, line in enumerate(lines) if line.strip().startswith(marker + "end")]
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        return ""
    return "\n".join(line.strip() for line in lines[starts[0] + 1:ends[0]]).strip()


def ensure_shell_channel(row, *, deadline=None, timeout=20.0):
    """A meterpreter position reads text as its own commands, so open its shell first.

    Measured on the real lab (2026-10-08): writing a shell script straight to a meterpreter
    session answers `[-] Unknown command: echo`, while writing `shell` first and then the
    same text returns its output. Opening it is the runtime's job, and whether it opened is
    observed here rather than declared by a card.
    """
    if str(row.get("session_type") or "") != "meterpreter":
        return True, "SHELL_CHANNEL_NOT_REQUIRED"
    if row.get("shell_channel") is True:
        return True, "SHELL_CHANNEL_OPEN"
    deadline = deadline if deadline is not None else _deadline(timeout)
    client = msfservice.client_for(_endpoint(row["endpoint"]), deadline=deadline)
    msfservice.shell_write(client, row["session_id"], "shell\n", deadline=deadline)
    seen = ""
    attempts = 0
    while time.monotonic() < deadline:
        chunk = msfservice.shell_read(client, row["session_id"], deadline=deadline)
        seen += str(chunk or "")
        #: Readiness is observed, not timed: the console prints its banner before it has
        #: finished switching into the channel, so a write issued at the banner is lost
        #: (measured 2026-10-08). Ask the channel something only a shell answers.
        if any(line.strip() == SHELL_CHANNEL_MARKER for line in seen.splitlines()):
            root = row.get("registry_root")
            if root:
                def update(value):
                    found = value["sessions"].get(row["channel_id"])
                    if found is None or found.get("lifecycle") == "revoked":
                        raise ValueError("SESSION_BINDING_STALE")
                    found["shell_channel"] = True
                session_registry._mutate(root, update)
            return True, "SHELL_CHANNEL_OPEN"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if attempts < SHELL_CHANNEL_ATTEMPTS and not chunk:
            attempts += 1
            msfservice.shell_write(client, row["session_id"],
                                   "echo " + SHELL_CHANNEL_MARKER + "\n", deadline=deadline)
        elif not chunk:
            time.sleep(min(SHELL_CHANNEL_STEP, remaining))
    return False, "SHELL_CHANNEL_UNCONFIRMED"


def position_call(binding, request, *, executor, timeout=90.0):
    """Send one command line through a control-end entry position; the entry answers for itself.

    Every use is a new observation: the recipe is replayed by the client that lives on the control
    end, nothing about the entry is remembered from an earlier call, and a frame that comes back
    with a non-zero command code is **not** a usable answer.
    """
    from runtime import lean_web

    if executor is None:
        raise ValueError("SESSION_POSITION_OBSERVER_REQUIRED")
    marker = call_marker(new_call_id() + "-" + uuid4().hex)
    action = dispatch.bind_console(request, binding, marker=marker)
    if action.get("operation") != "asset":
        raise ValueError("SESSION_POSITION_COMMAND_ONLY")
    argv = lean_web.command_argv(action["recipe"], action["text"], marker)
    outcome = executor(argv, max(0.1, float(timeout)))
    framed, command_rc = observe_marker_frame(outcome.stdout, marker)
    return {"outcome": outcome, "marker": marker, "framed": bool(framed),
            "command_rc": command_rc,
            "confirmed": bool(framed and command_rc == 0 and not outcome.timed_out
                              and not outcome.tool_error)}



def _delivery_action(executor, root, owner, label, step, *, secrets=()):
    """Use the original call record, with a synced boundary immediately around dispatch."""
    from hashlib import sha256
    from math import isfinite
    if (not isinstance(step, dict) or set(step) != {"request", "platform", "binding", "timeout"}
            or not isinstance(step["request"], dict)
            or not isinstance(step["platform"], str) or not step["platform"]
            or type(step["timeout"]) not in (int, float)
            or not isfinite(step["timeout"]) or step["timeout"] <= 0):
        raise ValueError("SESSION_DELIVERY_ACTION_INVALID")
    step_hash = sha256(json.dumps(step, sort_keys=True, separators=(",", ":"),
                                 allow_nan=False).encode("utf-8")).hexdigest()
    directory = Path(root) / "delivery" / owner
    directory.mkdir(parents=True, exist_ok=True)
    intent_path = directory / (label + ".intent.json")
    receipt_path = directory / (label + ".receipt.json")
    redactions = collect_secrets(step, [item for item in secrets if item])
    def save(path, value, *, force=False):
        text = mask_secrets(json.dumps(value, ensure_ascii=False, allow_nan=False), redactions)
        atomic_write(path, (text + "\n").encode("utf-8"), force=force)
    intent = None
    if intent_path.exists():
        try:
            intent = json.loads(intent_path.read_text(encoding="utf-8"))
            if intent.get("step_hash") != step_hash:
                raise ValueError("SESSION_DELIVERY_CALL_UNRESOLVED")
            if receipt_path.exists():
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                if (receipt.get("step_hash") != step_hash
                        or receipt.get("call_id") != intent.get("call_id")
                        or receipt.get("confirmed") is not True):
                    raise ValueError("SESSION_DELIVERY_CALL_UNRESOLVED")
                return {key: value for key, value in receipt.items() if key != "outcome"}
            if intent.get("phase") != "before_commit":
                raise ValueError("SESSION_DELIVERY_CALL_UNRESOLVED")
        except (OSError, ValueError):
            raise ValueError("SESSION_DELIVERY_CALL_UNRESOLVED") from None
    if intent is None:
        identifier = "delivery-" + uuid4().hex
        intent = {"call_id": identifier, "step": step, "step_hash": step_hash,
                  "marker": call_marker(identifier), "phase": "before_commit",
                  "deadline_at": time.time() + min(60.0, float(step["timeout"]))}
        save(intent_path, intent)
    identifier, marker = intent["call_id"], intent["marker"]
    remaining = float(intent.get("deadline_at") or 0.0) - time.time()
    if remaining <= 0:
        raise ValueError("SESSION_DELIVERY_ACTION_DEADLINE")
    intent["phase"] = "committing"
    save(intent_path, intent, force=True)
    if step["binding"] is not None:
        association = CALL_ASSOCIATION.set(identifier)
        try:
            bound = call_bound(step["binding"], step["request"], remaining)
        finally:
            CALL_ASSOCIATION.reset(association)
        receipt = {"call_id": identifier, "bound_call_id": bound["call_id"],
                   "confirmed": bound["confirmed"], "command_rc": bound["command_rc"],
                   "outcome": asdict(bound["outcome"]), "step_hash": step_hash}
    else:
        outcome = dispatch.invoke(step["request"], executor=executor, platform=step["platform"],
                                  marker=marker, timeout=remaining)
        complete, code = observe_marker_frame(outcome.stdout, marker)
        confirmed = bool(complete and outcome.read_stop in (None, "end_marker", "quiet")
                         and not outcome.timed_out and not outcome.tool_error)
        receipt = {"call_id": identifier, "confirmed": confirmed,
                   "command_rc": code if confirmed else None, "outcome": asdict(outcome),
                   "step_hash": step_hash}
    intent["phase"] = "after_commit"
    save(intent_path, intent, force=True)
    save(receipt_path, receipt)
    return {key: value for key, value in receipt.items() if key != "outcome"}
