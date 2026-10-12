"""Exclusive session I/O for bound actions and explicit completion frames."""
from __future__ import annotations

import errno
import json
import math
import os
import tempfile
import time
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from runtime import msfservice
from runtime.runner import ExecOutcome, observe_marker_frame, ownership

#: How long a read loop waits before asking the console again, and how many quiet asks mean
#: "the answer is over".
CONSOLE_READ_STEP = 0.3
#: A verb like `sysinfo` has no closing frame, so nothing in the bytes says it finished. Waiting
#: for the deadline instead marked a *complete* answer as ``timeout``: the step lost its evidence
#: and the node stopped after one call (measured 2026-10-08, walk-131 node 5: sysinfo returned
#: PC1's banner, the call was recorded as a 60 s timeout, and the verifier saw no completed call).
CONSOLE_IDLE_READS = 8


def begin_use(binding, *, note=""):
    """Acquire one physical session across aliases, runs, and processes."""
    if not isinstance(binding, dict):
        raise ValueError("CHANNEL_BINDING_INVALID")
    endpoint, sid = binding.get("endpoint"), binding.get("session_id")
    if (not isinstance(endpoint, dict) or set(endpoint) != {"host", "port", "ssl"}
            or not isinstance(endpoint["host"], str) or not endpoint["host"].strip()
            or type(endpoint["port"]) is not int or not 1 <= endpoint["port"] <= 65535
            or type(endpoint["ssl"]) is not bool
            or not isinstance(sid, str) or not sid.strip() or sid != sid.strip()):
        raise ValueError("CHANNEL_BINDING_INVALID")
    identity = [endpoint["host"].strip().lower(), endpoint["port"], endpoint["ssl"], sid]
    key = sha256(json.dumps(identity, separators=(",", ":")).encode("utf-8")).hexdigest()
    token = ExitStack()
    #: An unsettled call belongs to the run that issued it. The console reuses session ids and
    #: incarnation ids, so a machine-wide directory let one run's unresolved call block the
    #: next run's fresh session (measured 2026-10-08: the same uuid `q6tyulqe` on two runs).
    base = binding.get("registry_root") or tempfile.gettempdir()
    token.session_dir = Path(base) / "session-locks" / key
    try:
        token.enter_context(ownership(token.session_dir))
    except OSError as error:
        token.close()
        if error.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
            raise ValueError("CHANNEL_BUSY") from error
        raise ValueError("CHANNEL_LOCK_FAILED") from error
    return token


def end_use(token) -> None:
    """Release only this acquisition; never unlink an OS-lock inode."""
    if not isinstance(token, ExitStack):
        raise ValueError("CHANNEL_USE_TOKEN_INVALID")
    token.close()


def _read_until(session_id, client, *, completion, deadline, reader):
    """Retain late bytes without claiming they completed within the deadline."""
    marker = completion["marker"] if completion is not None else None
    seen = ""
    quiet = 0
    while time.monotonic() < deadline:
        try:
            chunk = reader(client, session_id, deadline=deadline)
        except TimeoutError:
            return seen, "deadline"
        except (msfservice.MsfUnreachable, msfservice.MsfSessionMissing) as error:
            error.capture = seen
            raise
        if not isinstance(chunk, str):
            error = msfservice.MsfUnreachable("CHANNEL_READ_INVALID")
            error.capture = seen
            raise error
        seen += chunk
        if time.monotonic() >= deadline:
            return seen, "deadline"
        if marker is not None and observe_marker_frame(seen, marker)[0]:
            return seen, "end_marker"
        if not chunk:
            #: An unframed answer is done when it stops growing: the run must not sit on the
            #: deadline to discover that, and a timeout is not a verdict on the command.
            if marker is None and seen.strip():
                quiet += 1
                if quiet >= CONSOLE_IDLE_READS:
                    return seen, "quiet"
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(CONSOLE_READ_STEP, remaining))
        else:
            quiet = 0
    return seen, "deadline"


def _capture_outcome(seen, read_stop, *, error=""):
    """Transport completion never substitutes for the remote command's exit code."""
    return ExecOutcome(returncode=0 if read_stop in {"end_marker", "quiet"} else None,
                       stdout=seen, timed_out=read_stop == "deadline",
                       tool_error=error or None, read_stop=read_stop)


def _reconcile_settled_attempt(pending, previous, observed):
    """Remove pending only when this exact attempt has a matching durable completion."""
    if not isinstance(previous, dict) or not isinstance(observed, dict):
        return False
    identifier = previous.get("attempt_id")
    if (not isinstance(identifier, str) or len(identifier) != 32
            or any(char not in "0123456789abcdef" for char in identifier)):
        return False
    incarnation = previous.get("session_uuid")
    if (not isinstance(incarnation, str) or not incarnation
            or incarnation != observed.get("uuid")):
        return False
    payload_hash = previous.get("payload_sha256")
    if (not isinstance(payload_hash, str) or len(payload_hash) != 64
            or any(char not in "0123456789abcdef" for char in payload_hash)):
        return False
    try:
        settled = json.loads(
            (pending.parent / (identifier + ".json")).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(settled, dict):
        return False
    fields = ("attempt_id", "session_uuid", "operation", "completion",
              "payload_sha256", "at")
    if any(field not in previous or field not in settled
           or previous[field] != settled[field] for field in fields):
        return False
    capture_hash = settled.get("capture_sha256")
    if (not isinstance(capture_hash, str) or len(capture_hash) != 64
            or any(char not in "0123456789abcdef" for char in capture_hash)):
        return False
    completion = previous["completion"]
    if previous["operation"] == "native":
        valid = (completion is None
                 and settled.get("read_stop") in ("quiet", "deadline")
                 and type(settled.get("command_rc")) is int
                 and settled["command_rc"] == 0
                 and capture_hash != sha256(b"").hexdigest())
    elif previous["operation"] == "shell":
        valid = (isinstance(completion, dict) and set(completion) == {"marker"}
                 and isinstance(completion["marker"], str) and bool(completion["marker"])
                 and completion["marker"].isascii() and completion["marker"].isalnum()
                 and settled.get("read_stop") == "end_marker"
                 and type(settled.get("command_rc")) is int)
    else:
        valid = False
    if not valid:
        return False
    pending.unlink()
    return True


def _archive_unresolved_attempt(pending, previous, *, current_uuid):
    """Preserve an unresolved intent before allowing a different attempt to be sent."""
    if not isinstance(previous, dict):
        raise ValueError("CHANNEL_PENDING_INVALID")
    identifier = previous.get("attempt_id")
    payload_hash = previous.get("payload_sha256")
    if (not isinstance(identifier, str) or len(identifier) != 32
            or any(char not in "0123456789abcdef" for char in identifier)
            or not isinstance(payload_hash, str) or len(payload_hash) != 64
            or any(char not in "0123456789abcdef" for char in payload_hash)
            or previous.get("operation") not in ("native", "shell")
            or any(key not in previous for key in ("session_uuid", "completion", "at"))):
        raise ValueError("CHANNEL_PENDING_INVALID")
    archive = pending.parent / ("unsettled-" + identifier + "-" + uuid4().hex + ".json")
    record = dict(previous, archive={
        "state": "unresolved", "at": time.time(),
        "current_session_uuid": current_uuid,
        "read_stop": "unresolved", "capture_sha256": None,
        "note": "No recovery read was performed; remote execution and output remain unknown."})
    with archive.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    pending.unlink()
    return {"attempt_id": identifier, "archive": archive.name}


def console_call(binding, action, timeout):
    """Send unchanged payloads; synchronous I/O finishes before releasing ownership."""
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("CHANNEL_TIMEOUT_INVALID")
    deadline = time.monotonic() + float(timeout)
    if not isinstance(binding, dict):
        raise ValueError("CHANNEL_BINDING_INVALID")
    kind = binding.get("session_type")
    if kind not in {"shell", "meterpreter"}:
        raise ValueError("CHANNEL_SESSION_TYPE_UNKNOWN")
    if (not isinstance(action, dict) or set(action) != {"operation", "text", "completion"}
            or action["operation"] not in {"shell", "native"}
            or not isinstance(action["text"], str) or not action["text"]):
        raise ValueError("CHANNEL_ACTION_INVALID")
    completion = action["completion"]
    if completion is not None and (
            not isinstance(completion, dict) or set(completion) != {"marker"}
            or not isinstance(completion["marker"], str) or not completion["marker"]
            or not completion["marker"].isascii() or not completion["marker"].isalnum()):
        raise ValueError("CHANNEL_COMPLETION_INVALID")
    if action["operation"] == "native":
        if kind != "meterpreter" or completion is not None:
            raise ValueError("CHANNEL_NATIVE_CONTRACT_INVALID")
    elif binding.get("shell_ready") is not True:
        raise ValueError("CHANNEL_SHELL_NOT_READY")
    capacity = binding.get("capacity")
    if (not isinstance(capacity, dict) or set(capacity) != {"max_bytes", "source"}
            or type(capacity["max_bytes"]) is not int or capacity["max_bytes"] <= 0
            or not isinstance(capacity["source"], str) or not capacity["source"].strip()):
        raise ValueError("CHANNEL_CAPACITY_UNDECLARED")
    size = len(action["text"].encode("utf-8"))
    if size > capacity["max_bytes"]:
        #: The sizes travel with the refusal: "too big" without a number is a riddle.
        raise ValueError("CHANNEL_CAPACITY_EXCEEDED: %d > %d (%s)"
                         % (size, capacity["max_bytes"], capacity["source"]))
    endpoint = msfservice.endpoint_from_env()
    expected = {"host": endpoint.host, "port": int(endpoint.port), "ssl": bool(endpoint.ssl)}
    if binding.get("endpoint") != expected:
        raise ValueError("CHANNEL_ENDPOINT_CHANGED")
    token = begin_use(binding, note=action["operation"])
    try:
        pending = token.session_dir / "unsettled.json"
        client = msfservice.client_for(endpoint, deadline=deadline)
        sid = binding["session_id"]
        observed = msfservice.session_shape(client, sid, deadline=deadline)
        if observed["type"] != kind:
            raise ValueError("CHANNEL_SESSION_TYPE_CHANGED")
        if binding.get("uuid") is not None and observed.get("uuid") != binding["uuid"]:
            raise ValueError("CHANNEL_SESSION_CHANGED")
        previous_unresolved = None
        if pending.exists():
            previous = json.loads(pending.read_text(encoding="utf-8"))
            if not _reconcile_settled_attempt(pending, previous, observed):
                previous_unresolved = _archive_unresolved_attempt(
                    pending, previous, current_uuid=observed.get("uuid"))
        attempt_id = uuid4().hex
        intent = {"attempt_id": attempt_id, "session_uuid": observed.get("uuid"),
                  "operation": action["operation"],
                  "completion": completion, "at": time.time(),
                  "payload_sha256": sha256(action["text"].encode("utf-8")).hexdigest()}
        if previous_unresolved is not None:
            intent["previous_unresolved"] = previous_unresolved
        with pending.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(intent, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())

        if action["operation"] == "shell" and kind == "meterpreter":
            from runtime import session_io, session_registry

            preparation_binding = binding
            registry_root = binding.get("registry_root")
            if registry_root:
                current = [
                    row
                    for row in session_registry.snapshot(registry_root)
                    if row.get("channel_id") == binding["channel_id"]
                ]
                if len(current) != 1:
                    raise ValueError("SESSION_BINDING_STALE")
                preparation_binding = current[0]

            opened, channel_reason = session_io.ensure_shell_channel(
                preparation_binding, deadline=deadline)
            if not opened:
                raise ValueError(
                    "CHANNEL_SHELL_PREPARATION_UNCONFIRMED: "
                    + str(channel_reason))
            if time.monotonic() >= deadline:
                raise TimeoutError("CHANNEL_CALL_DEADLINE")

        if action["operation"] == "native":
            msfservice.runsingle(
                client, sid, action["text"], deadline=deadline)
            reader = msfservice.read
        else:
            msfservice.shell_write(
                client, sid, action["text"], deadline=deadline)
            reader = msfservice.shell_read
        seen, read_stop = _read_until(sid, client, completion=completion,
                                      deadline=deadline, reader=reader)
        #: A native console command has no frame to close, so an answer settles it: the read
        #: loop always ends on the deadline there (measured 2026-10-08: leaving it unsettled
        #: blocked every later call on that session with CHANNEL_CALL_UNRESOLVED).
        settled_call = read_stop == "end_marker" or (completion is None and bool(seen.strip()))
        if settled_call:
            settled = {**intent, "read_stop": read_stop,
                       "capture_sha256": sha256(seen.encode("utf-8")).hexdigest(),
                       "command_rc": (observe_marker_frame(seen, completion["marker"])[1]
                                      if completion is not None else 0)}
            with (token.session_dir / (attempt_id + ".json")).open(
                    "x", encoding="utf-8", newline="\n") as stream:
                json.dump(settled, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            pending.unlink()
        return _capture_outcome(seen, read_stop)
    except msfservice.MsfSessionMissing:
        raise
    except TimeoutError:
        return _capture_outcome("", "deadline")
    except msfservice.MsfUnreachable as error:
        return _capture_outcome(
            getattr(error, "capture", ""),
            "transport_error",
            error=str(error),
        )
    finally:
        end_use(token)
