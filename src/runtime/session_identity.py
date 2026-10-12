"""Read execution identity from session replies."""
from __future__ import annotations

import re
import time

from runtime import msfservice, session_io


#: Identity is read through the session itself. A declared label - a card field, a graph
#: privilege, or a session tag - is never accepted as the observation.
IDENTITY_PROBE = {"posix": "id -u; id -un; hostname; head -1 /proc/1/cgroup 2>/dev/null",
                  "windows": "whoami & hostname"}
CONTAINER_MARKERS = ("docker", "kubepods", "containerd", "lxc")


#: One console verb gets at least this long. An unframed answer settles only after the capture
#: stops growing (see `runtime.channels.CONSOLE_IDLE_READS`), so a 3-second budget could cut a
#: live console off mid-answer and report `SESSION_PROBE_UNCONFIRMED` for a session that was
#: answering (measured 2026-10-08, walk-140 node 7: the pc1 session stayed listed in the console
#: while the delivery's identity probe read it as unconfirmed, and the step lost its hand-over).
IDENTITY_COMMAND_BUDGET = 12.0


def identity_command(row) -> str:
    """Pick the identity command from the observed platform, not from a declared one."""
    platform = str(row.get("platform") or "").lower()
    if platform.startswith("windows") or "windows" in str(row.get("session_type") or "").lower():
        return IDENTITY_PROBE["windows"]
    return IDENTITY_PROBE["posix"]


def read_identity(platform, body) -> dict:
    """Read the raw identity output; an unreadable reply stays unobserved."""
    lines = [line.strip() for line in str(body or "").splitlines() if line.strip()]
    if not lines:
        return {}
    if str(platform or "").lower().startswith("windows"):
        named = [line for line in lines if "\\" in line]
        user = named[0] if named else lines[0]
        rest = [line for line in lines[lines.index(user) + 1:] if _identity_line(line)]
        return {"uid": "", "user": user, "hostname": rest[0] if rest else "", "environment": "host"}
    #: A console may print its own banner around the payload, so the reading is found by shape:
    #: the first all-digit line is the uid, and the account and host follow it.
    for index, line in enumerate(lines):
        if not line.isdigit():
            continue
        tail = [item for item in lines[index + 1:] if _identity_line(item)]
        marks = " ".join(tail[2:]).lower()
        return {"uid": line, "user": tail[0] if tail else "",
                "hostname": tail[1] if len(tail) > 1 else "",
                "environment": "container" if any(mark in marks
                                                  for mark in CONTAINER_MARKERS) else "host"}
    return {}


def _identity_line(line) -> bool:
    """Drop a console's own chatter; keep the lines an identity reading is made of."""
    text = str(line).strip()
    if not text:
        return False
    return not text.lower().startswith(("process ", "channel ", "sending ", "opening ",
                                        "closing ", "starting "))


def read_native_identity(platform, getuid_text, sysinfo_text) -> dict:
    """Read the identity from the console's own reports, which need no shell channel.

    Measured on the lab (2026-10-08): `getuid` answers `Server username: root` and `sysinfo`
    answers Computer/OS/Arch for a live meterpreter session, whatever channel it is in.
    """
    user = ""
    for line in str(getuid_text or "").splitlines():
        if "username" in line.lower():
            user = line.split(":", 1)[-1].strip()
            break
    if not user:
        return {}

    def field(text, name):
        for line in str(text or "").splitlines():
            head, separator, tail = line.partition(":")
            if separator and head.strip().lower() == name:
                return tail.strip()
        return ""

    computer = field(sysinfo_text, "computer")
    inside = bool(re.fullmatch(r"[0-9a-f]{12}", computer.lower())) if computer else False
    return {"uid": "0" if user.strip().lower() in ("root",) else "",
            "user": user, "hostname": computer,
            "environment": "container" if inside else ("host" if computer else "unknown"),
            "platform": str(platform or ""), "source": "console_identity_commands"}


class NativeIdentityUnconfirmed(ValueError):
    """Keep confirmed identity evidence when another command is unconfirmed."""

    def __init__(self, reason, *, partial_identity=None, failed_call_id=""):
        super().__init__(reason)
        self.partial_identity = dict(partial_identity or {})
        self.failed_call_id = str(failed_call_id or "")


def observe_native_identity(row, *, deadline=None, timeout=20.0,
                            commands=("getuid", "sysinfo")):
    """Read native identity and retain confirmed evidence if a later call fails."""
    deadline = deadline if deadline is not None else session_io._deadline(timeout)
    identity = {}

    def reading():
        read = read_native_identity(row.get("platform"), identity.get("getuid", ""),
                                    identity.get("sysinfo", ""))
        if not read:
            return {}
        return dict(read, at=identity["at"], call_id=identity.get("call_id", ""),
                    raw=(identity.get("getuid", "") + identity.get("sysinfo", ""))[:2000])

    for command in commands:
        remaining = min(IDENTITY_COMMAND_BUDGET, deadline - time.monotonic())
        if remaining <= 0:
            break
        try:
            receipt = session_io.call_bound(row, {"tool": "msf", "cmd": command}, remaining)
        except msfservice.MsfSessionMissing:
            raise
        except (OSError, ValueError, RuntimeError, msfservice.MsfUnreachable) as error:
            raise NativeIdentityUnconfirmed(
                type(error).__name__ + ": " + str(error),
                partial_identity=reading()) from error
        if not receipt["confirmed"]:
            raise NativeIdentityUnconfirmed(
                "SESSION_IDENTITY_COMMAND_UNCONFIRMED: " + str(command),
                partial_identity=reading(), failed_call_id=receipt.get("call_id", ""))
        text = str(getattr(receipt.get("outcome"), "stdout", "") or "")
        if command == "getuid":
            identity["getuid"], identity["call_id"] = text, str(receipt["call_id"])
            identity["at"] = time.time()
        else:
            identity["sysinfo"] = text
    return reading()


def observe_identity(row, *, deadline=None, timeout=20.0):
    """Record what the session itself says about the identity behind it."""
    deadline = deadline if deadline is not None else session_io._deadline(timeout)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("SESSION_IDENTITY_DEADLINE")
    receipt = session_io.call_bound(row, {"tool": "cmd", "cmd": identity_command(row)}, remaining)
    if not receipt["confirmed"] or receipt["command_rc"] != 0:
        return {}
    body = session_io._frame_body(getattr(receipt.get("outcome"), "stdout", ""), receipt.get("marker") or "")
    identity = read_identity(row.get("platform"), body)
    if not identity:
        return {}
    return dict(identity, at=time.time(), call_id=str(receipt["call_id"]),
                platform=str(row.get("platform") or ""), raw=body)
