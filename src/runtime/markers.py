"""Shared marker framing and explicit shell serialization.

Both are about *correlation*, not about a target: one call gets one marker, the wrapper prints it
around the command, and the runtime slices the receipt on it. They used to live in ``runtime/adapter``
next to the fixed-assembly machinery every card once shipped; that machinery is gone (the executor
drives cards from their knowledge and the model, not from a per-card script), so what is left is
small enough to stand on its own.
"""
from __future__ import annotations

import re
import shlex
import uuid


def call_marker(call_id: str) -> str:
    """Marker derived from the call id, so a marker seen on a target maps back to one call.

    The id shape is call-<stamp>-<token>[-<label>]: a multi-step adapter labelled its main call
    (call-...-f07418-include). The marker comes from the token segment, never from the label -
    taking the label produced "agvinclude" once and the checker could no longer match the marker
    the adapter had put on the wire. Ids without the three segments keep the last-segment
    behaviour.
    """
    parts = [part for part in str(call_id).lower().split("-") if part]
    tail = re.sub(r"[^0-9a-z]", "", parts[2]) if len(parts) >= 3 else ""
    if not tail:
        tail = re.sub(r"[^0-9a-z]", "", str(call_id).lower().rsplit("-", 1)[-1])
    return "agv" + (tail[:10] or uuid.uuid4().hex[:10])


def shell_command(argv, *, windows=False):
    """Serialize argv once for the declared shell; never inspect its command shape."""
    if not isinstance(argv, (list, tuple)) or not argv:
        raise ValueError("COMMAND_ARGV_INVALID")
    parts = [str(part) for part in argv]
    if not parts[0] or any("\x00" in part for part in parts):
        raise ValueError("COMMAND_ARGV_INVALID")
    if not windows:
        return shlex.join(parts)
    if any(any(char in part for char in "%!\r\n") for part in parts) or '"' in parts[0]:
        raise ValueError("WINDOWS_ARGV_UNREPRESENTABLE: expansion and multiline arguments require an explicit action")
    import subprocess
    arguments = subprocess.list2cmdline(parts[1:])
    arguments = re.sub(r'([&|<>^()"])', r'^\1', arguments)
    return '"' + parts[0] + '"' + (" " + arguments if arguments else "")


def marker_script(argv, marker: str, *, merge_stderr: bool = False, windows: bool = False,
                  command=None, single_line: bool = False) -> str:
    """Frame explicit argv or an explicitly declared raw Windows command."""
    if command is not None:
        if not windows or argv is not None or not isinstance(command, str) or not command.strip():
            raise ValueError("COMMAND_TEXT_INVALID")
        line = command
    else:
        line = shell_command(argv, windows=windows)
    if merge_stderr:
        line += " 2>&1"
    if single_line:
        #: A meterpreter shell channel reads the write as one command line, so the frame has
        #: to travel on one line (measured on the lab, 2026-10-08: the multi-line frame came
        #: back empty while the one-line frame completed).
        if windows:
            raise ValueError("COMMAND_SINGLE_LINE_WINDOWS_UNSUPPORTED")
        return ("printf '%s\\n' " + shlex.quote(str(marker) + "start") + "; " + line
                + "; probe_rc=$?; printf '\\n%s %s\\n' " + shlex.quote(str(marker) + "end")
                + ' "$probe_rc"' + "\n")
    if windows:
        return ("echo " + str(marker) + "start\n" + line + "\n"
                + "echo " + str(marker) + "end %errorlevel%\n")
    return ("printf '%s\\n' " + shlex.quote(str(marker) + "start") + "\n"
            + line + "\n"
            + "probe_rc=$?\n"
            + "printf '\\n%s %s\\n' " + shlex.quote(str(marker) + "end")
            + ' "$probe_rc"\n'
            + 'exit "$probe_rc"\n')
