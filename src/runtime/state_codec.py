"""Strict state encoding, reads and atomic publication."""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import tempfile




@dataclass(frozen=True)
class Committed:
    revision: int | None
    value: object = None


@dataclass(frozen=True)
class Unchanged:
    revision: int | None
    value: object = None


class StateCorrupt(Exception):
    def __init__(self, path, detail):
        self.path = Path(path)
        super().__init__(str(self.path) + ": " + str(detail))


class StorageFault(Exception):
    def __init__(self, path, phase, cause, *, committed=None):
        self.path, self.phase, self.cause = Path(path), phase, cause
        self.committed_result = committed
        self.commit_state = "COMMITTED" if committed is not None else "NOT_COMMITTED"
        super().__init__(str(self.path) + ": " + phase + ": " + str(cause))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def _constant(value):
    raise ValueError("nonfinite JSON number: " + value)


def _float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("nonfinite JSON number")
    return value


def _loads(text):
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant,
                      parse_float=_float)


_MISSING = object()


def _read_document(path, format="json", *, missing=_MISSING):
    # Parsing happens after closing: a Windows reader must not retain the handle.
    try:
        with path.open("rb") as stream:
            data = stream.read()
    except FileNotFoundError as error:
        if missing is not _MISSING:
            return missing
        raise StorageFault(path, "read", error) from error
    except OSError as error:
        raise StorageFault(path, "read", error) from error
    try:
        text = data.decode("utf-8")
        if format == "jsonl":
            if data and not data.endswith(b"\n"):
                raise ValueError("incomplete JSONL record")
            return [_loads(line) for line in text[:-1].split("\n")] if text else []
        return _loads(text)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise StateCorrupt(path, error) from error


def _encode(value, format="json"):
    def encode(item):
        return json.dumps(item, ensure_ascii=False, sort_keys=True, allow_nan=False)
    if format == "jsonl":
        if not isinstance(value, list):
            raise ValueError("JSONL document must be a list")
        text = "".join(encode(row) + "\n" for row in value)
    else:
        text = encode(value) + "\n"
    return text.encode("utf-8")


def _publish(path, value, format="json"):
    # All serialization errors occur before any file is published.
    data = _encode(value, format)
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix="." + path.name + "-",
            suffix=".tmp", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        # Successful replacement is the commit point. No fallible cleanup follows.
    except OSError as error:
        fault = StorageFault(path, "publish", error)
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as cleanup:
                fault.cleanup_error = cleanup
        raise fault from error


def _location(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("expected a path relative to runtime_root")
    path = (root / relative).resolve()
    if path == root or root not in path.parents:
        raise ValueError("record path escapes runtime_root")
    if path == root / ".locks" or root / ".locks" in path.parents:
        raise ValueError("lock files are not records")
    return path
