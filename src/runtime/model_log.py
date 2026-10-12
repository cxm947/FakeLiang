"""Model-call journal: one JSONL line per model call, appended, never rewritten.

``calls.jsonl`` journals every registered call (one row per call). This file is its
generation-side twin: each seam that asks a model appends exactly one line - task, source,
ok/error, model, attempts, latency and tokens - so a reader can tell, without opening any
record file, which agent asked what, whether an answer arrived, and where to look next.
Append-only: old lines are never rewritten, and a run without a directory simply has no
journal.
"""

from __future__ import annotations

import io
import json
from datetime import datetime
from pathlib import Path

#: The one-line row: stable keys, all present on every line (order = write order).
ROW_KEYS = ("ts", "task", "source", "ok", "error", "model", "attempts", "latency_ms",
            "prompt_tokens", "completion_tokens", "finish_reason", "request_sha256")


def record(run_dir, *, task: str, source: str, reply=None, metadata: dict | None = None,
           error: str = "", request_sha256: str = "", ts: str | None = None) -> dict:
    """Append one model-call line and return it.

    ``reply`` is a ModelReply-shaped object (its ``to_json()`` carries the counts);
    ``metadata`` is accepted for callers that only kept that dict. A line is written even
    when the call failed - that is the point: the failure is visible, in place, in order.
    """
    data: dict = {}
    if reply is not None:
        to_json = getattr(reply, "to_json", None)
        data = dict(to_json() or {}) if callable(to_json) else {}
    data.update(metadata or {})
    line = {
        "ts": ts or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "task": str(task),
        "source": str(source or ""),
        "ok": bool(data.get("ok")) and not error,
        "error": str(error or data.get("error") or ""),
        "model": str(data.get("model") or ""),
        "attempts": data.get("attempts"),
        "latency_ms": data.get("latency_ms"),
        "prompt_tokens": data.get("prompt_tokens"),
        "completion_tokens": data.get("completion_tokens"),
        "finish_reason": str(data.get("finish_reason") or ""),
        "request_sha256": str(request_sha256 or data.get("request_sha256") or ""),
    }
    if run_dir is None:
        # No directory, no journal - the caller's run just has nothing to read back.
        return line
    path = Path(run_dir) / "model.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with io.open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(line, ensure_ascii=False) + "\n")
    return line


def read(run_dir) -> list[dict]:
    """Every recorded line, oldest first (for the CLI and for tests)."""
    path = Path(run_dir) / "model.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def complete_logged(client, *, run_dir, task, system, user, secrets=(),
                    source="verify", timeout=None):
    """Persist the request before calling, and the raw answer before parsing it."""
    import hashlib
    import os
    from uuid import uuid4
    from runtime.lean import collect_secrets, mask_secrets

    request = {"task": task, "system": system, "user": user}
    if timeout is not None:
        request["timeout"] = timeout
    exchange_id = uuid4().hex
    request_hash = hashlib.sha256((system + "\n" + user).encode("utf-8")).hexdigest()
    path = Path(run_dir) / "model_exchanges.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)

    def append(phase, data, known):
        row = {"exchange_id": exchange_id, "task": task, "phase": phase,
               "request_sha256": request_hash, **data}
        with io.open(path, "a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(mask_secrets(row, known), ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    append("request", {"request": request}, secrets)
    try:
        reply = client.complete(**request)
    except Exception as error:
        message = type(error).__name__ + ": " + str(error)
        append("response", {"text": None, "payload": None, "error": message}, secrets)
        record(run_dir, task=task, source=source, request_sha256=request_hash,
               error=mask_secrets(message, secrets))
        raise
    payload = getattr(reply, "payload", None)
    known = collect_secrets(payload, secrets)
    metadata = (reply.to_json() if callable(getattr(reply, "to_json", None)) else
                {"ok": bool(getattr(reply, "ok", False)),
                 "error": str(getattr(reply, "error", "") or "")})
    append("response", {"text": getattr(reply, "text", None), "payload": payload,
                        "metadata": metadata}, known)
    record(run_dir, task=task, source=source, request_sha256=request_hash,
           metadata=mask_secrets(metadata, known))
    return reply
