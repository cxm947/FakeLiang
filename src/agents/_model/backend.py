"""Freeze a model backend before creating any run-owned input or issuing I/O."""
import json
import os
from pathlib import Path

BACKENDS = ("legacy", "native")


def freeze_backend(root, backend=None):
    wanted = backend if backend is not None else os.environ.get("AGV_MODEL_BACKEND")
    if wanted is not None and wanted not in BACKENDS:
        raise ValueError("MODEL_BACKEND_INVALID")
    try:
        root = Path(root)
    except TypeError:
        #: A caller may hand over a duck-typed run root (the in-memory fakes in the test suite
        #: implement only `__truediv__`/`mkdir`/`write_text`). There is nothing to read or write
        #: there, so the requested/default value is simply returned.
        return wanted or "legacy"
    marker = root / ".model_backend.json"

    def read():
        try:
            data = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise ValueError("MODEL_BACKEND_BINDING_INVALID") from None
        if (set(data) != {"version", "backend"} or data["version"] != 1
                or data["backend"] not in BACKENDS):
            raise ValueError("MODEL_BACKEND_BINDING_INVALID")
        if wanted is not None and data["backend"] != wanted:
            raise ValueError("MODEL_BACKEND_CHANGED")
        return data["backend"]

    if marker.exists():
        return read()
    #: The compiled graph is written into the run root before the backend is frozen, so it must not
    #: be read as "this run already exists" - otherwise a fresh run could never choose native.
    #: Everything else in the directory is a real trace and keeps the legacy protection.
    ignored = {"graph"}
    entries = [item.name for item in root.iterdir()] if root.is_dir() else []
    populated = any(name not in ignored for name in entries)
    if populated and (root / "native_tools.jsonl").exists():
        raise ValueError("MODEL_BACKEND_BINDING_MISSING")
    chosen = wanted or "legacy"
    if populated and chosen != "legacy":
        raise ValueError("MODEL_BACKEND_LEGACY_RUN")
    root.mkdir(parents=True, exist_ok=True)
    try:
        with marker.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps({"version": 1, "backend": chosen},
                                    sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        return read()
    return chosen
