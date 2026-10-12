"""Atomic individual artifact writes; never overwrite an input or existing output implicitly."""

import os
import tempfile
import time
from pathlib import Path


def check_targets(paths, *, inputs=(), force=False):
    resolved = [Path(path).resolve() for path in paths]
    if len(set(resolved)) != len(resolved):
        raise ValueError("output paths must be distinct")
    sources = {Path(path).resolve() for path in inputs}
    for path in resolved:
        if path in sources:
            raise ValueError("an output path must not equal an input path")
        if path.exists() and (not force or not path.is_file()):
            raise FileExistsError(f"output exists (use --force to replace an output file): {path}")


def replace_retrying(source, target, *, attempts=8):
    """Replace a file, retrying briefly while Windows still holds the old one.

    A caller that fsyncs a fresh file and immediately replaces it can lose a race
    against an indexer or a virus scanner that keeps a handle open, and Windows
    reports that as ERROR_ACCESS_DENIED. The retry is bounded, keeps the same
    atomic replace, and raises the last failure like before.
    """
    delay = 0.02
    for attempt in range(attempts):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt + 1 == attempts:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.25)


def atomic_write(path, content: bytes, *, force=False):
    path = Path(path)
    check_targets([path], force=force)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".agv-", suffix=".tmp", delete=False) as stream:
            temp_path = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if force:
            replace_retrying(temp_path, path)
        else:
            # Linking is atomic and fails if a concurrent writer created path.
            os.link(temp_path, path)
            temp_path.unlink()
        temp_path = None
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
