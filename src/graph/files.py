"""Atomic individual artifact writes; never overwrite an input or existing output implicitly."""

import os
import tempfile
import time
from pathlib import Path


def publish_bundle(paths, contents, *, writer=None):
    """Publish a small bundle, rolling back completed writes on failure.

    Each replacement is atomic; the whole bundle is not crash-atomic. Callers
    must serialize writers. If rollback itself fails, retain original bytes in
    a recovery directory and report it instead of claiming a consistent bundle.
    """
    writer = writer or atomic_write
    if set(paths) != set(contents):
        raise ValueError("artifact paths and contents must have matching keys")
    check_targets(paths.values(), force=True)
    originals = {name: Path(path).read_bytes() if Path(path).exists() else None
                 for name, path in paths.items()}
    written = []
    try:
        for name, path in paths.items():
            writer(path, contents[name], force=True)
            written.append(name)
    except BaseException as failure:
        failed_restores = []
        for name in reversed(written):
            try:
                if originals[name] is None:
                    Path(paths[name]).unlink(missing_ok=True)
                else:
                    writer(paths[name], originals[name], force=True)
            except OSError:
                failed_restores.append(name)
        if failed_restores:
            parent = Path(next(iter(paths.values()))).resolve().parent
            recovery = Path(tempfile.mkdtemp(prefix=".agv-recovery-", dir=parent))
            import json
            manifest = {}
            for index, name in enumerate(written):
                backup = f"{index}.original" if originals[name] is not None else None
                manifest[name] = {"target": str(Path(paths[name]).resolve()), "backup": backup}
                if backup is not None:
                    (recovery / backup).write_bytes(originals[name])
            (recovery / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            raise RuntimeError(f"Artifact publication and rollback failed; recovery data: {recovery}") from failure
        raise


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
