"""Card-declared assets: the tools a card ships, placed on the execution end at dispatch.

A card that names a tool in its body ("run /opt/agv/tools/<x>.py") is only half a card: the tool
has to be there. The old fixed-assembly execution flow shipped a per-card client module and deployed it by
hand; that machinery is gone, and what a card actually needs is its *data* - a PoC script, a
helper, a receiver. So the card declares them (the path its recipe names -> the file inside the
card) and the runtime places them before the node runs.

Content decides: an asset whose sha256 already matches is left alone, so a second run does not
rewrite what is there, and the check is the same fact a reviewer would check by hand.
"""
from __future__ import annotations

import base64
from hashlib import sha256
from pathlib import Path
from pathlib import PurePosixPath
import shlex
import time

from runtime import artifacts

#: One asset larger than this is not a card's tool; refusing keeps a stray 100 MB blob out of the
#: run's argv (the write travels as one base64 argument).
ASSET_LIMIT = 512 * 1024

#: How many times one placement is attempted before the node is refused. Measured 2026-10-06
#: (e2e-full-40): a single push of the laravel PoC failed once on a busy control box and the node
#: was refused; the same command typed by hand succeeded. A short retry is what an operator does.
ATTEMPTS = 3


def declared(card: dict, root) -> list:
    """(destination, source) pairs for one card; raises when a declared file is not there.

    A source may point at another card's file (``../other-card/poc/x.py``) - the suid helper takes
    the same PoC the laravel card ships - but it may not leave the repository's ``skills`` tree:
    a declaration is a deployment fact, not a way to ship an arbitrary file from the host.
    """
    out = []
    skills_root = (Path(root) / "skills").resolve() if root is not None else None
    for dest, relative in sorted((card.get("assets") or {}).items()):
        source = Path(card["path"]).parent / str(relative)
        if skills_root is not None:
            try:
                source.resolve().relative_to(skills_root)
            except ValueError:
                raise ValueError("LEAN_CARD_ASSET_OUTSIDE_SKILLS: %s" % dest)
        if not source.is_file():
            raise ValueError("LEAN_CARD_ASSET_MISSING: %s -> %s" % (dest, relative))
        if source.stat().st_size > ASSET_LIMIT:
            raise ValueError("LEAN_CARD_ASSET_TOO_LARGE: %s" % dest)
        out.append((str(dest), source))
    return out


def ensure(card: dict, executor, *, root=None, timeout: float = 90.0, run_dir=None,
           node="") -> list:
    """Place every declared asset on the execution end; returns a line per asset acted on.

    The control box is the execution end these cards mean: their recipes run there (`python3
    /opt/agv/tools/...`), so the same executor that will carry the step's commands carries the file.
    ``run_dir`` turns the placement into an *artifact* (a file we created, with the argv that
    removes it), so a later reclaim can walk the table backwards instead of guessing a prefix.
    """
    placed = []
    for dest, source in declared(card, root):
        payload = source.read_bytes()
        digest = sha256(payload).hexdigest()
        current = executor(["/bin/sh", "-c", "sha256sum %s 2>/dev/null | cut -d' ' -f1"
                            % shlex.quote(dest)], timeout)
        if str(getattr(current, "stdout", "") or "").strip() == digest:
            placed.append(dest + " (already there)")
            continue
        blob = base64.b64encode(payload).decode("ascii")
        #: A *remote* path is POSIX even when this process runs on Windows: ``Path("/a/b").parent``
        #: hands back ``\\a\\b`` there, and the control box then creates a directory whose name
        #: starts with a literal backslash while the redirect fails with "Directory nonexistent"
        #: (measured 2026-10-06, e2e-full-40 - the whole web2 branch was blocked by it).
        folder = str(PurePosixPath(dest).parent)
        command = ("mkdir -p %s && echo %s | base64 -d > %s && chmod 0755 %s "
                   "&& sha256sum %s | cut -d' ' -f1"
                   % (shlex.quote(folder), blob, shlex.quote(dest),
                      shlex.quote(dest), shlex.quote(dest)))
        trouble = ""
        for attempt in range(ATTEMPTS):
            wrote = executor(["/bin/sh", "-c", command], timeout)
            if getattr(wrote, "returncode", None) == 0:
                break
            trouble = str(getattr(wrote, "stderr", "") or "").strip()[:200]
            time.sleep(1.0 + attempt)
        else:
            raise ValueError("LEAN_CARD_ASSET_UNPUSHED: %s%s"
                             % (dest, (" (" + trouble + ")") if trouble else ""))
        if str(getattr(wrote, "stdout", "") or "").strip().splitlines()[-1:] != [digest]:
            raise ValueError("LEAN_CARD_ASSET_MISMATCH: " + dest)
        placed.append(dest)
        if run_dir is not None:
            artifacts.record(run_dir, kind="file", host=str(getattr(executor, "label", lambda: "")()
                                                            or ""), node=node, target=dest,
                             detail="card asset of " + str(card.get("id") or ""),
                             undo=["rm", "-f", dest])
    return placed
