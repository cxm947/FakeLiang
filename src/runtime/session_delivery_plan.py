"""Prepare, receive, and cancel explicitly declared session deliveries."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import time
from uuid import uuid4

from runtime import msfservice, session_io, session_registry, sessions
from runtime.redact import collect_secrets, mask_secrets




def _save_delivery_plan(root, plan):
    """Persist the recovery plan before an action can acquire resources or change a host."""
    owner = str(plan.get("owner") or "")
    if not re.fullmatch(r"delivery-[0-9a-f]{32}", owner):
        raise ValueError("SESSION_DELIVERY_OWNER_INVALID")
    directory = Path(root) / "delivery" / owner
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / ("plan-" + uuid4().hex + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(plan, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(directory / "plan.json")
    finally:
        if temporary.exists():
            temporary.unlink()
