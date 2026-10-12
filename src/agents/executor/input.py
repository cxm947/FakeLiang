"""Task input validation and executor selection."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from runtime.lean_http import endpoint_parts
from runtime.remote import SshExecutor, parse_remote
from runtime.runner import subprocess_executor


def read_json(value):
    text = str(value)
    if text.lstrip().startswith(("{", "[")):
        return json.loads(text)
    path = Path(text[1:] if text.startswith("@") else text)
    return json.loads(path.read_text(encoding="utf-8-sig"))


def validate_task(card, task):
    if (not isinstance(task, dict) or not isinstance(task.get("inputs"), dict)
            or not isinstance(task.get("node_id"), str) or not task["node_id"].strip()
            or not isinstance(task.get("goal"), str) or not task["goal"].strip()):
        raise ValueError("LEAN_TASK_INVALID: node_id, goal, inputs and scope required")
    host, port = endpoint_parts(task.get("scope"))
    inputs = task["inputs"]
    for name, declaration in card["inputs"].items():
        if (declaration["from"] == "graph" and not declaration.get("optional")
                and inputs.get(name) in (None, "", [], {})):
            raise ValueError("LEAN_TASK_INPUT_UNBOUND: " + name)
    for name in ("target_host", "host_ref"):
        if name in inputs:
            try:
                equal = str(ipaddress.ip_address(inputs[name])) == host
            except (ValueError, TypeError):
                equal = False
            if not equal:
                raise ValueError("LEAN_TASK_TARGET_CONFLICT: " + name)
    for name in ("port", "service_port", "target_port"):
        if name in inputs and (isinstance(inputs[name], bool) or str(inputs[name]) != str(port)):
            raise ValueError("LEAN_TASK_TARGET_CONFLICT: " + name)
    if "target_url" in inputs:
        try:
            url = urlsplit(inputs["target_url"])
            equal = (url.scheme == "http" and str(ipaddress.ip_address(url.hostname)) == host
                     and (url.port if url.port is not None else 80) == port
                     and url.username is None and url.password is None)
        except (ValueError, TypeError):
            equal = False
        if not equal:
            raise ValueError("LEAN_TASK_TARGET_CONFLICT: target_url")
    if inputs.get("protocol", "tcp") not in ("http", "tcp"):
        raise ValueError("LEAN_TASK_TARGET_CONFLICT: protocol")


def select_executor(args, card, scope):
    """Bind one executor from the real transport label; never infer a host from a graph name.

    ``base`` is the one hop this version drives, and it is a legal vantage for any card. A finer
    vantage value has to name that hop's actual label, or the run would be claiming a position
    nobody proved.
    """
    password = args.password or os.environ.get("AGV_SSH_PASSWORD")
    if args.chain:
        raise ValueError("LEAN_CHAIN_UNSUPPORTED: this version drives one SSH hop; a multi-hop "
                         "carrier is a separate module")
    owner = (SshExecutor(parse_remote(args.remote), password=password, key_filename=args.key)
             if args.remote else None)
    if scope["vantage"] != "base" and (owner is None or owner.label() != scope["vantage"]):
        if owner:
            owner.close()
        raise ValueError("LEAN_VANTAGE_BINDING_UNAVAILABLE: scope must equal the actual "
                         "transport label of the one hop this version drives")
    return (owner or subprocess_executor), owner
