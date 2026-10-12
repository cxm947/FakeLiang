"""Read and atomically update the run's session registry."""
from __future__ import annotations

import json
import os
from pathlib import Path
import time
from uuid import uuid4

from runtime.runner import ownership


REGISTRY_TABLES = ("sessions", "resources", "releases", "contexts")
REGISTRY_AUDIT_KEYS = ("dropped", "revision")
REGISTRY_WRITE_WAIT_S = 20.0


def _resource_root(root):
    """Leases belong to one run, not to the machine: a crashed run must not wedge the next."""
    return Path(root) / "session-resources"


def _registry(root):
    path = Path(root) / "sessions.json"
    if not path.exists():
        return {name: {} for name in REGISTRY_TABLES}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("SESSION_REGISTRY_INVALID")
    if set(value) == {"sessions", "resources"}:
        #: 更老的账本连 releases 都没有：补空表，读法不变。
        value["releases"] = {}
    value.setdefault("contexts", {})   #: 老账本没有"上下文观测"这一栏。
    value.setdefault("dropped", [])    #: 登记去重的审计栏。
    unknown = set(value) - set(REGISTRY_TABLES) - set(REGISTRY_AUDIT_KEYS)
    if (unknown
            or not set(REGISTRY_TABLES) <= set(value)
            or any(not isinstance(value[name], dict) for name in REGISTRY_TABLES)
            or not isinstance(value["dropped"], list)
            or any(not isinstance(row, dict) for row in value["dropped"])):
        raise ValueError("SESSION_REGISTRY_INVALID")
    return value


def _mutate(root, update):
    root = Path(root)
    with ownership(root / ".session-registry", wait=REGISTRY_WRITE_WAIT_S):
        value = _registry(root)
        result = update(value)
        path = root / "sessions.json"
        temporary = root / (".sessions-" + uuid4().hex + ".json")
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(path)
        finally:
            if temporary.exists():
                temporary.unlink()
        return result


def snapshot(root):
    """Read current bindings; harvest history never supplies current availability.

    读路径不取锁（爷爷 2026-10-08 的锁口径）：写者用原子替换发布，读者永远看到一份完整文档；
    walk-184 整轮崩就是"读去抢写闸、被本轮自己的探活守护弹回"。
    """
    rows = _registry(root)["sessions"].values()
    return [dict(row, registry_root=str(Path(root).resolve())) for row in rows
            if row.get("lifecycle") != "revoked"]


def register_observation(root, *, channel_id, logical, privilege, identity, environment,
                         source_node="", source_call="", evidence_call_id="", observed_at=None):
    """Append one immutable context observation; the channel keeps exactly one owner.

    Privilege belongs to an execution context, not to the connection (external review
    2026-10-08: Windows tokens are per-process, Linux credentials are per-task). A step that
    raises privilege **in place** therefore keeps the same single channel row and records what it
    observed; a second row owning the same channel would make reclaim ambiguous.
    """
    if not isinstance(channel_id, str) or not channel_id.strip():
        raise ValueError("SESSION_OBSERVATION_CHANNEL_REQUIRED")
    if not isinstance(privilege, str) or not privilege.strip():
        raise ValueError("SESSION_OBSERVATION_PRIVILEGE_REQUIRED")
    record = {"context_id": "context-" + uuid4().hex, "channel_id": channel_id.strip(),
              "logical": str(logical or ""), "privilege": privilege.strip(),
              "identity": dict(identity or {}), "environment": str(environment or "host"),
              "source_node": str(source_node or ""), "source_call": str(source_call or ""),
              "evidence_call_id": str(evidence_call_id or ""),
              "at": float(observed_at if observed_at is not None else time.time())}

    def update(value):
        if record["channel_id"] not in value["sessions"]:
            raise ValueError("SESSION_OBSERVATION_CHANNEL_UNKNOWN")
        value["contexts"][record["context_id"]] = record

    _mutate(root, update)
    return record


def observations(root):
    """Read context observations. They own no channel and never keep one from being reclaimed.

    与 ``snapshot`` 同理：读路径不取锁。
    """
    rows = _registry(root)["contexts"].values()
    return [dict(row, registry_root=str(Path(root).resolve())) for row in rows]


def held_resources(root, *, host="") -> list:
    """Return held [host, port] reservations from this run's resource ledger."""
    value = _registry(_resource_root(root))
    rows = []

    for key, lease in value["resources"].items():
        try:
            resource = json.loads(key)
        except (TypeError, ValueError) as error:
            raise ValueError("SESSION_RESOURCE_REGISTRY_INVALID") from error

        if (
                not isinstance(resource, dict)
                or set(resource) != {"host", "port", "protocol"}
                or not isinstance(resource["host"], str)
                or not resource["host"]
                or type(resource["port"]) is not int
                or not 1 <= resource["port"] <= 65535
                or resource["protocol"] not in ("tcp", "udp")
                or key != json.dumps(
                    resource, sort_keys=True, separators=(",", ":"))
                or not isinstance(lease, dict)
                or not isinstance(lease.get("owner"), str)
                or not lease["owner"]
                or lease.get("state") != "held"
                or lease["owner"] in value["releases"]):
            raise ValueError("SESSION_RESOURCE_REGISTRY_INVALID")

        if host and resource["host"] != str(host):
            continue
        rows.append([resource["host"], resource["port"]])

    return rows




def reserve_resources(root, *, owner, resources):
    """Lease declared resources without scanning, guessing ports, or expiring another owner."""
    if not isinstance(owner, str) or not owner or not isinstance(resources, list) or not resources:
        raise ValueError("SESSION_RESOURCES_REQUIRED")
    keys = []
    for resource in resources:
        if (not isinstance(resource, dict) or set(resource) != {"host", "port", "protocol"}
                or not isinstance(resource["host"], str) or not resource["host"]
                or type(resource["port"]) is not int or not 1 <= resource["port"] <= 65535
                or resource["protocol"] not in ("tcp", "udp")):
            raise ValueError("SESSION_RESOURCE_INVALID")
        keys.append(json.dumps(resource, sort_keys=True, separators=(",", ":")))
    if len(keys) != len(set(keys)):
        raise ValueError("SESSION_RESOURCE_DUPLICATE")
    def update(value):
        if owner in value["releases"]:
            raise ValueError("SESSION_RESOURCE_OWNER_RELEASED")
        if any(key in value["resources"] for key in keys):
            raise ValueError("SESSION_RESOURCE_BUSY")
        for key in keys:
            value["resources"][key] = {"owner": owner, "state": "held", "at": time.time()}
    _mutate(_resource_root(root), update)


def release_unstarted(root, *, owner, reason):
    """Release an owner's reservations that never started anything (no cleanup to confirm).

    A started resource keeps its lease until its own cleanup is confirmed; only an attempt that
    installed nothing may be released without those receipts, and then the reason is recorded
    rather than a receipt being fabricated for it.
    """
    if not isinstance(owner, str) or not owner:
        raise ValueError("SESSION_RESOURCE_OWNER_UNKNOWN")
    released = []

    def update(value):
        keys = [key for key, row in value["resources"].items() if row["owner"] == owner]
        if not keys:
            raise ValueError("SESSION_RESOURCE_OWNER_UNKNOWN")
        value["releases"][owner] = {"reason": str(reason or "TUNNEL_NOT_STARTED"),
                                    "at": time.time(), "resources": keys}
        for key in keys:
            del value["resources"][key]
        released.extend(keys)

    _mutate(_resource_root(root), update)
    return released


def release_resources(root, *, owner, receipts):
    """Release an owner's resources only after its declared cleanup actions were confirmed."""
    if (not isinstance(receipts, list) or not receipts
            or any(not row.get("confirmed") or row.get("command_rc") != 0 for row in receipts)):
        raise ValueError("SESSION_RESOURCE_CLEANUP_UNCONFIRMED")
    def update(value):
        previous = value["releases"].get(owner)
        if previous is not None:
            if previous["receipts"] != receipts:
                raise ValueError("SESSION_RESOURCE_RELEASE_MISMATCH")
            return
        keys = [key for key, row in value["resources"].items() if row["owner"] == owner]
        if not keys:
            raise ValueError("SESSION_RESOURCE_OWNER_UNKNOWN")
        value["releases"][owner] = {"receipts": receipts, "at": time.time(), "resources": keys}
        for key in keys:
            del value["resources"][key]
    _mutate(_resource_root(root), update)
