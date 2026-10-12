"""Register exact bindings and observe whether sessions remain usable."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import time
from uuid import uuid4

from runtime import msfservice, session_identity, session_io, session_registry




WEB_ENTRY_PROBE = "echo agv-entry-ok; id -un"


def _identity(endpoint, session_id, incarnation=""):
    public = {key: endpoint[key] for key in ("host", "port", "ssl")}
    value = json.dumps([public, str(session_id), str(incarnation)], sort_keys=True, separators=(",", ":"))
    return "session-" + sha256(value.encode("utf-8")).hexdigest()


def register_web_position(root, *, host, logical, recipe, platform="linux", source_node="",
                          source_call="", session_id="", kind="web", privilege=""):
    """Register one entry as a position: a leftover resource plus the recipe that talks to it.

    The entry is not a connection (external review 2026-10-08): the row records **where it is and
    how this run talks to it**, while every use still has to observe it again -- a gone entry is
    reported as gone, never silently re-planted. The entry itself belongs to the step that made it,
    so this row owns no port and takes part in no resource lease.

    `kind` says what the entry is: `web` (a command entry a request drives) or `ssh` (a host this
    run authorised for itself). Both are read the same way -- a recipe, run on the control end --
    so the row's `session_type` is the generic `entry` and the recipe keeps its own shape.

    `privilege` is the identity this entry's commands actually run as (the container's web account,
    or root through a helper). It belongs to the execution context, not to the entry (bridge
    2026-10-08: 权限属于执行上下文，不属于连接), so a step whose premise names a privilege picks
    the entry that runs as it instead of asking the model to guess between two entries on one host.
    """
    if not isinstance(host, str) or not host.strip():
        raise ValueError("SESSION_WEB_HOST_REQUIRED")
    if not isinstance(recipe, dict) or not recipe:
        raise ValueError("SESSION_WEB_RECIPE_REQUIRED")
    if str(recipe.get("kind") or "") not in ("asset_command", "argv_command"):
        raise ValueError("SESSION_WEB_RECIPE_UNSUPPORTED")

    def update(value):
        channel_id = str(kind) + "-" + uuid4().hex
        value["sessions"][channel_id] = {
            "kind": "console_session", "channel_id": channel_id,
            "session_id": str(session_id or (str(kind) + "-" + uuid4().hex[:8])),
            "session_type": "entry", "position_kind": str(kind),
            "platform": str(platform or "linux"),
            "host": host.strip(), "logical": str(logical or ""), "recipe": dict(recipe),
            "privilege": str(privilege or ""),
            "lifecycle": "registered", "source_node": str(source_node or ""),
            "source_call": str(source_call or ""),
            "identity": {}, "observation": {"state": "unknown", "at": time.time()},
            "endpoint": {"host": "", "port": 0, "ssl": False},
            "capacity": {"max_bytes": 4096, "source": "one web entry request"},
            "shell_ready": False}

    session_registry._mutate(root, update)
    row = next(item for item in session_registry.snapshot(root)
               if item.get("session_type") == "entry" and item.get("host") == host.strip()
               and item.get("source_node") == str(source_node or ""))
    return row
def register_session(root, *, endpoint, session_id, logical, source_node="", source_call="",
                     capabilities, timeout=30.0, expected=None, privilege_term=""):
    """Register one exact session using the console's current metadata."""
    if not isinstance(endpoint, dict) or set(endpoint) != {"host", "port", "ssl"}:
        raise ValueError("SESSION_ENDPOINT_INVALID")
    if (not isinstance(endpoint["host"], str) or not endpoint["host"]
            or type(endpoint["port"]) is not int or not 1 <= endpoint["port"] <= 65535
            or type(endpoint["ssl"]) is not bool or not str(session_id)):
        raise ValueError("SESSION_ENDPOINT_INVALID")
    if not isinstance(capabilities, dict) or set(capabilities) != {"capacity", "shell_ready"}:
        raise ValueError("SESSION_CAPABILITIES_REQUIRED")
    capacity = capabilities["capacity"]
    if (not isinstance(capacity, dict) or set(capacity) != {"max_bytes", "source"}
            or type(capacity["max_bytes"]) is not int or capacity["max_bytes"] <= 0
            or not isinstance(capacity["source"], str) or not capacity["source"].strip()
            or type(capabilities["shell_ready"]) is not bool):
        raise ValueError("SESSION_CAPABILITIES_INVALID")
    deadline = session_io._deadline(timeout)
    client = msfservice.client_for(session_io._endpoint(endpoint), deadline=deadline)
    info = msfservice.session_shape(client, str(session_id), deadline=deadline)
    if expected is not None:
        if (not isinstance(expected, dict) or not expected
                or any(info.get(key) != value for key, value in expected.items())):
            raise ValueError("SESSION_OBSERVATION_CHANGED")
    if info.get("type") not in ("shell", "meterpreter"):
        raise ValueError("SESSION_TYPE_UNSUPPORTED")
    if not str(info.get("session_host") or "") or not str(info.get("platform") or ""):
        raise ValueError("SESSION_METADATA_INCOMPLETE")
    incarnation = str(info.get("uuid") or "")
    key = _identity(endpoint, session_id, incarnation)
    row = {"channel_id": key, "kind": "console_session", "endpoint": dict(endpoint),
           "session_id": str(session_id), "session_type": info["type"],
           "platform": str(info["platform"]), "host": str(info["session_host"]),
           "logical": str(logical), "source_node": str(source_node),
           "source_call": str(source_call), "capacity": dict(capacity),
           "shell_ready": capabilities["shell_ready"], "metadata": dict(info),
           "lifecycle": "registered",
           "observation": {"state": "unknown", "at": time.time(),
                           "reason": "SESSION_REGISTERED_NOT_PROBED"}}
    if info.get("uuid"):
        row["uuid"] = str(info["uuid"])
    #: 图上的**权限词**（例如 `system` / `root`）：去重与解析都用它当键的一半 —— 读回来的身份串
    #: 是 `NT AUTHORITY\SYSTEM` 这类拼写，两边不同名，只有图上那个词两边都认（爷爷 2026-10-08）。
    if str(privilege_term or "").strip():
        row["privilege_term"] = str(privilege_term).strip()
    def update(value):
        immutable = ("endpoint", "session_id", "session_type", "platform", "host", "logical",
                     "source_node", "source_call", "capacity", "shell_ready", "uuid")
        old = value["sessions"].get(key)
        if old is not None:
            if old.get("lifecycle") == "revoked":
                raise ValueError("SESSION_REVOKED_BINDING")
            if any(old.get(field) != row.get(field) for field in immutable):
                raise ValueError("SESSION_BINDING_RELABELLED")
            return dict(old)
        previous = [item for item in value["sessions"].values()
                    if item["endpoint"] == endpoint and item["session_id"] == str(session_id)]
        if any(not incarnation or not item.get("uuid") for item in previous):
            raise ValueError("SESSION_INCARNATION_UNCONFIRMED")
        for item in previous:
            item["lifecycle"] = "revoked"
            item["observation"] = {"state": "dead", "at": time.time(),
                                   "reason": "SESSION_INCARNATION_REPLACED",
                                   "replacement_uuid": incarnation}
        #: **登记去重**（爷爷 2026-10-08 口径）：同一 (主机, 规范化权限) 已经有活着的记录时，
        #: 本次**不新增行**，只把"丢弃"如实记进登记表（`dropped`）；运行层再把它落进遗留清单。
        #: 那个步骤本身仍按它自己的证据判成立 —— 打通了就算打通，不因为丢弃承载而改判。
        #: 身份规范化会把 shell 回显与提示符剥掉（walk-182 实测：19 那条的身份串被提示符污染，
        #: 于是同键的两条记录并存、下游只能去问模型挑 —— 那是这件事的根）。
        from runtime import carriers

        def _carrier_key(item):
            identity = item.get("identity") or {}
            return carriers.canonical_key({
                "host": str(item.get("logical") or item.get("host") or ""),
                "identity_user": str(item.get("privilege_term")
                                     or identity.get("user") or item.get("privilege") or "")})

        try:
            incoming = _carrier_key(row)
        except ValueError:
            incoming = None
        if incoming is not None:
            for existing_key, item in value["sessions"].items():
                if item.get("lifecycle") == "revoked":
                    continue
                try:
                    same = _carrier_key(item) == incoming
                except ValueError:
                    same = False
                if same:
                    value.setdefault("dropped", []).append({
                        "at": time.time(), "reason": "duplicate_key", "kept": existing_key,
                        "dropped": key, "logical": incoming[0], "privilege": incoming[1],
                        "source_node": str(source_node), "source_call": str(source_call)})
                    return dict(item)
        value["sessions"][key] = row
        return dict(row)
    registered = session_registry._mutate(root, update)
    return dict(registered, registry_root=str(Path(root).resolve()))


def revoke_session(root, binding, *, receipt, timeout=30.0):
    """Revoke only after a matching stop receipt and confirmed absence."""
    if (not isinstance(receipt, dict) or receipt.get("session_id") != binding["session_id"]
            or receipt.get("state") != "stopped"):
        raise ValueError("SESSION_STOP_UNCONFIRMED")
    deadline = session_io._deadline(timeout)
    client = msfservice.client_for(session_io._endpoint(binding["endpoint"]), deadline=deadline)
    if binding["session_id"] in msfservice.sessions(client, deadline=deadline):
        raise ValueError("SESSION_STOP_UNCONFIRMED")
    def update(value):
        row = value["sessions"].get(binding["channel_id"])
        if row is None:
            raise ValueError("SESSION_BINDING_UNKNOWN")
        row["lifecycle"] = "revoked"
        row["observation"] = {"state": "dead", "at": time.time(),
                              "reason": "SESSION_STOP_CONFIRMED", "receipt": dict(receipt)}
    session_registry._mutate(root, update)
