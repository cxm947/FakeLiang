"""Value-only recovery helpers; credentials and model mappings stay in memory."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import time

from runtime.redact import collect_secrets, mask_secrets


def digest(value):
    return sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("ascii")).hexdigest()


def safe_data(value, secrets=()):
    # Collect before projecting so short named secrets are masked everywhere.
    safe = mask_secrets(value, collect_secrets(value, secrets))
    return json.loads(json.dumps(safe, ensure_ascii=True, allow_nan=False))


def parent_binding(row, executor_host="", executor_label=""):
    if row is None:
        return {"source": "base", "host": str(executor_host),
                "executor_label": str(executor_label)}
    fields = ("channel_id", "session_id", "uuid", "kind", "session_type",
              "platform", "host", "logical", "source_node", "source_call", "privilege")
    return {"source": "position", "refs": {key: deepcopy(row.get(key)) for key in fields},
            "endpoint": deepcopy(row.get("endpoint")),
            "recipe_digest": digest(row.get("recipe"))}


def restore_parent(frozen, rows, executor, *, executor_host="", executor_label=""):
    from runtime import sessions
    if frozen.get("source") == "base":
        if frozen != parent_binding(None, executor_host, executor_label):
            raise ValueError("RECOVERY_PARENT_INVALIDATED")
        return None
    refs = frozen.get("refs") or {}
    matches = [row for row in rows if row.get("channel_id") == refs.get("channel_id")]
    if len(matches) != 1:
        raise ValueError("RECOVERY_PARENT_INVALIDATED")
    row = matches[0]
    if (row.get("lifecycle") == "revoked" or
            (row.get("observation") or {}).get("state") == "dead" or
            parent_binding(row) != frozen):
        raise ValueError("RECOVERY_PARENT_INVALIDATED")
    alive, _note = sessions.probe(row, executor)
    if not alive:
        raise ValueError("RECOVERY_PARENT_UNCONFIRMED")
    return row


class RecoveryModel:
    """Persist model sends; an interrupted send never authorizes replay."""

    def __init__(self, client, context, secrets, timeout=90.0):
        self.client, self.context, self.secrets = client, context, secrets
        self.timeout = min(90.0, float(timeout))

    def available(self):
        value = getattr(self.client, "available", False)
        return value() if callable(value) else bool(value)

    def __getattr__(self, name):
        return getattr(self.client, name)

    def complete(self, **kwargs):
        return self._invoke(False, kwargs)

    def invoke_tools(self, **kwargs):
        return self._invoke(True, kwargs)

    def _invoke(self, native, kwargs):
        method = self.client.invoke_tools if native else self.client.complete
        state, save = self.context.get("state"), self.context.get("save")
        if state is None or save is None:
            return method(**kwargs)
        limit = min(self.timeout, float(kwargs.get("timeout", self.timeout)))
        keys = (("task", "messages", "tools", "max_tokens", "reasoning_effort")
                if native else ("task", "system", "user", "max_tokens", "reasoning_effort"))
        request = {key: kwargs.get(key) for key in keys}
        request["model"] = {key: getattr(self.client, key, None) for key in
                            ("name", "base_url", "wire", "temperature",
                             "reasoning_effort", "max_tokens")}
        if native or getattr(self.client, "backend", "legacy") == "native":
            request["model"]["backend"] = "native"
            request["protocol"] = "native-tools-v1" if native else "native-json-v1"
        if native:
            request.update(tool_choice="auto", parallel_tool_calls=False)
        identity = digest(request)
        calls = state.setdefault("model_calls", [])
        if self.context.pop("resume_models", False) and calls:
            received = calls[-1]
            if received.get("phase") == "finished" and received.get("request_digest") == identity:
                payload = received.get("reply")
                if payload is None or digest(payload) != received.get("reply_digest"):
                    raise ValueError("MODEL_CALL_UNKNOWN: private reply unavailable")
                from agents._model.contract import ModelReply
                return ModelReply(**payload)
        pending = calls[-1] if calls and calls[-1].get("phase") in (
            "before_commit", "committing", "unknown") else None
        if pending is not None:
            if pending.get("phase") != "before_commit" or pending.get("request_digest") != identity:
                raise ValueError("MODEL_CALL_UNKNOWN")
            call = pending
        else:
            call = {"id": len(calls) + 1, "task": str(kwargs.get("task") or ""),
                    "request_digest": identity, "deadline_at": time.time() + limit,
                    "phase": "before_commit"}
            calls.append(call)
            save(state)
        remaining = min(limit, float(call["deadline_at"]) - time.time())
        if remaining <= 0:
            call["phase"] = "unknown"
            save(state)
            raise ValueError("MODEL_CALL_UNKNOWN: deadline elapsed")
        call["phase"] = "committing"
        save(state)
        kwargs["timeout"] = remaining
        from agents._model.client import HttpModel
        if isinstance(self.client, HttpModel) or getattr(self.client, "supports_deadline", False):
            kwargs["deadline_at"] = call["deadline_at"]
        try:
            reply = method(**kwargs)
        except BaseException:
            call["phase"] = "unknown"
            save(state)
            raise
        call["reply_digest"], call["reply"] = model_reply_record(reply, self.secrets)
        if native:
            received = bool(getattr(reply, "response_confirmed", False))
        else:
            received = bool(
                getattr(reply, "response_confirmed", False)
                or getattr(reply, "ok", False) or getattr(reply, "text", "")
                or str(getattr(reply, "error", "")) == "HTTP 429"
                or getattr(reply, "payload", None) is not None
                or str(getattr(reply, "error", "")).startswith(
                    ("the model returned no content", "the answer is not JSON",
                     "the model output was truncated", "provider response included")))
        call["phase"] = "finished" if received else "unknown"
        save(state)
        if not received:
            raise ValueError("MODEL_CALL_UNKNOWN")
        return reply


def recover_relay(*, root, run_dir, frozen, owner, before, targets):
    """Prove the original relay from its existing artifact and held leases."""
    from runtime import harvest, session_registry

    unknown = {"state": "unknown", "reason": "RECOVERY_RELAY_UNKNOWN"}
    try:
        refs = frozen["refs"]
        current = [row for row in session_registry.snapshot(root)
                   if row.get("channel_id") == refs["channel_id"]]
        if len(current) != 1 or parent_binding(current[0]) != frozen:
            return dict(unknown, reason="RECOVERY_PARENT_INVALIDATED")
        records = harvest.read(run_dir, row_type="tunnel", strict=True)
        closed = {row.get("parent") for row in records if row.get("kind") == "closed"}
        candidates = [row for row in records if row.get("kind") == "proxy"
                      and row.get("channel_id") not in before
                      and row.get("channel_id") not in closed
                      and row.get("parent") == refs["channel_id"] and row.get("alive") is True]
        if len(candidates) != 1:
            return unknown
        row = candidates[0]
        if parent_binding(row.get("session_binding")) != frozen:
            return dict(unknown, reason="RECOVERY_RELAY_ASSOCIATION_LOST")
        wanted = {(str(host), int(port)) for host, port in targets}
        ports = row["tunnel_ports"]
        actual = {(str(item["target"]), int(item["port"])) for item in ports}
        note = json.loads(row["note"])
        proved = {(str(host), int(port)) for host, port in note["proved"]}
        if (not actual or len(actual) != len(ports) or not actual <= wanted
                or not proved or not proved <= actual
                or str(note.get("session_id")) != str(refs["session_id"])):
            return unknown
        registry = session_registry._registry(session_registry._resource_root(run_dir))
        if owner in registry["releases"]:
            return unknown
        for item in ports:
            resource = {"host": refs["host"], "port": int(item["listen"]), "protocol": "tcp"}
            key = json.dumps(resource, sort_keys=True, separators=(",", ":"))
            lease = registry["resources"].get(key) or {}
            if lease.get("owner") != owner or lease.get("state") != "held":
                return dict(unknown, reason="RECOVERY_RELAY_OWNER_UNCONFIRMED")
        return {"state": "completed", "reason": "RECOVERY_RELAY_ARTIFACT",
                "channel_id": row["channel_id"]}
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        return unknown


class _ReplayReply:
    """The answer the frozen binding already produced."""

    ok = True

    def __init__(self, card_id, reason):
        self.payload = {"card_id": card_id, "reason": reason}


class _ReplayClient:
    """Answer the card choice from the frozen binding, never from the model."""

    def __init__(self, client, card_id, reason):
        self._client = client
        self._card_id = card_id
        self._reason = reason

    def available(self):
        return True

    def complete(self, *, task, **kwargs):
        if task == "choose_card":
            return _ReplayReply(self._card_id, self._reason)
        return self._client.complete(task=task, **kwargs)

    def __getattr__(self, name):
        return getattr(self._client, name)


def binding_client(client, active):
    """Wrap the model client while resuming: the card choice is replayed, not re-asked.

    A first attempt gets the client untouched. A resumed step already bound a card,
    so an ambiguous catalogue is answered from the frozen selection and no model
    call is spent.
    """
    if not isinstance(active, dict) or not active.get("card_id"):
        return client
    selection = active.get("binding_selection") or {}
    reason = str(selection.get("model_reason") or "").strip() or (
        "recovered: replaying the card this attempt already bound")
    return _ReplayClient(client, active["card_id"], reason)


def verify_recovered_card(card, active):
    """A resumed step must land on the card it already bound, byte for byte."""
    if not isinstance(active, dict) or not active.get("card_id"):
        return
    if (card is None or card.get("id") != active["card_id"]
            or digest(card) != active.get("card_digest")):
        raise ValueError("RECOVERY_CARD_CHANGED")


def model_reply_record(reply, secrets=()):
    """Mask decoded native arguments while retaining the original replay digest."""
    fields = ("ok", "text", "payload", "model", "error", "latency_ms",
              "prompt_tokens", "completion_tokens", "reasoning_tokens",
              "request_sha256", "attempts", "finish_reason", "max_tokens",
              "native_message", "tool_calls", "response_confirmed")
    payload = {key: getattr(reply, key) for key in fields if hasattr(reply, key)}
    original = digest(payload)
    wire = deepcopy(payload.get("native_message"))
    decoded = []
    if isinstance(wire, dict):
        for call in wire.get("tool_calls") or []:
            if not isinstance(call, dict) or not isinstance(call.get("function"), dict):
                continue
            function = call["function"]
            try:
                arguments = json.loads(function.get("arguments", ""))
            except (ValueError, TypeError):
                continue
            decoded.append((function, arguments))
    known = collect_secrets(
        [payload.get("tool_calls"), [args for function, args in decoded]], secrets)
    for function, arguments in decoded:
        masked = mask_secrets(arguments, known)
        if masked != arguments:
            function["arguments"] = json.dumps(masked, ensure_ascii=False, allow_nan=False)
    if isinstance(wire, dict):
        payload["native_message"] = wire
        payload["text"] = json.dumps(wire, ensure_ascii=False, allow_nan=False)
    return original, safe_data(payload, known)
