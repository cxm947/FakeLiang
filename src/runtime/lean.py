"""Small, explicit HTTP runtime: durable calls and checked quotations, never machine proof."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import time
from uuid import uuid4

from graph.files import atomic_write
from runtime import channels, dispatch
from runtime import lean_http
from runtime.markers import call_marker, marker_script, shell_command
from runtime.redact import MASK, is_secret_field, redact_text, residual_tokens
from runtime.redact import (
    _HEADER_SECRETS,
    _HEADER_VALUE,
    collect_secrets,
    mask_secrets,
)
from runtime.runner import ExecOutcome, execute, new_call_id, ownership

from runtime.lean_journal import CALL_ID, _bytes, _error, _sha, _LeanJournal
from runtime.lean_transport import (
    ACTION_GAP_SECONDS, _MATERIAL_VALUE, _inline_budget, observation_secrets,
    stage_payload_for, _transport_receipt_fields, _LeanTransport,
)
from runtime.lean_evidence import _fold_ws, _raw_offset, _LeanEvidence


class LeanRun(_LeanJournal, _LeanTransport, _LeanEvidence):

    """One frozen run, one control owner, and no automatic replay or business verdict."""

    def __init__(self, run_dir, *, card, task, scope, executor, python="python3", timeout=60, secrets=(),
                 proxy=(), session=None):
        self.root = Path(run_dir).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.card, self.task, self.scope = deepcopy(card), deepcopy(task), deepcopy(scope)
        self.executor, self.python, self.timeout = executor, str(python), timeout
        if session is not None and not isinstance(session, dict):
            _error("LEAN_SESSION_BINDING_INVALID")
        self.session = deepcopy(session)
        self.speaks = str((self.session or {}).get("session_type") or "")
        self.proxy = [str(part) for part in (proxy or ())]
        self.observations = {}
        #: 卡没声明 materials 时，模型多给的那份会被忽略 —— 这个标记让"忽略过"留痕，不静默。
        self.ignored_materials = False
        # The card is documentation: it may *mention* a header name and a placeholder, and a
        # pattern collector would mistake that mention for a live value - which then masks the
        # card text the model is entitled to see verbatim. Only the run's own inputs are sources.
        #: 保持成**列表对象**并始终原地增长：执行器写产物时按同一个对象取脱敏表（见 `transport`）。
        self.secrets = list(collect_secrets({"task": task, "scope": scope}, secrets))
        label = getattr(executor, "label", None)
        self.executor_label = str(label() if callable(label) else "local")
        if self.session is not None:
            endpoint = self.session.get("endpoint") or {}
            self.executor_label = "console:%s:%s/%s" % (
                endpoint.get("host"), endpoint.get("port"), self.session.get("session_id"))
        position = self.executor_label
        if not callable(executor) or not isinstance(timeout, (float, int)) \
                or isinstance(timeout, bool) or not 0 < timeout <= 3600:
            _error("LEAN_RUN_INVALID", "executor and bounded timeout are required")
        if not isinstance(card, dict) or not card.get("id") or not card.get("digest"):
            _error("LEAN_CARD_INVALID", "card id and digest are required")
        if not isinstance(task, dict) or not task.get("node_id") or not isinstance(task.get("inputs"), dict):
            _error("LEAN_TASK_INVALID", "fixed node_id and inputs are required")
        if not isinstance(scope, dict) or not isinstance(scope.get("vantage"), str) \
                or not scope["vantage"].strip():
            _error("LEAN_SCOPE_UNSUPPORTED", "a scope with a fixed vantage is required")
        if scope.get("resources") not in {"whole_endpoint", "execution_position"}:
            _error("LEAN_SCOPE_UNSUPPORTED", "whole_endpoint or execution_position required")
        if card.get("runs_at") not in {"base", "position"}:
            _error("LEAN_EXECUTION_BINDING_INVALID", "card must declare base or position")
        if card["runs_at"] == "base" and (scope.get("resources") != "whole_endpoint"
                                          or scope["vantage"] != "base"):
            _error("LEAN_EXECUTION_BINDING_INVALID",
                   "a base card runs at an endpoint from the base box")
        if scope.get("resources") == "execution_position":
            carrier = str(scope.get("carrier") or "")
            if not carrier or self.session is None or self.session.get("channel_id") != carrier:
                _error("LEAN_EXECUTION_BINDING_INVALID",
                       "a position scope must name its explicit console binding")
        elif card["runs_at"] == "position" and scope["vantage"] != "base" \
                and (not callable(label) or position != scope["vantage"]):
            _error("LEAN_EXECUTION_BINDING_INVALID", "position scope must match the actual executor label")
        lean_http.endpoint_parts(self.scope)
        binding = {"card_id": self._safe(card["id"]), "card_digest": self._safe(card["digest"]),
                   "card_snapshot_digest": _sha(_bytes(card)), "task_digest": _sha(_bytes(task)),
                   "scope": self._safe(self.scope), "executor_label": self._safe(self.executor_label),
                   "python": self._safe(self.python), "timeout": timeout,
                   "client_digest": _sha(lean_http.CLIENT_SOURCE.encode("utf-8")),
                   "session": self._safe(self.session)}
        with ownership(self.root):
            manifest = self.root / "manifest.json"
            if manifest.exists():
                try:
                    saved = json.loads(manifest.read_text(encoding="utf-8"))
                except (ValueError, OSError) as error:
                    _error("LEAN_MANIFEST_INVALID", error)
                if saved.get("binding") != binding:
                    _error("LEAN_BINDING_CHANGED", "resume requires the same card, task, scope and client")
                self.run_id = saved["run_id"]
            else:
                if (self.root / "events.jsonl").exists() or (self.root / "calls").exists():
                    _error("LEAN_MANIFEST_MISSING", "existing history must not be adopted as a new run")
                self.run_id = "run-" + uuid4().hex
                atomic_write(manifest, _bytes({"run_id": self.run_id, "binding": binding,
                                              "task": self._safe(task)}))
            self._read()

    def _safe(self, value):
        value = mask_secrets(value, self.secrets)
        if isinstance(value, dict):
            return {mask_secrets(str(key), self.secrets): MASK if is_secret_field(key) or
                    str(key).lower() in _HEADER_SECRETS else self._safe(item)
                    for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._safe(item) for item in value]
        return redact_text(mask_secrets(value, self.secrets)) if isinstance(value, str) else value
