"""Controller-owned record mappings and transactions."""
from __future__ import annotations

from copy import deepcopy
import inspect
import os
from pathlib import Path
import threading
from weakref import WeakKeyDictionary

from runtime import locking as locks
from runtime.state_codec import (
    Committed, Unchanged, StateCorrupt, StorageFault,
    _read_document, _encode, _publish, _location,
)


class _ControllerGate:
    def __init__(self):
        self.mutex = threading.RLock()
        self.active = False
        self.records = {}
        self.paths = {}


_CONTROLLER_GATES = WeakKeyDictionary()
_CONTROLLER_MUTEX = threading.Lock()


def _reset_controller_gates():
    global _CONTROLLER_GATES, _CONTROLLER_MUTEX
    _CONTROLLER_GATES = WeakKeyDictionary()
    _CONTROLLER_MUTEX = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_controller_gates)


def _record_schema(value, path, format):
    valid = (isinstance(value, dict) if format == "json" else
             isinstance(value, list) and all(isinstance(row, dict) for row in value))
    if not valid:
        raise StateCorrupt(path, "expected a JSON object or JSONL objects")
    return value


class ControllerStore:
    """Explicit record mappings; only the orchestrator's owning thread may write."""

    def __init__(self, instance):
        self.instance = instance
        self._authority()
        self.root = instance.root
        with _CONTROLLER_MUTEX:
            self._gate = _CONTROLLER_GATES.setdefault(instance, _ControllerGate())

    def _authority(self):
        if not isinstance(self.instance, locks.LockGuard):
            raise locks.LockProtocolError("a live orchestrator guard is required")
        self.instance.assert_instance()
        if self.instance.kind != "orchestrator":
            raise locks.LockProtocolError("controller writes require the orchestrator")

    def register_record(self, kind, identifier, relative_path, *, format="json"):
        """Register immutable mappings before sharing this store with readers."""
        self._authority()
        if not all(isinstance(part, str) and part for part in (kind, identifier)):
            raise ValueError("kind and identifier must be nonempty strings")
        if format not in ("json", "jsonl"):
            raise ValueError("unsupported record format")
        path = _location(self.root, relative_path)
        if path in (self.root / "sessions.json",
                    self.root / "session-resources" / "sessions.json"):
            raise locks.LockProtocolError("shared registries require RegistryStore")
        key = (kind, identifier)
        definition = (Path(relative_path), path, format)
        with self._gate.mutex:
            if self._gate.active:
                raise locks.LockProtocolError("cannot register during mutation")
            previous = self._gate.records.get(key)
            if previous is not None and previous != definition:
                raise locks.LockProtocolError("record mapping cannot change")
            owner = self._gate.paths.get(path)
            if owner is not None and owner != key:
                raise locks.LockProtocolError("path already has another record identity")
            self._gate.records[key] = definition
            self._gate.paths[path] = key

    def _record(self, kind, identifier):
        try:
            relative, original, format = self._gate.records[(kind, identifier)]
        except KeyError as error:
            raise locks.LockProtocolError("record is not registered") from error
        path = _location(self.root, relative)
        if path != original:
            raise locks.LockProtocolError("record path identity changed")
        return path, format

    def read_record(self, kind, identifier):
        path, format = self._record(kind, identifier)
        return _record_schema(_read_document(path, format), path, format)

    def update_record(self, kind, identifier, mutation, *, initial=None):
        """initial is an explicit factory, used only when this record is absent."""
        self._authority()
        if not callable(mutation) or (initial is not None and not callable(initial)):
            raise TypeError("mutation and initial must be callable")
        with self._gate.mutex:
            self._authority()
            if self._gate.active:
                raise locks.LockProtocolError("nested controller mutation")
            self._gate.active = True
            try:
                path, format = self._record(kind, identifier)
                absent = object()
                document = _read_document(path, format, missing=absent)
                missing = document is absent
                if missing:
                    if initial is None:
                        error = FileNotFoundError(str(path))
                        raise StorageFault(path, "read", error) from error
                    document = initial()
                if not missing:
                    _record_schema(document, path, format)
                before = deepcopy(document)
                value = mutation(document)
                if inspect.isawaitable(value):
                    if inspect.iscoroutine(value):
                        value.close()
                    raise TypeError("mutation must be synchronous")
                value = deepcopy(value)
                try:
                    _record_schema(document, path, format)
                except StateCorrupt as error:
                    raise ValueError("invalid controller mutation") from error
                _encode(document, format)
                if not missing and document == before:
                    return Unchanged(None, value)
                result = Committed(None, value)
                _publish(path, document, format)
                return result
            finally:
                self._gate.active = False
