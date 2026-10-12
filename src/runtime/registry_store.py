"""Registry snapshots and explicit write transactions."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import inspect
from pathlib import Path

from runtime import locking as locks
from runtime.state_codec import (
    Committed, Unchanged, StateCorrupt, StorageFault,
    _read_document, _encode, _publish, _location,
)




_MAPS = ("sessions", "resources", "releases", "contexts")


def _registry_schema(value, path):
    if not isinstance(value, dict):
        raise StateCorrupt(path, "registry must be an object")
    allowed = {*_MAPS, "dropped", "revision"}
    # Only the documented historic omissions are migrated, in memory.
    if set(value) - allowed or not {"sessions", "resources"} <= value.keys():
        raise StateCorrupt(path, "invalid registry fields")
    if "releases" not in value and set(value) != {"sessions", "resources"}:
        raise StateCorrupt(path, "missing releases")
    value = deepcopy(value)
    for key in ("releases", "contexts"):
        value.setdefault(key, {})
    value.setdefault("dropped", [])
    value.setdefault("revision", 0)
    for key in _MAPS:
        if not isinstance(value[key], dict) or any(
            not isinstance(name, str) or not isinstance(row, dict)
            for name, row in value[key].items()
        ):
            raise StateCorrupt(path, "invalid " + key)
    if not isinstance(value["dropped"], list) or any(
        not isinstance(row, dict) for row in value["dropped"]
    ):
        raise StateCorrupt(path, "invalid dropped")
    if type(value["revision"]) is not int or value["revision"] < 0:
        raise StateCorrupt(path, "invalid revision")
    return value


@dataclass(frozen=True)
class RegistrySnapshot:
    root: Path
    revision: int
    _data: dict

    @property
    def data(self):
        return deepcopy(self._data)

    def sessions(self):
        return [
            dict(deepcopy(row), registry_root=str(self.root))
            for row in self._data["sessions"].values()
            if row.get("lifecycle") != "revoked"
        ]


class RegistryStore:
    def __init__(self, runtime_root, instance=None, *, relative_path="sessions.json"):
        self.root = Path(runtime_root).resolve()
        self.path = _location(self.root, relative_path)
        self.instance = instance

    def _authority(self):
        if isinstance(self.instance, locks.LockGuard):
            self.instance.assert_instance()
        elif isinstance(self.instance, locks.RegistryWriter):
            self.instance.assert_valid()
        else:
            raise locks.LockProtocolError("an orchestrator guard or RegistryWriter is required")
        if self.instance.root != self.root:
            raise locks.LockProtocolError("instance belongs to another runtime_root")

    def snapshot(self):
        value = _registry_schema(_read_document(self.path), self.path)
        return RegistrySnapshot(self.root, value["revision"], value)

    @staticmethod
    def observations(snapshot):
        if not isinstance(snapshot, RegistrySnapshot):
            raise TypeError("a RegistrySnapshot is required")
        return [
            dict(deepcopy(row), registry_root=str(snapshot.root))
            for row in snapshot._data["contexts"].values()
        ]

    def _transaction(self, operation, *, timeout_s, deadline):
        self._authority()
        try:
            guard = locks.acquire_registry(
                self.instance, timeout_s=timeout_s, deadline=deadline
            )
        except OSError as error:
            raise StorageFault(self.path, "acquire", error) from error
        if isinstance(guard, locks.Busy):
            return guard
        try:
            result = operation()
        except BaseException as original:
            try:
                guard.close()
            except Exception as cleanup:
                raise original from cleanup
            raise
        try:
            guard.close()
        except Exception as error:
            committed = result if isinstance(result, Committed) else None
            raise StorageFault(
                self.path, "release", error, committed=committed
            ) from error
        return result

    def initialize(self, *, timeout_s=None, deadline=None):
        """Explicit creation; ordinary reads/updates never hide a missing ledger."""
        absent = object()

        def operation():
            value = _read_document(self.path, missing=absent)
            if value is not absent:
                value = _registry_schema(value, self.path)
                return Unchanged(value["revision"])
            value = {key: {} for key in _MAPS}
            value.update(revision=0, dropped=[])
            result = Committed(0)
            _publish(self.path, value)
            return result

        return self._transaction(operation, timeout_s=timeout_s, deadline=deadline)

    def update(self, mutation, *, timeout_s=None, deadline=None):
        """Run a pure in-memory mutation once, after rereading under the write lock."""
        if not callable(mutation):
            raise TypeError("mutation must be callable")

        def operation():
            before = self.snapshot().data
            after = deepcopy(before)
            value = mutation(after)
            if inspect.isawaitable(value):
                if inspect.iscoroutine(value):
                    value.close()
                raise TypeError("mutation must be synchronous")
            value = deepcopy(value)
            if after.get("revision") != before["revision"]:
                raise ValueError("mutation must not change revision")
            # Validate changes without reclassifying a programming error as disk corruption.
            try:
                if set(after) != set(before):
                    raise ValueError("mutation changed registry fields")
                after = _registry_schema(after, self.path)
                _encode(after)
            except (StateCorrupt, TypeError, ValueError, UnicodeError) as error:
                raise ValueError("invalid registry mutation") from error
            if after == before:
                return Unchanged(before["revision"], value)
            after["revision"] += 1
            result = Committed(after["revision"], value)
            _publish(self.path, after)
            return result

        return self._transaction(operation, timeout_s=timeout_s, deadline=deadline)
