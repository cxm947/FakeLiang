"""OS locks for one local runtime root; Python 3.10+.

The orchestrator owns its instance lock; attached daemons need no instance lock.
Both use the registry transaction lock. Never unlink or replace .lock files.
Snapshot readers must not call this module.
"""
from __future__ import annotations

from dataclasses import dataclass
import errno
import math
import os
from pathlib import Path
import random
import threading
import time

_WINDOWS = os.name == "nt"
if _WINDOWS:
    import msvcrt as _win
    _posix = None
else:
    import fcntl as _posix
    _win = None

_FILES = {
    "orchestrator": "orchestrator.instance.lock",
    "registry": "registry.write.lock",
}
_TIMEOUTS = {"orchestrator": 2.0, "daemon": 0.2}
_FD_MUTEX = threading.Lock()
_OPEN_FDS: set[int] = set()


@dataclass(frozen=True)
class Busy:
    resource: str
    phase: str
    reason: str
    waited_s: float


@dataclass(frozen=True)
class AlreadyRunning:
    role: str
    resource: str


class LockProtocolError(RuntimeError):
    pass


class LockReleaseError(RuntimeError):
    """Cleanup failed; never interpret this as an uncommitted Busy."""

    def __init__(self, resource, errors):
        super().__init__("failed to release " + resource)
        self.errors = tuple(errors)


def _after_fork_child():
    # Closing a duplicate is safe; LOCK_UN here would unlock the parent's lock.
    try:
        for fd in _OPEN_FDS:
            try:
                os.close(fd)
            except OSError:
                pass
        _OPEN_FDS.clear()
    finally:
        _FD_MUTEX.release()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(
        before=_FD_MUTEX.acquire,
        after_in_parent=_FD_MUTEX.release,
        after_in_child=_after_fork_child,
    )


def _open_fd(path):
    with _FD_MUTEX:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.set_inheritable(fd, False)
            _OPEN_FDS.add(fd)
        except BaseException:
            try:
                os.close(fd)
            finally:
                _OPEN_FDS.discard(fd)
            raise
        return fd


def _close_fd(fd):
    with _FD_MUTEX:
        try:
            os.close(fd)
        finally:
            _OPEN_FDS.discard(fd)


def _try_lock(fd):
    if _WINDOWS:
        # Seek errors are not contention: keep this outside the try block.
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            _win.locking(fd, _win.LK_NBLCK, 1)
        except OSError as exc:
            if exc.errno == errno.EACCES:
                return False
            raise
    else:
        try:
            _posix.flock(fd, _posix.LOCK_EX | _posix.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return False
            raise
    return True


def _unlock(fd):
    if _WINDOWS:
        os.lseek(fd, 0, os.SEEK_SET)
        _win.locking(fd, _win.LK_UNLCK, 1)
    else:
        _posix.flock(fd, _posix.LOCK_UN)


class LockGuard:
    def __init__(self, root, kind, fd, owner=None):
        self.root = root
        self.kind = kind
        self.resource = str(root / ".locks" / _FILES[kind])
        self._fd = fd
        self._pid = os.getpid()
        self._thread = threading.current_thread()
        self._owner = owner
        self._registry_active = False
        self._entered = False

    def __getstate__(self):
        raise TypeError("LockGuard cannot be transferred to another process")

    def assert_valid(self):
        if self._fd is None:
            raise LockProtocolError("guard is closed")
        if os.getpid() != self._pid:
            raise LockProtocolError("guard belongs to another process")
        if threading.current_thread() is not self._thread:
            raise LockProtocolError("guard belongs to another thread")

    def assert_instance(self):
        self.assert_valid()
        if self.kind != "orchestrator":
            raise LockProtocolError("an instance guard is required")

    def __enter__(self):
        self.assert_valid()
        if self._entered:
            raise LockProtocolError("guard is not reentrant")
        self._entered = True
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.close()
        except LockReleaseError as cleanup:
            if exc is not None:
                raise exc.with_traceback(tb) from cleanup
            raise
        return False

    def close(self):
        if self._fd is None:
            return
        self.assert_valid()
        if self._registry_active:
            raise LockProtocolError("close the registry guard first")
        fd, self._fd = self._fd, None
        errors = []
        try:
            try:
                _unlock(fd)
            except OSError as exc:
                errors.append(exc)
            finally:
                try:
                    _close_fd(fd)
                except OSError as exc:
                    errors.append(exc)
        finally:
            if self._owner is not None:
                self._owner._registry_active = False
        if errors:
            raise LockReleaseError(self.resource, errors) from errors[0]


def _acquire(root, kind, timeout_s, deadline, owner=None):
    timeout_s = float(timeout_s)
    if not math.isfinite(timeout_s) or timeout_s < 0:
        raise ValueError("timeout_s must be finite and nonnegative")
    if deadline is not None:
        deadline = float(deadline)
        if not math.isfinite(deadline):
            raise ValueError("deadline must be a finite monotonic timestamp")

    started = time.monotonic()
    end = started + timeout_s
    if deadline is not None:
        end = min(end, deadline)
    root = Path(root).resolve()
    path = root / ".locks" / _FILES[kind]

    def busy(reason):
        return Busy(str(path), "acquire", reason, time.monotonic() - started)

    if deadline is not None and time.monotonic() >= deadline:
        return busy("deadline_exhausted")

    path.parent.mkdir(parents=True, exist_ok=True)
    fd = _open_fd(path)
    attempted = False
    try:
        while True:
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                return busy("deadline_exhausted")
            # timeout=0 permits exactly one attempt, but never past deadline.
            if (attempted or timeout_s > 0) and now >= end:
                return busy("lock_contention" if attempted else "deadline_exhausted")
            attempted = True
            if _try_lock(fd):
                guard = LockGuard(root, kind, fd, owner)
                fd = None
                return guard
            remaining = end - time.monotonic()
            if remaining <= 0:
                return busy("lock_contention")
            time.sleep(min(random.uniform(0.020, 0.100), remaining))
    finally:
        if fd is not None:
            _close_fd(fd)


def _acquire_instance(root, kind):
    result = _acquire(root, kind, 0.0, None)
    if isinstance(result, Busy):
        return AlreadyRunning(kind, result.resource)
    return result


def acquire_orchestrator(root) -> LockGuard | AlreadyRunning:
    return _acquire_instance(root, "orchestrator")


class RegistryWriter:
    """Attached daemon client: no file descriptor, singleton, or instance ownership."""

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.kind = "daemon"
        self._pid = os.getpid()
        self._thread = threading.current_thread()
        self._registry_active = False

    def __getstate__(self):
        raise TypeError("RegistryWriter must be constructed in its owning process")

    def assert_valid(self):
        if os.getpid() != self._pid:
            raise LockProtocolError("writer belongs to another process")
        if threading.current_thread() is not self._thread:
            raise LockProtocolError("writer belongs to another thread")


def acquire_registry(
    instance: LockGuard | RegistryWriter, *, timeout_s=None, deadline=None
) -> LockGuard | Busy:
    """deadline is an absolute time.monotonic() timestamp in this process."""
    if isinstance(instance, LockGuard):
        instance.assert_instance()
    elif isinstance(instance, RegistryWriter):
        instance.assert_valid()
    else:
        raise LockProtocolError("an orchestrator guard or RegistryWriter is required")
    if instance._registry_active:
        raise LockProtocolError("nested registry transaction")
    if timeout_s is None:
        timeout_s = _TIMEOUTS[instance.kind]
    instance._registry_active = True
    try:
        result = _acquire(instance.root, "registry", timeout_s, deadline, instance)
    except BaseException:
        instance._registry_active = False
        raise
    if isinstance(result, Busy):
        instance._registry_active = False
    return result
