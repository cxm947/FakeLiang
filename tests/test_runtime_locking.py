import errno
import json
import multiprocessing as mp
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from runtime import locking as locks


def _hold_registry(root, pipe, release):
    writer = locks.RegistryWriter(root)
    with locks.acquire_registry(writer):
        pipe.send("LOCKED")
        if not release.wait(15):
            raise RuntimeError("test did not release holder")
    pipe.send("RELEASED")


def _race_instance(root, pipe, role, start, release):
    pipe.send("WAITING")
    if not start.wait(15):
        raise RuntimeError("test did not start race")
    acquire = getattr(locks, "acquire_" + role)
    result = acquire(root)
    if isinstance(result, locks.AlreadyRunning):
        pipe.send("ALREADY_RUNNING")
        return
    with result:
        pipe.send("ACQUIRED")
        if not release.wait(15):
            raise RuntimeError("test did not release winner")


def _race_registry_writer(root, pipe, start, release):
    writer = locks.RegistryWriter(root)
    pipe.send("CLIENT_CREATED")
    if not start.wait(15):
        raise RuntimeError("test did not start registry race")
    result = locks.acquire_registry(writer, timeout_s=0)
    if isinstance(result, locks.Busy):
        pipe.send("BUSY")
        return
    with result:
        pipe.send("ACQUIRED")
        if not release.wait(15):
            raise RuntimeError("test did not release registry winner")


class LockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ctx = mp.get_context("spawn")

    def launch(self, target, *args):
        parent, child = self.ctx.Pipe()
        process = self.ctx.Process(
            target=target, args=(str(self.root), child, *args)
        )
        process.start()
        child.close()
        self.addCleanup(parent.close)

        def stop():
            if process.is_alive():
                process.terminate()
            process.join(10)
            if process.is_alive():
                process.kill()
                process.join(10)
            process.close()

        self.addCleanup(stop)
        return process, parent

    def receive(self, pipe):
        self.assertTrue(pipe.poll(10), "child handshake timed out")
        return pipe.recv()

    def test_read_busy_then_release_and_retry(self):
        path = self.root / "registry.json"
        original = b'{"revision": 7, "channels": {}}\n'
        path.write_bytes(original)
        release = self.ctx.Event()
        process, pipe = self.launch(_hold_registry, release)
        self.assertEqual(self.receive(pipe), "LOCKED")
        with locks.acquire_orchestrator(self.root) as instance:
            self.assertEqual(json.loads(path.read_bytes())["revision"], 7)
            result = locks.acquire_registry(instance, timeout_s=0.05)
            self.assertIsInstance(result, locks.Busy)
            self.assertEqual(path.read_bytes(), original)
            release.set()
            self.assertEqual(self.receive(pipe), "RELEASED")
            with locks.acquire_registry(instance, timeout_s=0):
                self.assertEqual(path.read_bytes(), original)
        process.join(10)
        self.assertEqual(process.exitcode, 0)

    def test_process_death_releases_lock(self):
        process, pipe = self.launch(_hold_registry, self.ctx.Event())
        self.assertEqual(self.receive(pipe), "LOCKED")
        process.terminate()
        process.join(10)
        self.assertFalse(process.is_alive())
        with locks.acquire_orchestrator(self.root) as instance:
            with locks.acquire_registry(instance):
                pass
        self.assertTrue((self.root / ".locks/registry.write.lock").exists())

    def test_double_orchestrator_race(self):
        for role in ("orchestrator",):
            with self.subTest(role=role):
                start, release = self.ctx.Event(), self.ctx.Event()
                first, p1 = self.launch(_race_instance, role, start, release)
                second, p2 = self.launch(_race_instance, role, start, release)
                self.assertEqual(self.receive(p1), "WAITING")
                self.assertEqual(self.receive(p2), "WAITING")
                start.set()
                results = [self.receive(p1), self.receive(p2)]
                self.assertCountEqual(results, ["ACQUIRED", "ALREADY_RUNNING"])
                release.set()
                for process in (first, second):
                    process.join(10)
                    self.assertEqual(process.exitcode, 0)

    def test_daemon_writers_coexist_and_serialize(self):
        start, release = self.ctx.Event(), self.ctx.Event()
        first, p1 = self.launch(_race_registry_writer, start, release)
        second, p2 = self.launch(_race_registry_writer, start, release)
        self.assertEqual(self.receive(p1), "CLIENT_CREATED")
        self.assertEqual(self.receive(p2), "CLIENT_CREATED")
        start.set()
        self.assertCountEqual([self.receive(p1), self.receive(p2)],
                              ["ACQUIRED", "BUSY"])
        release.set()
        for process in (first, second):
            process.join(10)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(sorted(path.name for path in (self.root / ".locks").iterdir()),
                         ["registry.write.lock"])

    def test_deadline_and_jitter_budget(self):
        with locks.acquire_orchestrator(self.root) as instance:
            now, waits = [10.0], []

            def sleep(delay):
                waits.append(delay)
                now[0] += delay

            with mock.patch.object(locks.time, "monotonic", side_effect=lambda: now[0]), \
                 mock.patch.object(locks.time, "sleep", side_effect=sleep), \
                 mock.patch.object(locks.random, "uniform", return_value=0.08) as jitter, \
                 mock.patch.object(locks, "_try_lock", return_value=False) as attempt:
                result = locks.acquire_registry(instance, deadline=10.15)
                self.assertIsInstance(result, locks.Busy)
                self.assertAlmostEqual(sum(waits), 0.15)
                self.assertEqual(attempt.call_count, 2)
                jitter.assert_called_with(0.020, 0.100)
                attempt.reset_mock()
                with mock.patch.object(locks, "_open_fd") as opened:
                    result = locks.acquire_registry(instance, deadline=now[0])
                self.assertIsInstance(result, locks.Busy)
                opened.assert_not_called()
                attempt.assert_not_called()

    def test_defaults_and_nonblocking_instances(self):
        with locks.acquire_orchestrator(self.root) as instance:
            with mock.patch.object(locks.time, "sleep", side_effect=AssertionError):
                self.assertIsInstance(locks.acquire_orchestrator(self.root),
                                      locks.AlreadyRunning)
            for writer, expected in ((instance, 2.0), (locks.RegistryWriter(self.root), 0.2)):
                busy = locks.Busy("registry", "acquire", "lock_contention", 0)
                with mock.patch.object(locks, "_acquire", return_value=busy) as call:
                    self.assertIs(locks.acquire_registry(writer), busy)
                    self.assertEqual(call.call_args.args[2], expected)

    def test_invalid_budgets(self):
        with locks.acquire_orchestrator(self.root) as instance:
            for timeout in (-1, float("nan"), float("inf")):
                with self.assertRaises(ValueError):
                    locks.acquire_registry(instance, timeout_s=timeout)
            for deadline in (float("nan"), float("inf")):
                with self.assertRaises(ValueError):
                    locks.acquire_registry(instance, deadline=deadline)
            with locks.acquire_registry(instance, timeout_s=0):
                pass

    def test_open_permission_error_is_not_busy(self):
        with mock.patch.object(
            locks, "_open_fd", side_effect=PermissionError(errno.EACCES, "denied")
        ):
            with self.assertRaises(PermissionError):
                locks.acquire_orchestrator(self.root)

    def test_windows_offsets_and_error_classification(self):
        fake = SimpleNamespace(LK_NBLCK=1, LK_UNLCK=0, locking=mock.Mock())
        fd = os.open(self.root / "byte-lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            calls = []

            def observe(handle, mode, count):
                calls.append((os.lseek(handle, 0, os.SEEK_CUR), mode, count))

            fake.locking.side_effect = observe
            with mock.patch.object(locks, "_WINDOWS", True), \
                 mock.patch.object(locks, "_win", fake):
                os.lseek(fd, 17, os.SEEK_SET)
                self.assertTrue(locks._try_lock(fd))
                os.lseek(fd, 23, os.SEEK_SET)
                locks._unlock(fd)
                self.assertEqual(calls, [(0, 1, 1), (0, 0, 1)])
                fake.locking.side_effect = PermissionError(errno.EACCES, "held")
                self.assertFalse(locks._try_lock(fd))
                fake.locking.side_effect = OSError(errno.EBADF, "bad descriptor")
                with self.assertRaises(OSError):
                    locks._try_lock(fd)
                fake.locking.reset_mock()
                with mock.patch.object(
                    locks.os, "lseek", side_effect=PermissionError(errno.EACCES, "seek")
                ):
                    with self.assertRaises(PermissionError):
                        locks._try_lock(fd)
                fake.locking.assert_not_called()
        finally:
            os.close(fd)

    def test_guard_qualification_and_cleanup_errors(self):
        with locks.acquire_orchestrator(self.root) as instance:
            errors = []

            def other_thread():
                try:
                    locks.acquire_registry(instance)
                except locks.LockProtocolError as exc:
                    errors.append(exc)

            thread = threading.Thread(target=other_thread)
            thread.start()
            thread.join(10)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            with locks.acquire_registry(instance):
                with self.assertRaises(locks.LockProtocolError):
                    locks.acquire_registry(instance)
                with self.assertRaises(locks.LockProtocolError):
                    instance.close()
            with mock.patch.object(locks, "_unlock", side_effect=OSError("unlock")):
                with self.assertRaises(locks.LockReleaseError):
                    with locks.acquire_registry(instance):
                        pass
                with self.assertRaisesRegex(ValueError, "body") as caught:
                    with locks.acquire_registry(instance):
                        raise ValueError("body")
                self.assertIsInstance(caught.exception.__cause__, locks.LockReleaseError)
            with locks.acquire_registry(instance):
                pass
        with self.assertRaises(locks.LockProtocolError):
            locks.acquire_registry(instance)


if __name__ == "__main__":
    unittest.main()
