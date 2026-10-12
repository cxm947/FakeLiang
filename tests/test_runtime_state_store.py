"""Run with: python -m pytest -q tests/test_runtime_state_store.py"""
import multiprocessing
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from runtime import locking as locks
from runtime import controller_store, registry_store, state_codec


def _hold_registry(root, ready, release):
    writer = locks.RegistryWriter(root)
    with locks.acquire_registry(writer, timeout_s=2):
        ready.send("LOCKED")
        if not release.wait(15):
            raise RuntimeError("parent did not release holder")
    ready.send("RELEASED")
    ready.close()


def _other_writer(root, ready):
    writer = locks.RegistryWriter(root)
    store = registry_store.RegistryStore(root, writer)
    result = store.update(lambda value: value["contexts"].update(other={"at": 1}))
    ready.send(isinstance(result, state_codec.Committed))
    ready.close()


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.instance = locks.acquire_orchestrator(self.root)
        self.assertIsInstance(self.instance, locks.LockGuard)
        self.addCleanup(self.instance.close)
        self.store = registry_store.RegistryStore(self.root, self.instance)
        self.assertIsInstance(self.store.initialize(), state_codec.Committed)

    def _receive(self, pipe):
        self.assertTrue(pipe.poll(10), "child did not report its state")
        return pipe.recv()

    def _stop_child(self, child):
        child.join(5)
        if child.is_alive():
            child.terminate()
            child.join(5)
        self.assertFalse(child.is_alive())

    def test_reader_busy_and_explicit_retry(self):
        context = multiprocessing.get_context("spawn")
        reader, writer = context.Pipe(duplex=False)
        release = context.Event()
        child = context.Process(target=_hold_registry,
                                args=(str(self.root), writer, release))
        child.start()
        writer.close()
        try:
            self.assertEqual(self._receive(reader), "LOCKED")
            before = self.store.path.read_bytes()
            self.assertEqual(self.store.snapshot().revision, 0)
            mutation = mock.Mock(side_effect=lambda value:
                                 value["contexts"].update(local={"at": 2}))
            result = self.store.update(mutation, timeout_s=0)
            self.assertIsInstance(result, locks.Busy)
            mutation.assert_not_called()
            self.assertEqual(self.store.path.read_bytes(), before)
            release.set()
            self.assertEqual(self._receive(reader), "RELEASED")
            self.assertIsInstance(self.store.update(mutation), state_codec.Committed)
            mutation.assert_called_once()
        finally:
            release.set()
            reader.close()
            self._stop_child(child)
        self.assertEqual(child.exitcode, 0)

    def test_update_rereads_after_other_writer(self):
        stale = self.store.snapshot()
        context = multiprocessing.get_context("spawn")
        reader, writer = context.Pipe(duplex=False)
        child = context.Process(target=_other_writer, args=(str(self.root), writer))
        child.start()
        writer.close()
        try:
            self.assertIs(self._receive(reader), True)
            self.assertEqual(stale.data["contexts"], {})
            self.store.update(lambda value: value["contexts"].update(local={"at": 2}))
            current = self.store.snapshot()
            self.assertEqual(set(current.data["contexts"]), {"local", "other"})
            self.assertEqual(current.revision, 2)
        finally:
            reader.close()
            self._stop_child(child)
        self.assertEqual(child.exitcode, 0)

    def test_dropped_commits_even_when_callback_returns_kept_row(self):
        self.store.update(lambda value: value["sessions"].update(kept={"lifecycle": "registered"}))
        def drop(value):
            value["dropped"].append({"kept": "kept", "dropped": "incoming"})
            return value["sessions"]["kept"]
        result = self.store.update(drop)
        self.assertIsInstance(result, state_codec.Committed)
        self.assertEqual(result.revision, 2)
        self.assertEqual(set(self.store.snapshot().data["sessions"]), {"kept"})
        self.assertEqual(len(self.store.snapshot().data["dropped"]), 1)
        unchanged = self.store.update(lambda value: value["sessions"]["kept"])
        self.assertIsInstance(unchanged, state_codec.Unchanged)
        self.assertEqual(unchanged.revision, 2)

    def test_legacy_schema_and_pure_observations(self):
        raw = b'{"sessions": {}, "resources": {}}'
        self.store.path.write_bytes(raw)
        snapshot = self.store.snapshot()
        self.assertEqual(snapshot.revision, 0)
        self.assertEqual(snapshot.data["dropped"], [])
        self.assertEqual(self.store.path.read_bytes(), raw)
        with mock.patch.object(registry_store, "_read_document", side_effect=AssertionError("reread")):
            self.assertEqual(self.store.observations(snapshot), [])

    def test_invalid_json_schema_and_missing_are_not_empty(self):
        for raw in (b'{"sessions":', b'{"sessions": {}, "sessions": {}}',
                    b'{"sessions": [], "resources": {}}',
                    b'{"sessions": {}, "resources": {}, "releases": {}, "revision": true}'):
            with self.subTest(raw=raw):
                self.store.path.write_bytes(raw)
                with self.assertRaises(state_codec.StateCorrupt):
                    self.store.snapshot()
        self.store.path.unlink()
        with self.assertRaises(state_codec.StorageFault):
            self.store.snapshot()
        with self.assertRaises(state_codec.StorageFault):
            self.store.update(lambda value: None)

    def test_postcommit_unlock_failure_carries_result_and_never_replays(self):
        mutation = mock.Mock(side_effect=lambda value:
                             (value["contexts"].update(local={"at": 2}), "saved")[1])
        with mock.patch.object(locks, "_unlock", side_effect=OSError("injected unlock failure")):
            with self.assertRaises(state_codec.StorageFault) as caught:
                self.store.update(mutation)
        fault = caught.exception
        self.assertEqual(fault.commit_state, "COMMITTED")
        self.assertEqual(fault.committed_result.value, "saved")
        self.assertEqual(fault.committed_result.revision, 1)
        mutation.assert_called_once()
        self.assertEqual(self.store.snapshot().revision, 1)
        with locks.acquire_registry(self.instance, timeout_s=0):
            pass

    def test_permission_failure_is_not_busy(self):
        before = self.store.path.read_bytes()
        with mock.patch.object(state_codec.os, "replace", side_effect=PermissionError("denied")):
            with self.assertRaises(state_codec.StorageFault) as caught:
                self.store.update(lambda value: value["contexts"].update(local={}))
        self.assertEqual(caught.exception.commit_state, "NOT_COMMITTED")
        self.assertEqual(self.store.path.read_bytes(), before)

    def test_writer_authority(self):
        reader = registry_store.RegistryStore(self.root)
        self.assertEqual(reader.snapshot().revision, 0)
        with self.assertRaises(locks.LockProtocolError):
            reader.update(lambda value: None)
        with self.assertRaises(locks.LockProtocolError):
            registry_store.RegistryStore(self.root / "other", self.instance).initialize()
        self.instance.close()
        with self.assertRaises(locks.LockProtocolError):
            self.store.update(lambda value: None)

    def test_resource_ledger_uses_same_instance_root(self):
        resources = registry_store.RegistryStore(
            self.root, self.instance, relative_path="session-resources/sessions.json"
        )
        self.assertIsInstance(resources.initialize(), state_codec.Committed)
        resources.update(lambda value: value["resources"].update(port={"owner": "delivery"}))
        self.assertIn("port", resources.snapshot().data["resources"])
        self.assertFalse((self.root / "session-resources" / ".locks").exists())

    def test_controller_jsonl_atomic_publish_and_shared_gate(self):
        first = controller_store.ControllerStore(self.instance)
        second = controller_store.ControllerStore(self.instance)
        first.register_record("step", "events", "step-1/events.jsonl", format="jsonl")
        result = first.update_record("step", "events",
                                     lambda rows: rows.append({"seq": 1}), initial=list)
        self.assertIsInstance(result, state_codec.Committed)
        self.assertEqual(second.read_record("step", "events"), [{"seq": 1}])
        with self.assertRaises(locks.LockProtocolError):
            first.update_record(
                "step", "events",
                lambda rows: second.update_record("step", "events", lambda items: None)
            )
        before = (self.root / "step-1/events.jsonl").read_bytes()
        with mock.patch.object(state_codec.os, "replace", side_effect=PermissionError("denied")):
            with self.assertRaises(state_codec.StorageFault):
                first.update_record("step", "events", lambda rows: rows.append({"seq": 2}))
        self.assertEqual((self.root / "step-1/events.jsonl").read_bytes(), before)
        with mock.patch.object(locks, "acquire_registry", side_effect=AssertionError("OS lock")):
            second.update_record("step", "events", lambda rows: rows.append({"seq": 2}))
        self.assertEqual(len(first.read_record("step", "events")), 2)
        (self.root / "step-1/events.jsonl").write_bytes(b'{"seq": 1}')
        with self.assertRaises(state_codec.StateCorrupt):
            first.read_record("step", "events")


if __name__ == "__main__":
    unittest.main()
