"""Model-call journal checks: one line per call, append-only, honest about failures.

`model.jsonl` is the generation-side twin of `calls.jsonl`: every caller that asks a model appends
exactly one row, in order, so a reader can tell which task asked, whether an answer arrived, and
where the full record lives - without opening any record and without replaying the run.
"""

import json
import tempfile
import unittest
from pathlib import Path

from agents._model import client as model
from runtime import model_log


class FakeClient(model.ModelClient):
    """One canned answer or one canned failure - the client contract, nothing else."""

    name = "fake-1"

    def __init__(self, payload=None, *, ok=True, error=""):
        self.payload = payload
        self.ok = ok
        self.error = error

    def available(self):
        return True

    def complete(self, *, task, system, user, timeout=60.0, retries=2):
        return model.ModelReply(
            ok=self.ok, text=json.dumps(self.payload or {}),
            payload=self.payload if self.ok else None, model=self.name, error=self.error,
            latency_ms=5, attempts=1, request_sha256=model._digest(system + "\n" + user))


class JournalRowTests(unittest.TestCase):
    """The row itself: pinned keys, failures in place, append-only, no directory no journal."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.folder = Path(self._tmp.name)

    def ok_reply(self, task="lean_action"):
        return FakeClient({"kind": "finish"}).complete(task=task, system="s", user="u")

    def test_a_successful_call_is_one_line_with_the_pinned_keys(self):
        line = model_log.record(self.folder, task="lean_action", source="lean",
                                reply=self.ok_reply(), request_sha256="req-1")
        self.assertEqual(list(model_log.ROW_KEYS), list(line))
        rows = model_log.read(self.folder)
        self.assertEqual([line], rows)
        self.assertEqual(list(model_log.ROW_KEYS), list(rows[0]))
        self.assertTrue(rows[0]["ok"])
        self.assertEqual("lean_action", rows[0]["task"])
        self.assertEqual("lean", rows[0]["source"])
        self.assertEqual("fake-1", rows[0]["model"])
        self.assertEqual(1, rows[0]["attempts"])
        self.assertEqual(5, rows[0]["latency_ms"])
        self.assertEqual("req-1", rows[0]["request_sha256"])

    def test_a_failed_call_still_leaves_its_error_in_place(self):
        failed = FakeClient(ok=False, error="the model returned no content").complete(
            task="lean_action", system="s", user="u")
        model_log.record(self.folder, task="lean_action", source="lean", reply=failed)
        rows = model_log.read(self.folder)
        self.assertEqual(1, len(rows))
        self.assertFalse(rows[0]["ok"])
        self.assertEqual("the model returned no content", rows[0]["error"])

    def test_the_stop_reason_rides_the_line_when_a_reply_carries_one(self):
        reply = model.ModelReply(
            ok=False, text="", model="fake-1", attempts=1, finish_reason="length",
            max_tokens=12000,
            error="the model output was truncated (finish_reason=length)")
        line = model_log.record(self.folder, task="lean_action", source="lean",
                                reply=reply, request_sha256="req-3")
        self.assertEqual("length", line["finish_reason"])
        self.assertEqual("length", model_log.read(self.folder)[0]["finish_reason"])

    def test_a_raised_call_records_the_error_class_only(self):
        line = model_log.record(self.folder, task="lean_action", source="lean",
                                error="TimeoutError", request_sha256="req-2")
        self.assertFalse(line["ok"])
        self.assertEqual("TimeoutError", line["error"])
        self.assertIsNone(line["attempts"])

    def test_lines_append_in_order_and_never_rewrite_an_older_one(self):
        model_log.record(self.folder, task="lean_action", source="lean", reply=self.ok_reply())
        first = (self.folder / "model.jsonl").read_text(encoding="utf-8")
        model_log.record(self.folder, task="lean_action", source="lean",
                         metadata={"ok": True, "model": "fake-1"})
        second = (self.folder / "model.jsonl").read_text(encoding="utf-8")
        self.assertTrue(second.startswith(first))
        self.assertEqual(["lean_action", "lean_action"],
                         [row["task"] for row in model_log.read(self.folder)])

    def test_metadata_rows_work_for_callers_that_keep_only_the_counts(self):
        line = model_log.record(self.folder, task="lean_action", source="lean",
                                metadata={"ok": True, "model": "deepseek-chat", "attempts": 0,
                                          "latency_ms": 900},
                                request_sha256="req-3")
        self.assertTrue(line["ok"])
        self.assertEqual("deepseek-chat", line["model"])
        self.assertEqual(900, line["latency_ms"])
        self.assertEqual("req-3", line["request_sha256"])

    def test_a_missing_run_directory_writes_nothing_and_does_not_raise(self):
        line = model_log.record(None, task="lean_action", source="lean", reply=self.ok_reply())
        self.assertTrue(line["ok"])
        self.assertEqual([], list(self.folder.iterdir()))

    def test_read_of_a_directory_without_a_journal_is_empty(self):
        self.assertEqual([], model_log.read(self.folder))


def test_full_exchange_is_recorded_before_parsing_and_secrets_are_masked(tmp_path):
    secret = "fixture-sensitive-value"

    class Client:
        def complete(self, **kwargs):
            request = json.loads((tmp_path / "model_exchanges.jsonl").read_text(encoding="utf-8"))
            assert request["phase"] == "request"
            return model.ModelReply(ok=True, text='{"unrecognized":"' + secret + '"}',
                                    payload={"unrecognized": secret})

    model_log.complete_logged(Client(), run_dir=tmp_path, task="verify",
                              system="s", user=secret, secrets=[secret])
    text = (tmp_path / "model_exchanges.jsonl").read_text(encoding="utf-8")
    assert secret not in text
    rows = [json.loads(line) for line in text.splitlines()]
    assert rows[1]["text"] == '{"unrecognized":"<redacted>"}'
    assert rows[0]["request"]["user"] == "<redacted>"
    assert len(model_log.read(tmp_path)) == 1


def test_unrecordable_request_is_not_sent(tmp_path, monkeypatch):
    calls = []

    def refuse(*args, **kwargs):
        raise OSError("journal unavailable")

    monkeypatch.setattr(model_log.io, "open", refuse)
    client = type("Client", (), {"complete": lambda *args, **kwargs: calls.append(kwargs)})()
    import pytest
    with pytest.raises(OSError, match="journal unavailable"):
        model_log.complete_logged(client, run_dir=tmp_path, task="verify", system="s", user="u")
    assert calls == []


if __name__ == "__main__":
    unittest.main()
