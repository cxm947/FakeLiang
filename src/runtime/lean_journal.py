"""Durable journal records and artifact integrity for a lean run."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
import re
import time

from runtime.runner import ownership


CALL_ID = re.compile(r"call-[0-9]{8}T[0-9]{6}-[0-9a-f]{6}-[0-9a-f]{32}")

def _bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("utf-8")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _error(code, detail=""):
    raise ValueError(code + (": " + str(detail) if detail else ""))


class _LeanJournal:

    def _read(self):
        path = self.root / "events.jsonl"
        if not path.exists():
            return []
        try:
            data = path.read_bytes()
            if data and not data.endswith(b"\n"):
                _error("LEAN_LOG_INVALID", "incomplete final record")
            rows = [json.loads(line) for line in data.splitlines()]
            for number, row in enumerate(rows, 1):
                if not isinstance(row, dict) or row.get("seq") != number or row.get("run_id") != self.run_id:
                    _error("LEAN_LOG_INVALID", "record identity or ordering differs")
            return rows
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            _error("LEAN_LOG_INVALID", error)

    def _append(self, kind, **payload):
        rows = self._read()
        event = {"seq": len(rows) + 1, "run_id": self.run_id, "at": time.time(),
                 "kind": kind, **payload}
        with (self.root / "events.jsonl").open("ab") as stream:
            stream.write(_bytes(event))
            stream.flush()
            os.fsync(stream.fileno())
        return event

    def _calls(self, events):
        intents, receipts = {}, {}
        for event in events:
            if event.get("kind") == "intent":
                key = event.get("call_id")
                if not isinstance(key, str) or not CALL_ID.fullmatch(key) or key in intents:
                    _error("LEAN_LOG_INVALID", "duplicate or invalid call identity")
                intents[key] = event
            elif event.get("kind") == "receipt":
                key = event.get("call_id")
                if key not in intents or key in receipts:
                    _error("LEAN_LOG_INVALID", "receipt without one original intent")
                receipts[key] = event["receipt"]
        return intents, receipts

    def _artifact(self, call_id, name):
        if not CALL_ID.fullmatch(str(call_id)):
            _error("LEAN_CALL_UNKNOWN", "invalid call identity")
        path = self.root / "calls" / call_id / name
        expected = self.root / "calls" / call_id
        if path.is_symlink() or expected.is_symlink() or expected.parent.is_symlink() \
                or path.resolve().parent != expected:
            _error("LEAN_ARTIFACT_INVALID", "artifact path escaped its call")
        return path

    def _verify(self, call_id, receipt):
        try:
            saved = self._artifact(call_id, "receipt.json").read_bytes()
            if saved != _bytes(receipt) or receipt.get("call_id") != call_id \
                    or receipt.get("run_id") != self.run_id:
                _error("LEAN_ARTIFACT_CHANGED", "receipt differs from registration")
            for name, entry in receipt["artifacts"].items():
                if name not in {"stdout.txt", "stderr.txt", "call.json"}:
                    _error("LEAN_ARTIFACT_INVALID", "unregistered artifact name")
                raw = self._artifact(call_id, name).read_bytes()
                if {"bytes": len(raw), "sha256": _sha(raw)} != entry:
                    _error("LEAN_ARTIFACT_CHANGED", name)
        except (OSError, KeyError, TypeError) as error:
            _error("LEAN_ARTIFACT_INVALID", error)
        return receipt

    def _pending(self, events):
        intents, receipts = self._calls(events)
        pending = []
        # Abandon stops local waiting; it cannot settle the remote outcome.
        for call_id in intents:
            receipt = receipts.get(call_id)
            if receipt is not None:
                self._verify(call_id, receipt)
            if receipt is None or receipt.get("status") != "completed_transport":
                pending.append(call_id)
        return pending

    def _view(self, receipt):
        self._verify(receipt["call_id"], receipt)
        return dict(deepcopy(receipt), **{name: self._artifact(receipt["call_id"], name + ".txt")
                    .read_text(encoding="utf-8") for name in ("stdout", "stderr")})

    def read_evidence(self, call_id, stream="stdout", start=0, limit=2000, contains=""):
        """Inspect a bounded local receipt; never dispatch or settle a call."""
        if (not isinstance(call_id, str) or not isinstance(stream, str)
                or stream not in {"stdout", "stderr"}
                or type(start) is not int or start < 0
                or type(limit) is not int or not 1 <= limit <= 2000
                or not isinstance(contains, str) or len(contains) > 200):
            _error("LEAN_EVIDENCE_REQUEST_INVALID")
        with ownership(self.root):
            intents, receipts = self._calls(self._read())
            if call_id not in intents or intents[call_id].get("parent_call_id"):
                _error("LEAN_CALL_UNKNOWN", call_id)
            receipt = receipts.get(call_id)
            if receipt is None:
                _error("LEAN_EVIDENCE_UNAVAILABLE", call_id)
            source = self._view(receipt)[stream]
            if start > len(source):
                _error("LEAN_EVIDENCE_REQUEST_INVALID", "offset exceeds stream length")
            matched = source.find(contains, start) if contains else start
            found = not contains or matched >= 0
            offset = max(0, matched - 120) if contains and found else start
            text = source[offset:offset + limit] if found else ""
            evidence = {"call_id": call_id, "stream": stream, "start": offset,
                        "text": text, "total_chars": len(source),
                        "next_start": offset + len(text), "found": found,
                        "status": receipt.get("status"), "command_rc": receipt.get("command_rc")}
            self._append("receipt_read", evidence=self._safe(evidence))
            return evidence

    def history(self):
        with ownership(self.root):
            events = deepcopy(self._read())
            for event in events:
                if event.get("kind") == "receipt":
                    event["receipt"] = self._view(event["receipt"])
            return events

    def model_history(self):
        """Declared material producers reason over private observations via projection."""
        events = self.history()
        if self.card.get("materials"):
            for event in events:
                if event.get("kind") == "receipt":
                    receipt = event["receipt"]
                    receipt.update(self.observations.get(receipt["call_id"], {}))
        return events

    def record_decision(self, prompt, reply):
        with ownership(self.root):
            return self._append("decision", prompt=self._safe(prompt), reply=self._safe(reply))

    def record_abandon(self, call_id, reason=""):
        """Record local stop-waiting, without cancellation, settlement or retry permission."""
        with ownership(self.root):
            return self._append("abandon", call_id=str(call_id or ""), reason=str(reason or "")[:200])

    def record_refusal(self, refusal):
        """A refused request belongs in the next prompt: why it was refused, and what is allowed.

        Without this the runtime had only two answers - run it, or stop the node - so a model that
        asked for something this deployment does not offer lost the whole step instead of picking
        again. Measured 2026-10-06: node 5 asked for ``http`` on a shell-only card and the node
        ended on its first turn.
        """
        with ownership(self.root):
            return self._append("refusal", refusal=self._safe(refusal))



    def _recovery_fact(self, call_id, intent, events, *, adopt=True):
        """Classify this original call without sending or reading remote output."""
        from graph.files import atomic_write
        from types import SimpleNamespace

        fact = {"call_id": call_id, "state": "unknown",
                "reason": "LEAN_COMMIT_UNCONFIRMED",
                "deadline_at": intent.get("deadline_at")}
        intents, receipts = self._calls(events)
        children = [key for key, row in intents.items()
                    if row.get("parent_call_id") == call_id]
        if children:
            facts = [self._recovery_fact(key, intents[key], self._read(), adopt=adopt)
                     for key in children]
            if any(item["state"] == "unknown" for item in facts):
                return dict(fact, reason="LEAN_STAGING_UNCONFIRMED")
        receipt = receipts.get(call_id)
        try:
            if receipt is not None:
                self._verify(call_id, receipt)
                if receipt.get("status") == "completed_transport":
                    return dict(fact, state="finished", reason="LEAN_REGISTERED_RECEIPT")
                return fact
            path = self._artifact(call_id, "receipt.json")
            if path.exists():
                receipt = json.loads(path.read_text(encoding="utf-8"))
                if (receipt.get("marker") != intent.get("marker")
                        or set(receipt.get("artifacts") or {})
                           != {"stdout.txt", "stderr.txt", "call.json"}):
                    return dict(fact, reason="LEAN_RECEIPT_ASSOCIATION_LOST")
                self._verify(call_id, receipt)
                if adopt:
                    self._append("receipt", call_id=call_id, receipt=receipt)
                if receipt.get("status") == "completed_transport":
                    return dict(fact, state="finished", reason="LEAN_SAVED_RECEIPT")
                return fact
            metadata_path = self._artifact(call_id, "call.json")
            if metadata_path.exists():
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                if (metadata.get("call_id") != call_id
                        or metadata.get("skill") != self._safe(self.card["id"])
                        or type(metadata.get("timed_out")) is not bool):
                    return dict(fact, reason="LEAN_ARTIFACT_ASSOCIATION_LOST")
                captured = {name: self._artifact(call_id, name + ".txt")
                            .read_text(encoding="utf-8")
                            for name in ("stdout", "stderr")}
                result = SimpleNamespace(**captured,
                    returncode=metadata.get("returncode"),
                    timed_out=metadata["timed_out"],
                    tool_error=metadata.get("tool_error"),
                    read_stop=metadata.get("read_stop"))
                receipt = self._receipt_for(call_id, intent["marker"], result,
                                           framed_required=intent.get("framed_required", True))
                if receipt.get("status") != "completed_transport":
                    return fact
                saved = [row for row in events if row.get("kind") == "commit"
                         and row.get("call_id") == call_id
                         and row.get("phase") == "artifacts_saved"]
                if saved and saved[-1].get("artifacts") != receipt["artifacts"]:
                    return dict(fact, reason="LEAN_ARTIFACT_CHANGED")
                if adopt:
                    atomic_write(path, _bytes(receipt))
                    self._append("receipt", call_id=call_id, receipt=receipt)
                return dict(fact, state="finished", reason="LEAN_PROVEN_ARTIFACT")
            phases = [row.get("phase") for row in events
                      if row.get("kind") == "commit" and row.get("call_id") == call_id]
            if "before_commit" in phases and "committing" not in phases:
                return dict(fact, state="not_executed", reason="LEAN_PROVEN_UNCOMMITTED")
        except (ValueError, OSError, KeyError, TypeError):
            return dict(fact, reason="LEAN_RECOVERY_QUERY_UNCONFIRMED")
        return fact

    def recover_calls(self):
        """Explicit same-run entry: preserve unknown and adopt only original evidence."""
        with ownership(self.root):
            events = self._read()
            intents, _ = self._calls(events)
            return [dict(self._recovery_fact(key, row, self._read()),
                         parent_call_id=row.get("parent_call_id", ""))
                    for key, row in intents.items()]
