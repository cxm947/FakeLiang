"""Receipt evidence: read back what this run's own artifacts say, straight from disk."""
from __future__ import annotations

import json
import re
from pathlib import Path

from graph import rehydrate
from runtime import dispatch


def _evidence_context(document, host_map=None):
    from graph.parser import digest

    view = rehydrate.ensure_view(document)
    graph_hash = view["source_graph"]["graph_hash"]
    epoch = digest({"graph_hash": graph_hash, "host_map": dict(host_map or {})})
    return graph_hash, epoch


def _receipt_artifacts(run_dir, receipt):
    """Find one complete bundle matching the registered artifact manifest."""
    import hashlib

    root = Path(run_dir).resolve()
    names = ("call.json", "stdout.txt", "stderr.txt")
    manifest = receipt.get("artifacts")
    if not isinstance(manifest, dict):
        raise ValueError("RECEIPT_ARTIFACTS_MISSING")
    for name in names:
        entry = manifest.get(name)
        if (not isinstance(entry, dict)
                or type(entry.get("bytes")) is not int or entry["bytes"] < 0
                or not isinstance(entry.get("sha256"), str)
                or re.fullmatch(r"[0-9a-fA-F]{64}", entry["sha256"]) is None):
            raise ValueError("RECEIPT_ARTIFACT_MANIFEST_INVALID")

    matches, seen = [], set()
    for found in root.rglob("call.json"):
        directory = found.parent.resolve()
        if directory in seen:
            continue
        seen.add(directory)
        try:
            directory.relative_to(root)
        except ValueError:
            continue
        contents = {}
        for name in names:
            path = (directory / name).resolve()
            try:
                path.relative_to(root)
                if not path.is_file() or path.stat().st_size != manifest[name]["bytes"]:
                    break
                data = path.read_bytes()
            except (ValueError, OSError):
                break
            if (len(data) != manifest[name]["bytes"]
                    or hashlib.sha256(data).hexdigest() != manifest[name]["sha256"].lower()):
                break
            contents[name] = data
        if set(contents) == set(names):
            matches.append(contents)
    if len(matches) != 1:
        raise ValueError("RECEIPT_ARTIFACT_UNAVAILABLE" if not matches
                         else "RECEIPT_ARTIFACT_AMBIGUOUS")
    return matches[0]


def _framed_stdout(text, marker):
    """Return only the body of one complete, successful registered frame."""
    from runtime.runner import observe_marker_frame

    complete, code = observe_marker_frame(text, marker)
    if not complete or code != 0:
        raise ValueError("RECEIPT_FRAME_UNCONFIRMED")
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.strip() == marker + "start"]
    ends = [i for i, line in enumerate(lines)
            if re.fullmatch(re.escape(marker + "end") + r"[ \t]+[+-]?[0-9]+", line.strip())]
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise ValueError("RECEIPT_FRAME_AMBIGUOUS")
    return "".join(lines[starts[0] + 1:ends[0]])


def _receipt_output(call, marker, stdout):
    """The body of one registered call: a framed body, or the answer of a native verb.

    A meterpreter verb (`sysinfo`, `load kiwi`, `creds_all`) closes no frame, and demanding one
    dropped every call the step had already completed: the run recorded them as
    `completed_transport`, the receipt check for evidence threw `RECEIPT_FRAME_UNCONFIRMED` on
    each, the verifier was handed an empty `calls` list, and the only honest answer left was
    UNKNOWN (measured 2026-10-08, walk-132 node 5: the credentials were in hand and the step
    could not show them). What a frame-less verb printed *is* its answer, exactly as the
    session probe reads identity; an empty capture is still refused.
    """
    argv = call.get("argv")
    if isinstance(argv, list) and [str(part) for part in argv[:2]] == ["console", "native"]:
        if not str(stdout).strip():
            raise ValueError("RECEIPT_OUTPUT_EMPTY")
        return stdout
    return _framed_stdout(stdout, marker)


def _receipt_request_matches(call, request, marker, manifest):
    """Rebuild the recorded transport arguments with the existing dispatcher."""
    from runtime.redact import redact_argv

    binding = manifest.get("binding") or {}
    inputs = (manifest.get("task") or {}).get("inputs") or {}
    session = binding.get("session")
    argv = call.get("argv")
    if request.get("tool") == "body_stage":
        if not (isinstance(argv, list) and len(argv) == 2
                and argv[0] == "lean-http-body-stage" and isinstance(argv[1], str)):
            return False
        try:
            return json.loads(argv[1]) == request
        except (TypeError, ValueError):
            return False
    if request.get("tool") == "http":
        #: A structured request is compared as **the object**, never as its serialization: the
        #: journal is written with sorted keys, so re-dumping it here produced a different key
        #: order and rejected every http row on sight (measured 2026-10-08, walk-138 node 7).
        if not (isinstance(argv, list) and len(argv) == 2 and argv[0] == "lean-http-client"
                and isinstance(argv[1], str)):
            return False
        try:
            return json.loads(argv[1]) == request
        except (TypeError, ValueError):
            return False
    elif session is not None:
        action = dispatch.bind_console(request, session, marker=marker)
        if str(session.get("session_type") or "") in ("web", "entry"):
            #: 入口位置那一发走的是**控制端 argv**（形态由配方决定），账本记的就是它；
            #: 按控制台三段式重建会让入口位置的每一发都判成"请求对不上"
            #: （2026-10-08 walk-157 node 26 实测：命令全跑通、回执里已拿到 root 证据，
            #: 整格仍判"产出事实未确证"，因为验证器拿到的调用列表是空的）。
            from runtime import lean_web

            expected = lean_web.command_argv(action["recipe"], action["text"], marker,
                                             python=str(binding.get("python") or "python3"))
        else:
            expected = ["console", action["operation"], action["text"]]
    else:
        expected = dispatch.build(
            request, platform=str(inputs.get("position_platform") or ""), marker=marker)
    return argv == redact_argv(expected)


def _registered_receipts(run_dir):
    """Pair registered intents and completed receipts; intents alone earn no credit."""
    path = Path(run_dir) / "events.jsonl"
    if not path.is_file():
        return [], ["RECEIPT_JOURNAL_MISSING"]
    groups, issues = {}, []
    try:
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("RECEIPT_EVENT_INVALID")
            if event.get("kind") not in ("intent", "receipt"):
                continue
            call_id = event.get("call_id")
            if not isinstance(call_id, str) or not call_id:
                raise ValueError("RECEIPT_CALL_ID_MISSING")
            groups.setdefault(call_id, []).append(event)
    except (ValueError, OSError, UnicodeError) as error:
        return [], ["RECEIPT_JOURNAL_INVALID: " + str(error)]

    manifest_path = Path(run_dir) / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {}
        if not isinstance(manifest, dict):
            raise ValueError("RECEIPT_MANIFEST_INVALID")
    except (ValueError, OSError) as error:
        return [], ["RECEIPT_MANIFEST_INVALID: " + str(error)]
    calls = []
    for call_id, events in groups.items():
        try:
            intents = [event for event in events if event["kind"] == "intent"]
            receipts = [event for event in events if event["kind"] == "receipt"]
            if len(intents) != 1 or len(receipts) != 1:
                raise ValueError("RECEIPT_PAIR_NOT_UNIQUE")
            intent, event = intents[0], receipts[0]
            receipt = event.get("receipt")
            if not isinstance(receipt, dict):
                raise ValueError("RECEIPT_INVALID")
            run_id = intent.get("run_id")
            if (not isinstance(run_id, str) or not run_id
                    or event.get("run_id") != run_id or receipt.get("run_id") != run_id
                    or receipt.get("call_id") != call_id):
                raise ValueError("RECEIPT_IDENTITY_MISMATCH")
            if (type(intent.get("seq")) is not int or type(event.get("seq")) is not int
                    or intent["seq"] >= event["seq"]):
                raise ValueError("RECEIPT_ORDER_INVALID")
            marker = intent.get("marker")
            if not isinstance(marker, str) or not marker or receipt.get("marker") != marker:
                raise ValueError("RECEIPT_MARKER_MISMATCH")
            scope, request = intent.get("scope"), intent.get("request")
            if (not isinstance(scope, dict) or not isinstance(request, dict)
                    or receipt.get("scope") != scope):
                raise ValueError("RECEIPT_SCOPE_MISMATCH")
            #: Two digests, two jobs（见 lean.LeanRun.call）：`request_digest` 是**重放身份**
            #: （按模型原始请求算，两份只差一个秘密的请求不能被判成同一份）；这里要核的是
            #: `request_record_digest` —— 它按**账本真正存下的那份（已脱敏）请求**算，所以能
            #: 被重算出来，用来证"这一行没被改过"。
            request_digest = intent.get("request_digest")
            if (not isinstance(request_digest, str)
                    or re.fullmatch(r"[0-9a-fA-F]{64}", request_digest) is None):
                raise ValueError("RECEIPT_REQUEST_DIGEST_MISSING")
            #: 老行/夹具只记 `request_digest`（那份请求本来就是没脱敏的原文，两把尺子等长）；
            #: 新行按"账本存下的那份"另记一把。
            record_digest = intent.get("request_record_digest") or request_digest
            if (not isinstance(record_digest, str)
                    or re.fullmatch(r"[0-9a-fA-F]{64}", record_digest) is None):
                raise ValueError("RECEIPT_REQUEST_DIGEST_MISSING")
            if (receipt.get("status") not in ("executed", "completed_transport")
                    or receipt.get("read_stop") not in (None, "end_marker", "quiet")
                    or receipt.get("timed_out") is not False
                    or receipt.get("tool_error") not in (None, "")
                    or type(receipt.get("returncode")) is not int
                    or receipt["returncode"] != 0
                    or type(receipt.get("command_rc")) is not int
                    or receipt["command_rc"] != 0):
                raise ValueError("RECEIPT_COMMAND_UNCONFIRMED")
            if manifest and (manifest.get("run_id") != run_id
                             or (manifest.get("binding") or {}).get("scope") != scope):
                raise ValueError("RECEIPT_MANIFEST_MISMATCH")
            import hashlib
            request_bytes = (json.dumps(request, ensure_ascii=False, sort_keys=True,
                                        separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
            if hashlib.sha256(request_bytes).hexdigest() != record_digest:
                raise ValueError("RECEIPT_REQUEST_DIGEST_MISMATCH")
            artifacts = _receipt_artifacts(run_dir, receipt)
            call = json.loads(artifacts["call.json"].decode("utf-8-sig"))
            if (not isinstance(call, dict) or call.get("call_id") != call_id
                    or not _receipt_request_matches(call, request, marker, manifest)):
                raise ValueError("RECEIPT_REQUEST_UNCONFIRMED")
            if (call.get("status") != "executed"
                    or call.get("returncode") != receipt["returncode"]
                    or call.get("timed_out") is not False
                    or call.get("tool_error") not in (None, "")
                    or call.get("read_stop") != receipt.get("read_stop")):
                raise ValueError("RECEIPT_CALL_OUTCOME_MISMATCH")
            stdout = artifacts["stdout.txt"].decode("utf-8")
            output = _receipt_output(call, marker, stdout)
            parent_id = intent.get("parent_call_id")
            if parent_id:
                parents = [row for row in groups.get(parent_id, [])
                           if row.get("kind") == "intent"]
                if (request.get("tool") != "body_stage" or len(parents) != 1
                        or parents[0].get("run_id") != run_id
                        or parents[0].get("scope") != scope
                        or type(intent.get("staging_index")) is not int
                        or intent["staging_index"] < 0
                        or request.get("index") != intent["staging_index"]
                        or marker != str(parents[0].get("marker") or "") + "w" + str(intent["staging_index"])
                        or request.get("remote_path") != "/tmp/agv-http-" + re.sub(
                            r"[^0-9a-z]", "", str(parents[0].get("marker") or "").lower()) + ".b64"):
                    raise ValueError("RECEIPT_STAGING_ASSOCIATION_LOST")
                continue
            calls.append({"call_id": call_id, "run_id": run_id,
                          "request": request, "request_digest": request_digest,
                          "request_record_digest": record_digest,
                          "scope": scope, "receipt": receipt, "output": output,
                          "stdout": stdout,
                          "stderr": artifacts["stderr.txt"].decode("utf-8")})
        except (ValueError, OSError, UnicodeError) as error:
            issues.append(call_id + ": " + str(error))
    if len({call["run_id"] for call in calls}) > 1:
        return [], issues + ["RECEIPT_RUN_MIXED"]
    return calls, issues
