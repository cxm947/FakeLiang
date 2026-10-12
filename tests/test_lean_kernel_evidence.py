"""Offline counterexamples for the runtime's three retained trust boundaries."""
from copy import deepcopy
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import tempfile

import pytest

from runtime import lean, lean_transport
from runtime.runner import ExecOutcome, ownership

from tests.test_lean_kernel import Collector, REQUEST, run_at, TASK, CARD


def test_real_quotation_and_wrapper_marker_never_become_machine_proof_or_replay(tmp_path):
    transport = Collector()
    run = run_at(tmp_path, transport)
    receipt = run.call(REQUEST)
    assert re.fullmatch(r"call-[0-9]{8}T[0-9]{6}-[0-9a-f]{6}-[0-9a-f]{32}", receipt["call_id"])
    citation = run.cite(receipt["call_id"], "root", require_marker=True)
    assert citation["status"] == "checked"
    report = run.conclude("I obtained root", [citation], claimed_verdict="pass")
    assert report["status"] == "model_reported" and report["machine_verified"] is False
    assert report["claimed_verdict"] == "pass"  # Preserved model claim, never the machine status.
    marker = run.cite(receipt["call_id"], receipt["marker"] + "start")
    assert run.conclude("Remote command executed", [marker], "pass")["status"] != "pass"
    assert run.call(dict(REQUEST)) == receipt
    resumed_transport = Collector()
    resumed = run_at(tmp_path, resumed_transport)
    assert resumed.call(REQUEST) == receipt
    assert len(transport.calls) == 1 and resumed_transport.calls == []
    history = resumed.history()
    assert sum(row["kind"] == "intent" for row in history) == 1
    assert next(row["receipt"] for row in history if row["kind"] == "receipt")["stdout"] == receipt["stdout"]


def test_only_registered_run_output_can_be_quoted_and_checked_flags_are_untrusted(tmp_path):
    run = run_at(tmp_path / "one")
    receipt = run.call(REQUEST)
    for quote, stream in [("not in output", "stdout"), ("", "stdout"), ("root", "call.json"),
                           ("root", "../../elsewhere"), ("root", "request")]:
        with pytest.raises(ValueError, match="LEAN_CITATION"):
            run.cite(receipt["call_id"], quote, stream=stream)
    other = run_at(tmp_path / "two")
    with pytest.raises(ValueError, match="LEAN_CALL_UNKNOWN"):
        other.cite(receipt["call_id"], "root")
    forged = {"call_id": receipt["call_id"], "quote": "not in output", "status": "checked"}
    report = run.conclude("true", [forged], "pass")
    assert report["status"] == "uncertain" and report["rejections"]
    path = tmp_path / "one" / "calls" / receipt["call_id"] / "stdout.txt"
    path.write_text("root from a modified file", encoding="utf-8")
    with pytest.raises(ValueError, match="LEAN_ARTIFACT_CHANGED"):
        run.cite(receipt["call_id"], "root")
    with pytest.raises(ValueError, match="LEAN_ARTIFACT_CHANGED"):
        run.call(dict(REQUEST, path="/next"))


def test_encoded_parameters_and_secrets_never_enter_audit_or_model_records(tmp_path):
    secret = "test-secret-8675309"
    transport = Collector(body="response " + secret)
    run = run_at(tmp_path, transport, secrets=[secret], task=dict(TASK, inputs={"password": secret}))
    request = dict(REQUEST, method="POST", body=secret, headers={"Authorization": "Bearer " + secret})
    receipt = run.call(request)
    run.record_decision({"password": secret, "prompt": secret}, {"reply": secret})
    assert secret not in receipt["stdout"]
    raw_argument = transport.calls[0][0][-1]
    for path in tmp_path.rglob("*"):
        if path.is_file() and path.name != "owner.lock":
            content = path.read_text(encoding="utf-8")
            assert secret not in content
            assert raw_argument not in content
    audit = json.loads((tmp_path / "calls" / receipt["call_id"] / "call.json").read_text(encoding="utf-8"))
    assert audit["argv"][0] == "lean-http-client" and "-c" not in audit["argv"]
    assert audit["vantage"] == receipt["executor_label"] == transport.label()
    assert receipt["scope"]["vantage"] == "base"


def test_a_quote_with_different_json_escaping_still_matches(tmp_path):
    """引文与回执只差 JSON 转义也算对上：回执把响应体按 JSON 串存，模型引的是渲染后的原话。

    2026-10-07 walk-85 node 7 实测：回执里是**双层转义**的响应体
    （`"body": "{\\"status\\":1,…}"`），模型引的是把它还原一层的原话 —— 转义层级不是内容。
    """
    body = '"body": "{\\"status\\":1,\\"msg\\":\\"\\",\\"url\\":\\"general\\\\/index.php\\"}"'
    transport = Collector(body=body)
    run = run_at(tmp_path, transport)
    receipt = run.call(dict(REQUEST, method="GET"))
    checked = run.cite(receipt["call_id"], '{"status":1,"msg":"","url":"general\\/index.php"}')
    assert checked["status"] == "checked" and checked["call_id"] == receipt["call_id"]


def test_a_quote_that_only_differs_in_whitespace_still_matches(tmp_path):
    """引文只差空白也算对上：模型抄回执常把 JSON 的间距改掉，而空白布局不是内容。

    2026-10-07 walk-82 node 7 实测：链条跑通（8 发全 rc=0）、结论也对，就因为把
    `"body": "AGV_SESSION_LAUNCHED"` 抄成 `"body":"AGV_SESSION_LAUNCHED"` 被判引文无效。
    """
    body = '{"peer": {"host": "192.0.2.9"}, "status": 200, "body": "AGV_SESSION_LAUNCHED"}'
    transport = Collector(body=body)
    run = run_at(tmp_path, transport)
    receipt = run.call(dict(REQUEST, method="GET"))
    checked = run.cite(receipt["call_id"], '"body":"AGV_SESSION_LAUNCHED"')
    assert checked["status"] == "checked" and checked["call_id"] == receipt["call_id"]


def test_a_quote_that_contains_a_secret_still_matches_the_masked_receipt(tmp_path):
    """引文里带着凭据原文时也要能对上：回执里存的是脱敏版本，比对前引文要过同一套脱敏。

    2026-10-07 walk-81 node 7 实测：8 发全 rc=0（通达链条跑通了），模型引的那行里带着口令原文，
    而账本里是脱敏后的文本 → `LEAN_CITATION_NOT_FOUND` → 整格停住。观测明明拿到了，是比对口径把它判死的。
    """
    secret = "test-secret-8675309"
    transport = Collector(body="password=" + secret + " (read back)")
    run = run_at(tmp_path, transport, secrets=[secret], task=dict(TASK, inputs={"password": secret}))
    receipt = run.call(dict(REQUEST, method="GET"))
    assert secret not in receipt["stdout"], "账本只存脱敏版本"
    checked = run.cite(receipt["call_id"], "password=" + secret + " (read back)")
    assert checked["status"] == "checked" and checked["call_id"] == receipt["call_id"]
    assert secret not in checked["quote"], "归档里留的也必须是脱敏后的句子"


def test_a_quotation_may_differ_in_whitespace_but_must_really_be_there():
    """引文匹配：允许空白（换行/对齐空格）不同，但仍必须是**这次调用真的打印过**的文字。

    2026-10-06 walk-67 node 14 实测：`nmap -oX -` 的 XML 排版一变，模型引用就对不上，
    连吃两次 `LEAN_CITATION_NOT_FOUND` 把节点停了 —— 而它引的确实是那一段原文。
    """
    import tempfile
    from pathlib import Path
    from runtime.lean import LeanRun
    card = {"id": "x.y", "digest": "d", "runs_at": "base", "tools": ["cmd"]}
    scope = {"host": "10.0.0.5", "port": 80, "protocol": "tcp", "vantage": "base",
             "resources": "whole_endpoint"}
    run = LeanRun(run_dir=Path(tempfile.mkdtemp()), card=card,
                  task={"node_id": "n", "inputs": {}}, scope=scope,
                  executor=lambda argv, timeout: ExecOutcome(
                      0, "agvmstart\nOS              : Windows 7\n状态      关闭\nagvmend\n", ""),
                  timeout=5, secrets=())
    receipt = run.call({"tool": "cmd", "cmd": "sysinfo"})
    call_id = receipt["call_id"]
    #: 把对齐空格收成一个空格 —— 旧规则会判 NOT_FOUND
    ok = run.cite(call_id, "OS : Windows 7")
    assert ok["meaning"] == "quotation_exists_only"
    #: 编造的文字仍然拒
    with pytest.raises(ValueError, match="LEAN_CITATION_NOT_FOUND"):
        run.cite(call_id, "OS : Linux 9")


@pytest.mark.parametrize("short", [False, True])
def test_named_secrets_are_masked_before_first_call_write_and_artifact_hash(tmp_path, monkeypatch, short):
    import hashlib
    from uuid import uuid4

    secret = "".join(map(chr, (126, 33))) if short else uuid4().hex
    supplied = dict(TASK, inputs={"credential_ref": {"user": "operator", "secret": secret}})
    collector = Collector(body="echo:" + secret)
    writes = []
    original_write = Path.write_text

    def observe_write(path, data, *args, **kwargs):
        if path.name in {"stdout.txt", "stderr.txt", "call.json"}:
            assert secret not in data, "masking must precede the first write"
            writes.append(path.name)
        return original_write(path, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", observe_write)
    run = run_at(tmp_path, collector, task=supplied)
    receipt = run.call(dict(REQUEST, method="POST", body=secret))
    assert receipt["status"] == "completed_transport"
    assert set(writes) == {"stdout.txt", "stderr.txt", "call.json"}
    wire = json.loads(base64.b64decode(collector.calls[0][0][-1]))
    assert wire["body"] == secret
    for name, metadata in receipt["artifacts"].items():
        raw = (tmp_path / "calls" / receipt["call_id"] / name).read_bytes()
        assert metadata == {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    run.cite(receipt["call_id"], "<redacted>", require_marker=True)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert secret not in path.read_text(encoding="utf-8"), path


def test_short_secret_is_masked_in_stderr_tool_error_and_dispatch_exception(tmp_path):
    secret = "".join(map(chr, (126, 33)))
    supplied = dict(TASK, inputs={"password": secret})

    def transport(argv, timeout):
        return ExecOutcome(1, "response:" + secret, "stderr:" + secret,
                           tool_error="tool failure:" + secret)

    run = run_at(tmp_path / "outcome", transport, task=supplied)
    receipt = run.call(REQUEST)
    assert receipt["status"] == "unknown" and secret not in json.dumps(receipt)
    assert receipt["tool_error"] == "tool failure:<redacted>"

    def interrupted(argv, timeout):
        raise RuntimeError("interrupted:" + secret)

    run_at(tmp_path / "exception", interrupted, task=supplied).call(REQUEST)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert secret not in path.read_text(encoding="utf-8"), path


def test_secret_sensitive_binding_and_request_replay_identity_are_preserved(tmp_path):
    from uuid import uuid4

    first, second = uuid4().hex, uuid4().hex
    supplied = dict(TASK, inputs={"secrets": [first, second]})
    collector = Collector()
    run = run_at(tmp_path, collector, task=supplied)
    one = run.call(dict(REQUEST, method="POST", body=first))
    two = run.call(dict(REQUEST, method="POST", body=second))
    assert one["call_id"] != two["call_id"] and len(collector.calls) == 2
    assert run.call(dict(REQUEST, method="POST", body=first))["call_id"] == one["call_id"]
    with pytest.raises(ValueError, match="LEAN_BINDING_CHANGED"):
        run_at(tmp_path, collector, task=dict(TASK, inputs={"secrets": [second]}))


def test_a_masked_intent_row_records_the_digest_of_what_it_actually_holds(tmp_path):
    """The row has to be verifiable: its digest must be over the copy the journal keeps.

    walk-138 node 7: the upload carried a payload, masking rewrote the recorded copy, and the
    ledger recomputed the *raw* digest from it -- every such row failed
    RECEIPT_REQUEST_DIGEST_MISMATCH and no http call could ever be evidence.
    """
    from hashlib import sha256
    from uuid import uuid4

    secret = uuid4().hex
    supplied = dict(TASK, inputs={"secrets": [secret]})
    collector = Collector()
    run = run_at(tmp_path, collector, task=supplied)
    receipt = run.call(dict(REQUEST, method="POST", body="uid=1&password=" + secret))
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text(
        encoding="utf-8-sig").splitlines() if line.strip()]
    rows = [row for row in events
            if row.get("kind") == "intent" and row.get("call_id") == receipt["call_id"]]
    assert len(rows) == 1
    stored = (json.dumps(rows[0]["request"], ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    assert sha256(stored).hexdigest() == rows[0]["request_record_digest"]
    assert rows[0]["request_record_digest"] != rows[0]["request_digest"]


def test_structured_secret_mask_keeps_receipt_ids_usable():
    from uuid import uuid4

    secret = "".join(map(chr, (126, 33)))
    identity = "run-" + uuid4().hex
    value = {"run_id": identity, "credential_ref": {"secret": secret}, "echo": "value:" + secret}
    safe = lean.mask_secrets(value, lean.collect_secrets(value))
    assert safe["run_id"] == identity
    assert safe["credential_ref"]["secret"] == "<redacted>" and secret not in json.dumps(safe)


def test_the_correction_feedback_carries_the_actual_text_to_copy(tmp_path):
    """引文失败后的回喂要**带上原文片段** —— 只说"哪几发能引"等于让模型继续凭记忆编。

    2026-10-07 walk-84 node 7 实测：模型编了一条登录响应（六份回执里一个字都没有），
    纠正是给了、可它下一发还是重构；把可引回执的原文片段摆出来，它才有机会照抄。
    """
    run = run_at(tmp_path, Collector(body="real observation text"))
    receipt = run.call(dict(REQUEST, method="GET"))
    index = run.citation_index()
    rows = {row["call_id"]: row for row in index}
    assert receipt["call_id"] in rows
    assert "real observation text" in rows[receipt["call_id"]]["excerpt"]


def test_a_secret_first_seen_in_the_output_never_reaches_the_artifacts(tmp_path):
    """The runtime must grow its secret list in place, not rebind it.

    `execute()` holds the list it was handed and masks the artifacts *after* the call returns, so
    a rebinding left the value this call discovered unmasked on disk (raised by the external
    review 2026-10-08: masking what is already known cannot protect a brand new secret).
    """
    secret = "Sup3r-S3cret-value"
    card = dict(deepcopy(CARD), secret_patterns=[r"(?im)^password\s*:\s*(?P<value>\S+)"])

    def transport(argv, timeout):
        return ExecOutcome(0, "password : %s\n" % secret, "")

    run = run_at(tmp_path, transport, card=card)
    run.call(REQUEST)
    artifacts = list(tmp_path.rglob("stdout.txt")) + list(tmp_path.rglob("call.json"))
    assert artifacts, "the call wrote no artifacts"
    for path in artifacts:
        assert secret not in path.read_text(encoding="utf-8"), path


@pytest.mark.parametrize("verdict", ["uncertain", "unsatisfied", "pass"])
@pytest.mark.parametrize("ran", [False, True])
def test_empty_report_is_valid_but_does_not_establish_output(tmp_path, verdict, ran):
    from orchestration.verification import assessment
    from tests.test_run_plan_support import graph

    run = run_at(tmp_path, Collector(body=""))
    if ran:
        assert run.call(REQUEST)["status"] == "completed_transport"
    report = run.conclude("No printable target evidence was observed.", [], verdict)
    assert report["status"] == "model_reported"
    assert report["reason"] == "MODEL_CLAIM_NOT_MACHINE_VERIFIED"
    assert report["claimed_verdict"] == verdict and report["machine_verified"] is False
    assert report["citations"] == report["rejections"] == report["pending_calls"] == []
    assert assessment.proof_of(None, report) is False
    gate = assessment._fact_gate(document=graph(), node_id="2", verification={})
    assert gate["proved"] is False and gate["reason"] == "OUTPUT_FACT_UNCONFIRMED"
    assert gate["unconfirmed"]


@pytest.mark.parametrize("verdict", ["uncertain", "unsatisfied", "pass"])
@pytest.mark.parametrize("quote", ["", "fabricated login success"])
def test_optional_citations_still_reject_bad_offered_text(tmp_path, verdict, quote):
    run = run_at(tmp_path)
    receipt = run.call(REQUEST)
    report = run.conclude("Unconfirmed result.", [{"call_id": receipt["call_id"],
                                                 "quote": quote}], verdict)
    assert report["status"] == "uncertain" and report["reason"] == "LEAN_CITATION_INVALID"
    assert report["rejections"] and report["citations"] == []
    assert report["machine_verified"] is False


@pytest.mark.parametrize("verdict", ["uncertain", "unsatisfied"])
def test_empty_report_does_not_start_a_citation_correction(tmp_path, verdict):
    from agents.executor.driver import drive
    from tests.test_lean_kernel import SCOPE

    transport = Collector(body="")
    actions = [{"kind": "call", "request": dict(REQUEST)},
               {"kind": "finish", "claim": "No target output was observed.",
                "claimed_verdict": verdict, "citations": []}]
    report = drive(CARD, dict(TASK, scope=dict(SCOPE)), SCOPE, transport,
                   actions=actions, run_dir=tmp_path, max_steps=4)
    assert report["status"] == "model_reported" and len(transport.calls) == 1
    assert report["reason"] == "MODEL_CLAIM_NOT_MACHINE_VERIFIED"
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text(
        encoding="utf-8").splitlines()]
    assert not any(row["kind"] == "correction" for row in events)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_saved_evidence_recovers_text_beyond_the_prompt_prefix(tmp_path, stream):
    body = "header " + "x" * 7500 + " printable-middle-proof " + "y" * 7500

    class BothStreams(Collector):
        def __call__(self, argv, timeout):
            result = super().__call__(argv, timeout)
            return ExecOutcome(result.returncode, result.stdout, body)

    transport = BothStreams(body=body)
    run = run_at(tmp_path, transport)
    receipt = run.call(REQUEST)
    rows = run.citation_index()
    previews = rows[0]["streams"]
    assert previews["stdout"]["chars"] == len(receipt["stdout"])
    assert previews["stderr"]["chars"] == len(receipt["stderr"])
    assert previews["stderr"]["head"] == receipt["stderr"][:320]
    assert previews["stdout"]["tail"] == receipt["stdout"][-320:]
    assert all("printable-middle-proof" not in part
               for preview in previews.values()
               for part in (preview["head"], preview["tail"]))
    evidence = run.read_evidence(receipt["call_id"], stream=stream,
                                 contains="printable-middle-proof")
    assert evidence["found"] and evidence["start"] > 6000
    assert "printable-middle-proof" in evidence["text"]
    assert len(evidence["text"]) <= 2000
    assert evidence["text"] == receipt[stream][evidence["start"]:evidence["next_start"]]
    assert run.cite(receipt["call_id"], "printable-middle-proof",
                    stream=stream, require_marker=True)["status"] == "checked"
    missing = run.read_evidence(receipt["call_id"], stream=stream, contains="not-printed")
    assert missing["found"] is False and missing["text"] == ""
    assert len(transport.calls) == 1


@pytest.mark.parametrize("kwargs", [
    {"stream": "call.json"}, {"start": -1}, {"start": True},
    {"limit": 2001}, {"limit": False}, {"contains": "x" * 201},
])
def test_saved_evidence_rejects_invalid_read_requests(tmp_path, kwargs):
    run = run_at(tmp_path)
    receipt = run.call(REQUEST)
    with pytest.raises(ValueError, match="LEAN_EVIDENCE_REQUEST_INVALID"):
        run.read_evidence(receipt["call_id"], **kwargs)


def test_saved_stderr_does_not_settle_unknown_or_replace_stdout_wrapper(tmp_path):
    class Incomplete(Collector):
        def __call__(self, argv, timeout):
            result = super().__call__(argv, timeout)
            return ExecOutcome(result.returncode, result.stdout, "printable stderr proof")

    transport = Incomplete("no_marker", body="partial stdout")
    run = run_at(tmp_path, transport)
    receipt = run.call(REQUEST)
    before = run._pending(run._read())
    read = run.read_evidence(receipt["call_id"], stream="stderr")
    assert read["status"] == receipt["status"] == "unknown"
    assert read["text"] == "printable stderr proof"
    assert run._pending(run._read()) == before == [receipt["call_id"]]
    with pytest.raises(ValueError, match="LEAN_MARKER_MISSING"):
        run.cite(receipt["call_id"], "printable stderr proof",
                 stream="stderr", require_marker=True)
    assert len(transport.calls) == 1


def test_saved_evidence_enforces_run_identity_and_artifact_integrity(tmp_path):
    run = run_at(tmp_path / "one")
    receipt = run.call(REQUEST)
    other = run_at(tmp_path / "two")
    with pytest.raises(ValueError, match="LEAN_CALL_UNKNOWN"):
        other.read_evidence(receipt["call_id"])
    path = tmp_path / "one" / "calls" / receipt["call_id"] / "stderr.txt"
    path.write_text("invented proof", encoding="utf-8")
    with pytest.raises(ValueError, match="LEAN_ARTIFACT_CHANGED"):
        run.read_evidence(receipt["call_id"])


def test_saved_evidence_slices_redacted_source_and_pages_without_gaps(tmp_path):
    secret = "sensitive-secret-at-page-boundary"
    body = "x" * 180 + secret + " ordinary proof " + "y" * 400
    run = run_at(tmp_path, Collector(body=body), secrets=[secret])
    receipt = run.call(REQUEST)
    read = run.read_evidence(receipt["call_id"], start=190, limit=90)
    assert read["text"] == receipt["stdout"][190:280]
    assert secret not in read["text"] and "sensitive-secret" not in read["text"]
    page = run.read_evidence(receipt["call_id"], start=read["next_start"], limit=90)
    assert page["start"] == read["next_start"]
    assert read["text"] + page["text"] == receipt["stdout"][190:370]
    assert secret not in (tmp_path / "events.jsonl").read_text(encoding="utf-8")


@pytest.mark.parametrize("authorize", ["", "authorize-stager"])
def test_delivery_contract_reports_before_runtime_registration(tmp_path, authorize):
    from orchestration.contracts import DeliveryState
    from orchestration.delivery_setup import add_delivery_inputs

    delivery = DeliveryState(plan={"command": "start-stager",
                                  "declaration": {"materials": {"authorize_command": authorize}}})
    supplied = {"inputs": {}}
    add_delivery_inputs(task=supplied, delivery=delivery, executor=None)
    instruction = supplied["inputs"]["must_deliver_session"]
    assert "after your report" in instruction
    assert "report the delivery receipts honestly" in instruction.lower()
    assert "run it once" in instruction and "uncertain with an empty citation list" in instruction
    assert "only then answer" not in instruction
    assert supplied["inputs"]["delivery_command"] == "start-stager"


def test_harvest_identity_is_context_until_its_source_is_eligible():
    from agents.verifier import runner
    from agents.verifier.prompts import SYSTEM

    task = runner.verification_task(
        None, "44", harvest=[{"session_id": "s1", "identity": {"call_id": "identity-only"}}],
        must_produce=[{"ref": "fact:session"}])
    assert task["calls"] == []
    row = {"ref": "fact:session", "verdict": "UNKNOWN", "proof": "partial",
           "verifier": "model", "reason": "Identity source is not supplied.",
           "checked_calls": []}
    report = runner.read_verdict({"facts": [row]}, expected_refs=["fact:session"],
                                 credited_calls=[])
    assert report["facts"][0]["verdict"] == "UNKNOWN"
    offered = dict(row, verdict="TRUE", call_id="identity-only", quote="user: lab")
    with pytest.raises(ValueError, match="VERIFY_CALL_UNCREDITED"):
        runner.read_verdict({"facts": [offered]}, expected_refs=["fact:session"],
                            credited_calls=[])
    assert "Harvest is context for the separate runtime checker" in SYSTEM
    assert "Otherwise report UNKNOWN" in SYSTEM
