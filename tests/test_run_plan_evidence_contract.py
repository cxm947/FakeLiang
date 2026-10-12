"""Offline regression tests for model-only scheduling and registered fact evidence."""

import csv
import hashlib
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from runtime import session_registry
from orchestration.verification import assessment as assessment_mod  # noqa: E402

from agents.verifier import backstops  # noqa: E402

from orchestration import evidence  # noqa: E402

from agents.planner import service as planning  # noqa: E402

from orchestration import positions  # noqa: E402

from orchestration import reporting  # noqa: E402

from agents.verifier import service  # noqa: E402

from orchestration.verification import assessment as assessment_mod  # noqa: E402

from agents.verifier import backstops  # noqa: E402

from runtime import dispatch  # noqa: E402

from orchestration import evidence  # noqa: E402

from agents.planner import service as planning  # noqa: E402

from orchestration import positions  # noqa: E402

from orchestration import reporting  # noqa: E402

from agents.verifier import service  # noqa: E402

from orchestration import session_flow  # noqa: E402
ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "src", ROOT / "scripts"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import run_plan
from tests.support import stub_callers
from agents.planner import service as planning_mod
from graph import criteria, rehydrate
from graph.parser import read_text
from graph.projector import project



@pytest.fixture
def document():
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerows([
        ("1", "netAccess(target,tcp,443)", "OR", "0"),
        ("2", "RULE 1 (Direct Network Access)", "AND", "0"),
        ("3", "attackerLocated(origin)", "LEAF", "1"),
        ("4", "hacl(origin,target,tcp,443)", "LEAF", "1"),
        ("3", "2", "0"),
        ("4", "2", "0"),
        ("2", "1", "0"),
    ])
    return rehydrate.load_document(project(read_text(
        stream.getvalue(), edge_order="source-target")))


def receipt_fixture(root, *, state="open", read_stop="end_marker", returncode=0,
                    command_rc=0, status="completed_transport", address="192.0.2.20",
                    output_address=None, output_port="443", port="443",
                    vantage="position-A", call_id="call-offline", xml=None, stdout=None,
                    request_mismatch=False, digest_mismatch=False):
    from runtime import dispatch

    root.mkdir(parents=True, exist_ok=True)
    argv = [part.format(port=port, host=address) for part in backstops.REACHABILITY_PROBE]
    request = {"tool": "tool", "name": argv[0], "args": argv[1:]}
    scope = {"host": address, "port": int(port), "protocol": "tcp",
             "resources": "whole_endpoint", "vantage": vantage}
    marker = "offline-marker"
    if xml is None:
        xml = (
            '<nmaprun><scaninfo type="connect" protocol="tcp" services="%s"/>'
            '<host><address addr="%s" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="%s"><state state="%s"/>'
            '</port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
            % (port, output_address or address, output_port, state)
        )
    if stdout is None:
        stdout = marker + "start\n" + xml + "\n" + marker + "end 0\n"
    actual = dispatch.build(request, marker=marker)
    if request_mismatch:
        actual = ["different", "request"]
    contents = {
        "call.json": json.dumps({"call_id": call_id, "argv": actual,
                                  "status": "executed", "returncode": returncode,
                                  "read_stop": read_stop, "timed_out": False,
                                  "tool_error": None}).encode(),
        "stdout.txt": stdout.encode(), "stderr.txt": b"",
    }
    directory = root / "artifacts" / call_id
    directory.mkdir(parents=True)
    manifest = {}
    for name, data in contents.items():
        (directory / name).write_bytes(data)
        manifest[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    encoded = (json.dumps(request, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False) + "\n").encode()
    intent = {
        "kind": "intent", "seq": 1, "call_id": call_id, "run_id": "run-offline",
        "marker": marker, "scope": scope, "request": request,
        "request_digest": "a" * 64 if digest_mismatch else hashlib.sha256(encoded).hexdigest(),
    }
    receipt = {
        "kind": "receipt", "seq": 2, "call_id": call_id, "run_id": "run-offline",
        "receipt": {
            "call_id": call_id, "run_id": "run-offline", "marker": marker,
            "scope": scope, "status": status, "read_stop": read_stop,
            "returncode": returncode, "command_rc": command_rc,
            "timed_out": False, "tool_error": None, "artifacts": manifest,
        },
    }
    (root / "events.jsonl").write_text(
        json.dumps(intent) + "\n" + json.dumps(receipt) + "\n", encoding="utf-8")
    return intent, receipt, directory


def checked_verification(document, node_id, ref, verdict="TRUE", host_map=None):
    graph_hash, epoch = evidence._evidence_context(document, host_map)
    assessment = {
        "verdict": verdict, "checker": "offline_test_checker",
        "proof": "sufficient" if verdict == "TRUE" else "necessary",
        "binding_epoch": epoch,
        "evidence": [{"call_id": "call-checked", "fact_ref": ref,
                      "graph_hash": graph_hash, "binding_epoch": epoch}],
    }
    return {"state": "verified", "node_id": node_id, "graph_hash": graph_hash,
            "binding_epoch": epoch, "assessments": {ref: assessment}}


def test_verification_request_carries_deployment_declarations(document, monkeypatch):
    """The real verification wiring supplies identity context without manufacturing observations."""
    from runtime import model_log
    from agents.verifier import runner as verify

    stub_callers(monkeypatch, "_registered_receipts", lambda path: ([], []), callers=(service, session_flow))
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [])
    sent = []

    def reply_without_observations(client, **request):
        sent.append(request)
        task = json.loads(request["user"])
        payload = {"facts": [
            {"ref": row["ref"], "verdict": "UNKNOWN", "proof": "partial",
             "verifier": "model", "reason": "No completed observations supplied.",
             "checked_calls": []}
            for row in task["facts"]
        ]}
        return SimpleNamespace(ok=True, payload=payload)

    monkeypatch.setattr(model_log, "complete_logged", reply_without_observations)
    host_map = {"origin": "192.0.2.10", "target": "192.0.2.20"}
    bindings = {"position-A": "origin"}
    result = service.verify_node(
        client=SimpleNamespace(complete=lambda **kwargs: None), document=document,
        node_id="2", run_dir=Path("unused"), root=Path("unused"),
        host_map=host_map, source_bindings=bindings,
        role_accounts={"domain_administrator": {"user": "Administrator",
                                                "domain": "WHOAMIANONY"}})
    assert len(sent) == 1
    assert sent[0]["system"] == verify.SYSTEM
    task = json.loads(sent[0]["user"])
    assert task["identity_context"] == {
        "kind": "deployment_declaration", "role_addresses": host_map,
        "vantage_roles": bindings,
        "role_accounts": {"domain_administrator": {"user": "Administrator",
                                                   "domain": "WHOAMIANONY"}},
    }
    assert task["calls"] == []
    assert result["model_claims"]
    assert all(item["verdict"] == "UNKNOWN" for item in result["model_claims"].values())
    assert all(item["verdict"] == "UNKNOWN" for item in result["assessments"].values())


def test_status_and_session_are_not_fact_evidence(document):
    session = {"row_type": "session", "kind": "console_session",
               "logical": "target", "channel_id": "same-host"}
    result = assessment_mod.final_goal_rows(
        document, {"2": {"status": "proved"}}, rows=[session])
    assert result[0]["established"] is False


def test_fact_evidence_does_not_require_producer_status_proved(document):
    verification = checked_verification(document, "2", "1")
    result = assessment_mod.final_goal_rows(
        document, {"2": {"status": "unconfirmed", "verification": verification}})
    assert result[0]["established"] is True


def test_evidence_for_another_ref_does_not_establish_goal(document):
    verification = checked_verification(document, "2", "4")
    result = assessment_mod.final_goal_rows(
        document, {"2": {"status": "proved", "verification": verification}})
    assert result[0]["established"] is False


def test_unknown_output_is_unconfirmed(document):
    graph_hash, epoch = evidence._evidence_context(document)
    verification = {"state": "verified", "node_id": "2",
                    "graph_hash": graph_hash, "binding_epoch": epoch,
                    "assessments": {"1": assessment_mod._unknown_fact()}}
    gate = assessment_mod._fact_gate(document=document, node_id="2", verification=verification)
    assert gate["proved"] is False
    assert gate["status"] == "unconfirmed"


def test_model_claiming_probe_cannot_establish_an_output(document, tmp_path, monkeypatch):
    """A model probe claim still cannot replace checked evidence for an output fact."""
    receipt_fixture(tmp_path)
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [])

    class Client:
        def complete(self, *, task, system, user):
            payload = json.loads(user)
            quote = payload["calls"][0]["stdout"]
            facts = [{"ref": row["ref"], "verdict": "TRUE", "proof": "sufficient",
                      "verifier": "probe", "call_id": "call-offline", "quote": quote}
                     for row in payload["facts"]]
            return SimpleNamespace(ok=True, payload={"kind": "verified", "facts": facts})

    result = service.verify_node(
        client=Client(), document=document, node_id="2",
        run_dir=tmp_path, root=tmp_path, host_map={"target": "192.0.2.20"})
    assert result["model_claims"]["1"]["verdict"] == "TRUE"
    assert result["model_claims"]["1"]["verifier"] == "model"
    assert result["assessments"]["1"]["verdict"] == "UNKNOWN"
    gate = assessment_mod._fact_gate(
        document=document, node_id="2", verification=result,
        host_map={"target": "192.0.2.20"})
    assert gate["status"] == "unconfirmed"


def test_a_cited_model_verdict_carries_a_fact_no_checker_covers(document, tmp_path, monkeypatch):
    """D62: the model does the verifying; the machine backstops only what it can.

    walk-143 node 5: the dump really showed the account's material, the verifier answered TRUE
    with a verbatim quote from that call, and the fact still stayed UNKNOWN -- because account
    facts have no machine checker at all, so a step that succeeded could never be proved.
    A fact that *does* have a checker keeps answering to it (see the probe-claim test above).
    """
    receipt_fixture(tmp_path)
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [])

    class Client:
        def complete(self, *, task, system, user):
            payload = json.loads(user)
            quote = payload["calls"][0]["stdout"]
            facts = [{"ref": row["ref"], "verdict": "TRUE", "proof": "sufficient",
                      "verifier": "model", "call_id": "call-offline", "quote": quote}
                     for row in payload["facts"]]
            return SimpleNamespace(ok=True, payload={"kind": "verified", "facts": facts})

    result = service.verify_node(
        client=Client(), document=document, node_id="2",
        run_dir=tmp_path, root=tmp_path, host_map={"target": "192.0.2.20"})
    #: `attackerLocated(origin)` 没有机器判据 → 模型的合法判定立它。
    assert result["assessments"]["3"]["verdict"] == "TRUE"
    assert result["assessments"]["3"]["checker"] == "model"
    assert result["assessments"]["3"]["proof"] == "sufficient"
    assert result["assessments"]["3"]["evidence"][0]["call_id"] == "call-offline"
    #: `netAccess` 有机器判据 → 机器说核不出，就还是 UNKNOWN。
    assert result["assessments"]["1"]["verdict"] == "UNKNOWN"


@pytest.mark.parametrize("response", ["facts_only", "invalid_json", "timeout"])
def test_output_evidence_survives_model_shape_or_transport_failure(
        document, tmp_path, monkeypatch, response):
    """The exact TCP observation establishes netAccess independently of model formatting."""
    receipt_fixture(tmp_path, read_stop=None)
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [])
    captured = {}

    class Client:
        def complete(self, *, task, system, user):
            before = [json.loads(line) for line in
                      (tmp_path / "model_exchanges.jsonl").read_text(encoding="utf-8").splitlines()]
            assert len(before) == 1 and before[0]["phase"] == "request"
            assert before[0]["request"] == {"task": task, "system": system, "user": user}
            if response == "timeout":
                raise TimeoutError("fixture timeout")
            data = json.loads(user)
            payload = {"facts": [
                {"ref": row["ref"], "verdict": "UNKNOWN", "proof": "partial",
                 "verifier": "model", "reason": "The fixture delegates judgment to the checker.",
                 "checked_calls": [call["call_id"] for call in data["calls"]]}
                for row in data["facts"]]}
            text = json.dumps(payload) if response == "facts_only" else '{"facts":'
            captured["text"] = text
            return SimpleNamespace(ok=True, text=text,
                                   payload=payload if response == "facts_only" else None)

    hosts = {"target": "192.0.2.20"}
    result = service.verify_node(
        client=Client(), document=document, node_id="2", run_dir=tmp_path, root=tmp_path,
        host_map=hosts, source_bindings={"position-A": "origin"})
    assert result["assessments"]["1"]["verdict"] == "TRUE"
    assert result["assessments"]["4"]["verdict"] == "TRUE"
    assert assessment_mod._fact_gate(document=document, node_id="2", verification=result,
                               host_map=hosts)["proved"] is True
    exchanges = [json.loads(line) for line in
                 (tmp_path / "model_exchanges.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [row["phase"] for row in exchanges] == ["request", "response"]
    assert exchanges[0]["exchange_id"] == exchanges[1]["exchange_id"]
    if response == "timeout":
        assert exchanges[1]["text"] is None
        assert "TimeoutError" in exchanges[1]["error"]
    else:
        assert exchanges[1]["text"] == captured["text"]
    journal = [json.loads(line) for line in
               (tmp_path / "model.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(journal) == 1 and journal[0]["task"] == "verify"
    assert bool(result["reason"]) == (response != "facts_only")


def test_exact_quote_is_required_even_for_an_unknown_claim(document, tmp_path, monkeypatch):
    receipt_fixture(tmp_path)
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [])

    def complete(**kwargs):
        task = json.loads(kwargs["user"])
        payload = {"facts": [{"ref": row["ref"], "verdict": "UNKNOWN", "proof": "partial",
                               "verifier": "model", "reason": "No sufficient observation.",
                               "checked_calls": ["call-offline"], "call_id": "call-offline",
                               "quote": "this quotation does not occur"}
                              for row in task["facts"]]}
        return SimpleNamespace(ok=True, payload=payload, text=json.dumps(payload))

    result = service.verify_node(client=SimpleNamespace(complete=complete), document=document,
                                  node_id="2", run_dir=tmp_path, root=tmp_path)
    assert result["model_claims"] == {}
    assert result["reason"].startswith("VERIFY_QUOTE_NOT_IN_RECEIPT")
    assert result["assessments"]["1"]["verdict"] == "UNKNOWN"


def exec_document():
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerows([
        ("1", "execCode(target,system)", "OR", "0"),
        ("2", "RULE 1 (fixture execution)", "AND", "0"),
        ("2", "1", "0"),
    ])
    return rehydrate.load_document(project(read_text(
        stream.getvalue(), edge_order="source-target")))


def test_a_cited_model_verdict_stands_when_the_machine_could_not_check(tmp_path, monkeypatch):
    """"I could not check" is not a verdict against the fact.

    walk-147 node 28: the step's own evidence showed the code running (a real quote from a
    registered call), while the execCode check looks for a *registered session* -- a step that
    only hands over command execution has none, so the checker could only say it found nothing.
    A checker that observes the wrong identity, by contrast, still decides (next assertion).
    """
    receipt_fixture(tmp_path)
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [])

    class Client:
        def complete(self, *, task, system, user):
            payload = json.loads(user)
            quote = payload["calls"][0]["stdout"]
            facts = [{"ref": row["ref"], "verdict": "TRUE", "proof": "sufficient",
                      "verifier": "model", "call_id": "call-offline", "quote": quote}
                     for row in payload["facts"]]
            return SimpleNamespace(ok=True, payload={"kind": "verified", "facts": facts})

    result = service.verify_node(
        client=Client(), document=exec_document(), node_id="2",
        run_dir=tmp_path, root=tmp_path, host_map={"target": "192.0.2.20"})
    assert result["backstops"]["1"]["reason"] == "NO_REGISTERED_OUTPUT_SESSION"
    assert result["assessments"]["1"]["verdict"] == "TRUE"
    assert result["assessments"]["1"]["checker"] == "model"
    assert assessment_mod._fact_gate(document=exec_document(), node_id="2", verification=result,
                               host_map={"target": "192.0.2.20"})["proved"] is True

    #: 机器**核出反面**（身份不是这个事实要的级别）时仍然由机器说话。
    row = {"kind": "console_session", "source_node": "2", "host": "192.0.2.20",
           "session_id": "9", "channel_id": "session-x", "lifecycle": "registered",
           "identity": {"user": "WHOAMIANONY\\Administrator", "uid": "", "environment": "host",
                        "call_id": "call-offline", "at": 1.0}}
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [row])
    again = service.verify_node(
        client=Client(), document=exec_document(), node_id="2",
        run_dir=tmp_path, root=tmp_path, host_map={"target": "192.0.2.20"})
    assert again["backstops"]["1"]["reason"] == "EXEC_IDENTITY_NOT_SYSTEM"
    assert again["assessments"]["1"]["verdict"] == "UNKNOWN"


def test_a_malformed_verification_reply_gets_one_corrective_ask(tmp_path, monkeypatch):
    """一次改正式重问：形状写歪时把错处告诉它，只重问一次（资源不动，不是重试掩盖未决）。"""
    receipt_fixture(tmp_path)
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [])
    calls = {"n": 0}

    class Client:
        def complete(self, *, task, system, user):
            calls["n"] += 1
            payload = json.loads(user)
            quote = payload["calls"][0]["stdout"]
            if calls["n"] == 1:
                #: 第一次：ref 不在清单里（形状错），必须被拒。
                return SimpleNamespace(ok=True, payload={"facts": [
                    {"ref": "not-a-ref", "verdict": "TRUE", "proof": "sufficient",
                     "verifier": "model", "call_id": "call-offline", "quote": quote}]})
            facts = [{"ref": row["ref"], "verdict": "TRUE", "proof": "sufficient",
                      "verifier": "model", "call_id": "call-offline", "quote": quote}
                     for row in payload["facts"]]
            return SimpleNamespace(ok=True, payload={"kind": "verified", "facts": facts})

    result = service.verify_node(
        client=Client(), document=exec_document(), node_id="2",
        run_dir=tmp_path, root=tmp_path, host_map={"target": "192.0.2.20"})
    assert calls["n"] == 2, "the refusal must be asked again, exactly once"
    assert result["model_claims"]["1"]["verdict"] == "TRUE"
    assert result["assessments"]["1"]["verdict"] == "TRUE"
