"""Offline walk tests use model choices and keep fact evidence separate from step reports."""

import sys
from pathlib import Path
import json
from copy import deepcopy
from uuid import uuid4

import pytest
from unittest.mock import create_autospec


from orchestration import delivery_setup  # noqa: E402
from agents.planner import service as planning  # noqa: E402
from orchestration import positions  # noqa: E402
from agents.verifier import service  # noqa: E402
from orchestration import session_flow  # noqa: E402
from orchestration import walk as walk_mod  # noqa: E402
ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import run_plan                                              # noqa: E402
from agents.executor import driver as run_lean_task                                         # noqa: E402
from tests.support import stub_callers                       # noqa: E402
from agents._model import client as model_mod                        # noqa: E402
from graph import rehydrate                                  # noqa: E402
from orchestration import graph_view, evidence
from agents.planner import service as planning     # noqa: E402
from orchestration import positions as positions_mod  # noqa: E402
from orchestration import preparation, reporting  # noqa: E402
from orchestration import session_flow                       # noqa: E402
from orchestration.graph_view import graph_nodes, needs      # noqa: E402
from agents.planner.service import (                         # noqa: E402
    choice_refusal,
    next_node,
    plan_next,
)
from orchestration.verification import assessment
from agents.verifier import backstops, service  # noqa: E402
from runtime import delivery_commands, dispatch               # noqa: E402
from runtime import session_delivery, session_registry        # noqa: E402
from runtime import credentials                              # noqa: E402
from runtime import session_io                               # noqa: E402
from runtime import session_resources, sessions               # noqa: E402
from skills import bind                                       # noqa: E402



PRODUCER_ID = "1"
ACCOUNT_FACT_ID = "2"
CONSUMER_ID = "3"
GOAL_FACT_ID = "4"
FIXTURE_CALL_ID = "call-20261005T010203-abcdef-test"


def _loaded_test_graph(node_rows, edges):
    from graph.parser import Graph, Node
    from graph.projector import project

    nodes = {str(nid): Node(str(nid), description, kind, "0")
             for nid, description, kind in node_rows}
    source = Graph(nodes, {(str(a), str(b)): "0" for a, b in edges})
    return rehydrate.load_document(project(source))


def graph():
    return _loaded_test_graph(
        [(nid, "RULE 1 (fixture step)", "AND") for nid in ("2", "5", "7", "12", "14")]
        + [("8", "attackerLocated(origin)", "LEAF")]
        + [(nid, "netAccess(host_%s,tcp,443)" % nid, "OR")
           for nid in ("1", "3", "4", "6", "9")],
        [("8", "14"), ("14", "6"), ("6", "12"), ("12", "4"), ("4", "7"),
         ("7", "3"), ("3", "5"), ("5", "1"), ("1", "2"), ("2", "9")],
    )


def checked_observations(document, node_id, verdicts, *, host_map=None):
    """Supply explicit checker observations independently of driver claims."""
    from graph import criteria

    graph_hash, epoch = evidence._evidence_context(document, host_map)
    declarations = criteria.node_criteria(document, node_id) + criteria.to_produce(document, node_id)
    assessments = {}
    for declaration in declarations:
        ref = declaration["ref"]
        verdict = verdicts.get(ref, "UNKNOWN")
        assert verdict in ("TRUE", "FALSE", "UNKNOWN", "UNRESOLVED_CONFLICT")
        if verdict == "UNKNOWN":
            item = assessment._unknown_fact("TEST_OBSERVATION_UNAVAILABLE")
        else:
            item = {
                "verdict": verdict, "checker": "offline_fixture_checker",
                "proof": ("sufficient" if verdict == "TRUE"
                          else "necessary" if verdict == "FALSE" else "partial"),
                "binding_epoch": epoch, "reason": "",
                "evidence": [{"call_id": FIXTURE_CALL_ID, "fact_ref": ref,
                              "graph_hash": graph_hash, "binding_epoch": epoch}],
            }
        assessments[ref] = item
    return {
        "state": "verified", "node_id": str(node_id),
        "graph_hash": graph_hash, "binding_epoch": epoch,
        "assessments": assessments,
        "facts": [{"ref": ref, "verdict": item["verdict"], "proof": item["proof"],
                   "verifier": "probe" if item["checker"] else None}
                  for ref, item in assessments.items()],
    }


class InventoryPlanner:
    """A fixture model that reads inventory and returns the installed three-field wire shape."""

    def __init__(self):
        self.calls = []

    def available(self):
        return True

    def complete(self, *, task, system, user, timeout=None, **kwargs):
        payload, _ = json.JSONDecoder().raw_decode(user.lstrip())
        self.calls.append((task, deepcopy(payload)))
        if task == "verify":
            answer = {
                "facts": [{"ref": row["ref"], "verdict": "UNKNOWN",
                           "proof": "partial", "verifier": "model",
                           "reason": "The fixture has no applicable observation.",
                           "checked_calls": [call["call_id"] for call in payload["calls"]]}
                          for row in payload["facts"]],
            }
        else:
            assert task == "pick_next_node"
            #: 新口径（爷爷 2026-10-08）：输入只有 图 + 已完成(成败) + 上一步(成败)，
            #: 所以这份 fixture 自己按因果推：成功步骤产出的前提事实为真，
            #: 只有"有人产出、但还没为真"的前提才拦住这一步（纯假设类前提不拦）。
            graph = payload["graph"]
            done = {row["node_id"]: row["status"] for row in payload["done"]}
            produced = {ref for step in graph["steps"] for ref in step["produces"]}
            true_facts = {ref for step in graph["steps"]
                          if done.get(step["node_id"]) == "success"
                          for ref in step["produces"]}
            chosen = None
            for step in graph["steps"]:
                if step["node_id"] in done:
                    continue
                if any(ref in produced and ref not in true_facts for ref in step["needs"]):
                    continue
                chosen = step["node_id"]
                break
            answer = {"decision": "continue" if chosen is not None else "done",
                      "next_node_id": chosen,
                      "change_note": "Fixture selection follows the current fact inventory."}
        return model_mod.ModelReply(ok=True, payload=answer, text=json.dumps(answer))


def walk(document, outcomes, *, observations):
    state, order = {}, []
    client = InventoryPlanner()
    while True:
        node, note = plan_next(document=document, state=state, order=order,
                               run_id="offline-walk", client=client)
        assert note["source"] == "model"
        if node is None:
            return order
        node_id = str(node["id"])
        assert node_id not in state
        verification = checked_observations(document, node_id, observations)
        gate = assessment._fact_gate(
            document=document, node_id=node_id, verification=verification)
        status = outcomes.get(node_id, gate["status"])
        assert status != "proved" or gate["proved"]
        state[node_id] = {"status": status, "reason": gate["reason"],
                          "verification": verification}
        order.append(node_id)


def credential_graph(source_host="vault", target_host="worker", account="attacker_role", *,
                     carried=False, producer_only=False):
    rows = [
        (PRODUCER_ID, "RULE 1 (fixture acquisition)", "AND"),
        (ACCOUNT_FACT_ID, f"getAccount({source_host},{account},account_material,admin)", "OR"),
        (CONSUMER_ID, "RULE 2 (fixture use)", "AND"),
        (GOAL_FACT_ID, f"execCode({target_host},admin)", "OR"),
        ("10", f"ttpExists({source_host},lsass,local,lsassCredentialDumping,credentialAccess)", "LEAF"),
        ("11", f"networkServiceInfo({source_host},lsass,tcp,80,admin)", "LEAF"),
        ("12", f"hasAccount({source_host},{account},account_material,admin)", "LEAF"),
        ("13", f"execCode({source_host},admin)", "LEAF"),
        ("14", f"networkServiceInfo({target_host},winrm,tcp,445,admin)", "LEAF"),
        ("15", f"hacl({source_host},{target_host},tcp,445)", "LEAF"),
        ("16", f"isFirewall({target_host},flase)", "LEAF"),
        ("17", f"hasAccount({target_host},{account},account_material,admin)", "LEAF"),
    ]
    edges = [(ref, PRODUCER_ID) for ref in ("10", "11", "12", "13")]
    edges += [(PRODUCER_ID, ACCOUNT_FACT_ID), (CONSUMER_ID, GOAL_FACT_ID)]
    edges += [(ref, CONSUMER_ID) for ref in (ACCOUNT_FACT_ID, "13", "14", "15", "16", "17")]
    assert not (carried and producer_only)
    if carried:
        omitted = {PRODUCER_ID, "10", "11", "12"}
        rows = [(nid, description, "LEAF" if nid == ACCOUNT_FACT_ID else kind)
                for nid, description, kind in rows if nid not in omitted]
    elif producer_only:
        omitted = {CONSUMER_ID, GOAL_FACT_ID, "14", "15", "16", "17"}
        rows = [row for row in rows if row[0] not in omitted]
    kept = {row[0] for row in rows}
    return _loaded_test_graph(rows, [(a, b) for a, b in edges if a in kept and b in kept])


def private_source(tmp_path, account="attacker_role"):
    path = tmp_path / "private" / "context.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    material = {"user": "actual_attacker", "domain": "example.invalid",
                "secret": uuid4().hex, "mode": "password"}
    path.write_text(json.dumps({"credentials": {account: material}}), encoding="utf-8")
    return path, material


def plan_harness(monkeypatch, document, driver, *, observations=None, client=None):
    """Keep model selection and evidence checks separate from explicit session-position fixtures."""
    from graph import criteria

    closed, carried = [], []
    monkeypatch.setenv("AGV_MSF_RPC", "")
    document = rehydrate.ensure_view(document)
    verdicts = {fact["ref"]: "TRUE" for node in graph_nodes(document)
                for fact in criteria.to_produce(document, node["id"])}
    verdicts.update(observations or {})
    client = client if client is not None else InventoryPlanner()
    sources = sorted({(host, privilege) for node in graph_nodes(document)
                      for host, privilege, _ in positions_mod.exec_preconditions(document, node["id"])})
    positions = [
        {"channel_id": "fixture-position-%d" % index,
         "kind": "console_session", "session_id": str(index),
         "session_type": "shell", "platform": "linux",
         "logical": host, "host": host, "privilege": privilege,
         "endpoint": {"host": "127.0.0.1", "port": 55553, "ssl": False},
         "capacity": {"max_bytes": 4096, "source": "offline fixture declaration"},
         "shell_ready": True, "lifecycle": "registered",
         "observation": {"state": "alive", "reason": "offline fixture observation"}}
        for index, (host, privilege) in enumerate(sources, 1)
    ]
    probed = set()

    from types import SimpleNamespace

    class Executor:
        def __init__(self, *args, **kwargs):
            pass

        def __call__(self, *args, **kwargs):
            pytest.fail("an offline walk must not execute a remote command")

        def close(self):
            closed.append(True)

    def snapshot(root):
        return [dict(deepcopy(row), registry_root=str(root)) for row in positions]

    def probe(row, executor):
        assert isinstance(executor, Executor)
        expected = next(item for item in positions if item["channel_id"] == row["channel_id"])
        assert all(row[key] == value for key, value in expected.items())
        probed.add(row["channel_id"])
        return True, "OFFLINE_SESSION_PROBE_CONFIRMED"

    def drive(card, task, scope, executor, **kwargs):
        required = positions_mod.exec_preconditions(document, task["node_id"])
        if required:
            position = kwargs["channel"]
            assert position["channel_id"] in probed
            assert position["logical"] in {host for host, _privilege, _producers in required}
        return driver(card, task, scope, executor, **kwargs)

    def card_for(node, _faces, **kwargs):
        inputs = {"target_host": {"from": "graph"}}
        if str(node["id"]) == CONSUMER_ID:
            inputs["credential_ref"] = {"from": "graph"}
        return {"id": "card-" + str(node["id"]), "inputs": inputs, "delivers": []}, "", {}

    def carry_handles(old, new, *, executor):
        carried.append((old, new, executor))
        return [], [], []

    def verify_fixture(*, document, node_id, host_map=None, **kwargs):
        return checked_observations(document, node_id, verdicts, host_map=host_map)

    monkeypatch.setattr(rehydrate, "load_file", lambda path: deepcopy(document))
    monkeypatch.setattr(bind, "faces", lambda root: [])
    monkeypatch.setattr(bind, "bind", card_for)
    monkeypatch.setattr(run_plan, "SshExecutor", Executor)
    monkeypatch.setattr(model_mod, "client_from_env", lambda **kwargs: client)
    monkeypatch.setattr(run_lean_task, "drive", drive)
    monkeypatch.setattr(session_registry, 'snapshot', snapshot)
    monkeypatch.setattr(sessions, 'probe', probe)
    monkeypatch.setattr(sessions, 'carry_handles', carry_handles)
    stub_callers(monkeypatch, "verify_node", verify_fixture, callers=(service,))
    return closed, carried


def plan_args(run_root, source=None, carry=None):
    """(helper below is used by many tests; the two tests above it guard the walk contract)"""
    args = ["--graph", "unused.json", "--run-root", str(run_root),
            "--remote", "attacker@198.51.100.19", "--model", "offline"]
    if source:
        args.extend(["--credentials", str(source)])
    if carry:
        args.extend(["--carry-from", str(carry)])
    return args


def proved_result(reason="checked"):
    return {"status": "model_reported", "claimed_verdict": "pass",
            "citations": [{"call_id": FIXTURE_CALL_ID}], "reason": reason}


class StubPlanner:
    """Return scripted answers and preserve the messages containing program refusals."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.seen = []

    def available(self):
        return True

    def complete(self, *, task, system, user, timeout=60.0, retries=2):
        assert task == "pick_next_node"
        self.seen.append(user)
        answer = self.answers.pop(0) if self.answers else {
            "decision": "done", "next_node_id": None, "change_note": "Fixture stopped."}
        return model_mod.ModelReply(ok=True, payload=answer, text=json.dumps(answer))


def _reachability_row():
    return {"ref": "39", "type": "LEAF", "fact": "hacl(pc1,dc,tcp,445)",
            "signature": "hacl/4", "produced_by": [],
            "validation_kind": "network_reachability",
            "validation_fields": {"from": {"term": "pc1"}, "to": {"term": "dc"},
                                  "protocol": "tcp", "port": "445"}}


def _reachability_receipts(root, *, port_state="open", address="192.168.93.30",
                           read_stop="end_marker", xml=None):
    from tests.test_run_plan_evidence_contract import receipt_fixture

    receipt_fixture(root, state=port_state, read_stop=read_stop,
                    address="192.168.93.30", output_address=address,
                    output_port="445", port="445", vantage="position-pc1",
                    call_id=FIXTURE_CALL_ID, xml=xml)
    return evidence._registered_receipts(root)


def delivery_fixture(tmp_path, monkeypatch):
    """Provide explicit harmless delivery actions and record the shared dispatch boundary."""
    from types import SimpleNamespace
    from runtime.runner import ExecOutcome
    monkeypatch.setattr(session_registry, "_resource_root", lambda root: tmp_path / "resources")
    calls = []
    def invoke(request, **kwargs):
        calls.append(request["cmd"])
        plans = list((tmp_path / "delivery").glob("*/plan.json"))
        assert len(plans) == 1
        stored = json.loads(plans[0].read_text(encoding="utf-8"))
        assert stored["state"] in ("preparing", "cleaning")
        marker = kwargs["marker"]
        return ExecOutcome(0, stdout=marker + "start\nobserved\n" + marker + "end 0\n")
    monkeypatch.setattr(dispatch, "invoke", invoke, raising=False)
    def rpc(*args, **kwargs):
        def call(method, *params, **options):
            assert method == "session.list"
            return {}
        call.endpoint = SimpleNamespace(host="127.0.0.1", port=55553, ssl=False)
        return call
    monkeypatch.setattr(session_io, "rpc_call", rpc)
    step = {"request": {"tool": "cmd", "cmd": "echo prepare"}, "platform": "linux",
            "binding": None, "timeout": 2.0}
    declaration = {
        "prepare": [step],
        "cleanup": [dict(step, request={"tool": "cmd", "cmd": "echo cleanup"})],
        "resources": [{"host": "192.0.2.1", "port": 12345, "protocol": "tcp"}],
        "expected": {"session_host": "192.0.2.7", "type": "shell", "exploit_uuid": "fixture-attempt"},
        "capabilities": {"capacity": {"max_bytes": 4096, "source": "fixture measurement"},
                         "shell_ready": True},
        "command": "echo delivery"}
    arguments = {"executor": None,
                 "rpc_conf": {"rpc_password": "fixture-rpc-secret"}, "root": tmp_path,
                 "node": "fixture", "target_host": "192.0.2.7", "declaration": declaration}
    return arguments, calls
