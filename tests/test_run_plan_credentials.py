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
from tests.test_run_plan_support import ROOT
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import run_plan                                              # noqa: E402
import run_lean_task                                         # noqa: E402
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

from tests.test_run_plan_support import (
    ACCOUNT_FACT_ID, CONSUMER_ID, FIXTURE_CALL_ID, PRODUCER_ID, credential_graph, plan_args,
    plan_harness, private_source, proved_result,
)


@pytest.mark.parametrize(("source_host", "target_host", "account"), [
    ("vault", "worker", "attacker_role"),
    ("archive_b", "edge_b", "service_role_b"),
])
def test_plan_records_proved_account_and_supplies_private_material(
        tmp_path, monkeypatch, source_host, target_host, account):
    """Account registration and private delivery still work with model choices and a probed session binding."""
    source, material = private_source(tmp_path, account)
    run_root = tmp_path / "run"
    document = credential_graph(source_host, target_host, account)
    dispatched = []

    def driver(card, task, scope, executor, **kwargs):
        dispatched.append(task["node_id"])
        assert material["secret"] in kwargs["secrets"]
        if task["node_id"] == CONSUMER_ID:
            assert task["inputs"]["credential_ref"] == material
        return proved_result("checked " + material["secret"])

    closed, _ = plan_harness(monkeypatch, document, driver)
    assert run_plan.main(plan_args(run_root, source)) == 0
    assert dispatched == [PRODUCER_ID, CONSUMER_ID]
    assert closed == [True]
    rows = credentials.read(run_root)
    assert len(rows) == 1  # OR and consumer produced_by refer to the same account.
    summary = json.loads((run_root / "plan_result.json").read_text(encoding="utf-8"))
    assert summary["nodes"][PRODUCER_ID]["credential"] == [rows[0]["credential_id"]]
    for path in run_root.rglob("*"):
        if path.is_file():
            assert material["secret"] not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("outcome", [
    {"status": "uncertain", "claimed_verdict": "pass", "citations": [{"call_id": "x"}]},
    dict(proved_result(), claimed_verdict="unsatisfied"),
    dict(proved_result(), rejections=["invalid citation"]),
    dict(proved_result(), pending_calls=["unresolved"]),
])
def test_plan_never_registers_unproved_accounts(tmp_path, monkeypatch, outcome):
    """Unproved reports still register no material and unknown outputs still block consumers with a usable session."""
    source, _ = private_source(tmp_path)
    run_root = tmp_path / "run"
    dispatched = []

    def driver(card, task, scope, executor, **kwargs):
        dispatched.append(task["node_id"])
        return outcome

    plan_harness(monkeypatch, credential_graph(), driver,
                 observations={ACCOUNT_FACT_ID: "UNKNOWN"})
    run_plan.main(plan_args(run_root, source))
    assert dispatched == [PRODUCER_ID]
    assert credentials.read(run_root) == []
    summary = json.loads((run_root / "plan_result.json").read_text(encoding="utf-8"))
    assert summary["nodes"][CONSUMER_ID]["status"] == "blocked_upstream"

    dispatched.clear()
    checked_root = tmp_path / "checked-output"
    plan_harness(monkeypatch, credential_graph(producer_only=True), driver)
    run_plan.main(plan_args(checked_root, source))
    checked = json.loads((checked_root / "plan_result.json").read_text(encoding="utf-8"))
    assert dispatched == [PRODUCER_ID]
    assert checked["nodes"][PRODUCER_ID]["status"] == "stopped"
    assert checked["nodes"][PRODUCER_ID]["verification"]["assessments"][
        ACCOUNT_FACT_ID]["verdict"] == "TRUE"
    assert checked["proved"] == []
    assert credentials.read(checked_root) == []


def test_a_hedging_report_does_not_block_a_machine_proven_output(tmp_path, monkeypatch):
    """"No verdict" is not a verdict against the step: the checker is the backstop.

    walk-139 node 7: the include chain ran, the session was handed over, the checker established
    execCode(pc1,system) -- and the step still stopped because the model itself had written
    claimed_verdict=uncertain. A report that *decides* the other way still wins (see the
    parametrised case above), and a refused verification turn is never overruled.
    """
    source, _ = private_source(tmp_path)
    dispatched = []

    def driver(card, task, scope, executor, **kwargs):
        dispatched.append(task["node_id"])
        return {"status": "model_reported", "claimed_verdict": "uncertain", "citations": [],
                "reason": "MODEL_CLAIM_NOT_MACHINE_VERIFIED"}

    plan_harness(monkeypatch, credential_graph(producer_only=True), driver)
    root = tmp_path / "hedged"
    assert run_plan.main(plan_args(root, source)) == 0
    summary = json.loads((root / "plan_result.json").read_text(encoding="utf-8"))
    assert dispatched == [PRODUCER_ID]
    assert summary["nodes"][PRODUCER_ID]["status"] == "proved"


def test_plan_names_missing_source_and_blocks_credential_consumer(tmp_path, monkeypatch):
    """Missing private material still blocks its consumer even when the checked fact and session are available."""
    dispatched = []

    def driver(card, task, scope, executor, **kwargs):
        dispatched.append(task["node_id"])
        return proved_result()

    plan_harness(monkeypatch, credential_graph(), driver)
    run_root = tmp_path / "run"
    assert run_plan.main(plan_args(run_root)) == 2
    assert dispatched == [PRODUCER_ID]
    summary = json.loads((run_root / "plan_result.json").read_text(encoding="utf-8"))
    assert summary["nodes"][PRODUCER_ID]["status"] == "proved"
    assert summary["nodes"][PRODUCER_ID]["credential_error"].startswith("CREDENTIAL_")
    assert summary["nodes"][CONSUMER_ID]["reason"].startswith("CREDENTIAL_")
    assert credentials.read(run_root) == []


def test_plan_carries_credentials_and_existing_handles_independently(tmp_path, monkeypatch):
    """Credential inheritance and handle carrying remain independent with an explicit usable source session."""
    source_path, material = private_source(tmp_path)
    old, new = tmp_path / "old", tmp_path / "new"
    source = credentials.load_source(source_path, run_dirs=[old, new], repository=ROOT)
    rows = credentials.record_proved(
        old, document=credential_graph(), node_id=PRODUCER_ID, proved=True, source=source,
        source_call=FIXTURE_CALL_ID)
    document = credential_graph(carried=True)
    dispatched = []

    def driver(card, task, scope, executor, **kwargs):
        dispatched.append(task["node_id"])
        assert task["inputs"]["credential_ref"] == material
        assert material["secret"] in kwargs["secrets"]
        return proved_result()

    closed, carried = plan_harness(monkeypatch, document, driver)
    assert run_plan.main(plan_args(new, carry=old)) == 0
    assert dispatched == [CONSUMER_ID]
    assert closed == [True]
    assert [(a, b) for a, b, _ in carried] == [(old, new)]
    carried_rows = credentials.read(new)
    assert len(carried_rows) == 1
    assert carried_rows[0]["parent"] == rows[0]["credential_id"]
    assert carried_rows[0]["source_path"] == rows[0]["source_path"]
    assert material["secret"] not in (new / "harvest.jsonl").read_text(encoding="utf-8")

def test_plan_masks_driver_exception_in_summary_and_console(tmp_path, monkeypatch, capsys):
    """Driver exceptions still reach masked records and console after the session-position checks pass."""
    source, material = private_source(tmp_path)
    run_root = tmp_path / "run"

    def driver(*args, **kwargs):
        raise RuntimeError("transport failed: " + material["secret"])

    plan_harness(monkeypatch, credential_graph(), driver)
    assert run_plan.main(plan_args(run_root, source)) == 2
    text = (run_root / "plan_result.json").read_text(encoding="utf-8")
    assert material["secret"] not in text + capsys.readouterr().out
    assert "transport failed:" in text


def test_plan_requests_internal_verdict_before_summary_mask(tmp_path, monkeypatch):
    """Private verdicts still precede redaction, with session setup no longer blocking the driver."""
    source, material = private_source(tmp_path)
    material["secret"] = "".join(map(chr, (112, 97, 115, 115)))
    source.write_text(json.dumps({"credentials": {"attacker_role": material}}), encoding="utf-8")
    run_root = tmp_path / "run"

    def driver(card, task, scope, executor, **kwargs):
        assert kwargs["private_result"] is True
        if task["node_id"] == CONSUMER_ID:
            assert task["inputs"]["credential_ref"] == material
        return proved_result()

    plan_harness(monkeypatch, credential_graph(), driver)
    assert run_plan.main(plan_args(run_root, source)) == 0
    summary = json.loads((run_root / "plan_result.json").read_text(encoding="utf-8"))
    assert summary["proved"] == sorted([PRODUCER_ID, CONSUMER_ID])
    assert summary["nodes"][PRODUCER_ID]["claimed_verdict"] == "<redacted>"
    assert len(credentials.read(run_root)) == 1


@pytest.mark.parametrize("derived,external,expected", [
    (True, True, ["derived", "external"]),
    (True, False, ["derived"]),
    (False, True, ["external"]),
])
def test_plan_supplies_ordered_material_candidates_before_dispatch(
        tmp_path, monkeypatch, derived, external, expected):
    """Material candidates retain their order and privacy after model selection and session binding."""
    source_path, external_material = private_source(tmp_path)
    derived_value = "".join(map(chr, (126, 33)))
    material = {"realm": "example.invalid", "user": "actual_attacker",
                "value": derived_value, "kind": "password",
                "source_call": "call-20261005T010203-abcdef-test",
                "quote": "example.invalid\\actual_attacker password: " + derived_value}
    run_root = tmp_path / "run"
    dispatched = []

    def driver(card, task, scope, executor, **kwargs):
        dispatched.append(task["node_id"])
        if task["node_id"] == PRODUCER_ID:
            result = proved_result()
            if derived:
                result["materials"] = [material]
                result["reason"] = "observed " + derived_value
            return result
        candidates = task["inputs"]["credential_candidates"]
        assert [candidate["origin"] for candidate in candidates] == expected
        # Candidate order starts at one for the candidates actually supplied.
        assert [candidate["order"] for candidate in candidates] == list(range(1, len(expected) + 1))
        assert task["inputs"]["credential_ref"] == candidates[0]["credential_ref"]
        if derived:
            assert candidates[0]["credential_ref"]["secret"] == derived_value
            assert derived_value in kwargs["secrets"]
        if external:
            assert candidates[-1]["credential_ref"] == external_material
        return proved_result()

    closed, _ = plan_harness(monkeypatch, credential_graph(), driver)
    args = plan_args(run_root, source_path if external else None)
    args.extend(["--materials-dir", str(tmp_path / "private" / "derived")])
    assert run_plan.main(args) == 0
    assert dispatched == [PRODUCER_ID, CONSUMER_ID] and closed == [True]
    assert len(credentials.read(run_root)) == len(expected)
    for artifact in run_root.rglob("*"):
        if artifact.is_file():
            text = artifact.read_text(encoding="utf-8")
            assert derived_value not in text
            assert external_material["secret"] not in text


def test_plan_refuses_both_material_candidates_missing_before_dispatch(tmp_path, monkeypatch):
    """Missing material sources still prevent consumer dispatch after a valid source session is selected."""
    dispatched = []

    def driver(card, task, scope, executor, **kwargs):
        dispatched.append(task["node_id"])
        return proved_result()

    plan_harness(monkeypatch, credential_graph(), driver)
    run_root = tmp_path / "run"
    assert run_plan.main(plan_args(run_root)) == 2
    assert dispatched == [PRODUCER_ID]
    result = json.loads((run_root / "plan_result.json").read_text(encoding="utf-8"))
    assert result["nodes"][CONSUMER_ID]["reason"] == "CREDENTIAL_MISSING"


def test_plan_private_material_directory_cannot_be_a_run_root(tmp_path, monkeypatch, capsys):
    plan_harness(monkeypatch, credential_graph(),
                 lambda *_args, **_kwargs: pytest.fail("must refuse before dispatch"))
    run_root = tmp_path / "run"
    args = plan_args(run_root) + ["--materials-dir", str(run_root / "private")]
    assert run_plan.main(args) == 2
    assert "CREDENTIAL_SOURCE_NOT_PRIVATE" in capsys.readouterr().out
    assert not run_root.exists()


def test_the_walk_hands_the_declared_account_roles_to_the_verifier(tmp_path, monkeypatch):
    """The declared role bindings must reach `verify_node`, not be dropped on the way.

    walk-136 shipped this wiring with the initialiser *after* the loader, so every run handed
    the verifier an empty mapping and node 5 kept answering UNKNOWN with the credentials in hand.
    """
    source, _ = private_source(tmp_path)
    captured = []
    closed, _ = plan_harness(monkeypatch, credential_graph(),
                             lambda *args, **kwargs: proved_result())
    original = service.verify_node

    def capture(**kwargs):
        captured.append(kwargs.get("role_accounts"))
        return original(**kwargs)

    stub_callers(monkeypatch, "verify_node", capture, callers=(service,))
    assert run_plan.main(plan_args(tmp_path / "run", source)) == 0
    assert captured, "the walk never verified a node"
    assert all(rows == {"attacker_role": {"user": "actual_attacker",
                                          "domain": "example.invalid",
                                          #: 图上的账号事实同一条里也写着凭据符号，一并交给验证器。
                                          "symbols": ["account_material"]}}
               for rows in captured), captured
