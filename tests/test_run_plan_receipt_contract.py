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
from tests.test_run_plan_evidence_contract import ROOT
for directory in (ROOT / "src", ROOT / "scripts"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import run_plan
from tests.support import stub_callers
from agents.planner import service as planning_mod
from graph import criteria, rehydrate
from graph.parser import read_text
from graph.projector import project

from tests.test_run_plan_evidence_contract import (
    document, receipt_fixture,
)


@pytest.mark.parametrize(("read_stop", "returncode", "command_rc", "status"), [
    (None, 0, None, "completed_transport"),
    ("deadline", 0, 0, "executed"),
    ("prompt", 0, 0, "executed"),
    ("end_marker", 1, 0, "executed"),
    ("end_marker", 0, 1, "completed_transport"),
])
def test_incomplete_or_failed_receipts_are_not_credited(
        tmp_path, read_stop, returncode, command_rc, status):
    receipt_fixture(tmp_path, read_stop=read_stop, returncode=returncode,
                    command_rc=command_rc, status=status)
    calls, issues = evidence._registered_receipts(tmp_path)
    assert calls == []
    assert issues


def test_artifact_tampering_removes_credit(tmp_path):
    _, _, directory = receipt_fixture(tmp_path)
    (directory / "stdout.txt").write_text("different output", encoding="utf-8")
    calls, issues = evidence._registered_receipts(tmp_path)
    assert calls == []
    assert issues


def test_duplicate_receipt_removes_credit(tmp_path):
    _, receipt, _ = receipt_fixture(tmp_path)
    with (tmp_path / "events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(receipt) + "\n")
    calls, issues = evidence._registered_receipts(tmp_path)
    assert calls == []
    assert any("RECEIPT_PAIR_NOT_UNIQUE" in issue for issue in issues)


@pytest.mark.parametrize(("port_state", "output_address", "output_port", "expected"), [
    ("open", "192.0.2.20", "443", "TRUE"),
    ("closed", "192.0.2.20", "443", "UNKNOWN"),
    ("filtered", "192.0.2.20", "443", "UNKNOWN"),
    ("open", "192.0.2.21", "443", "UNKNOWN"),
    ("open", "192.0.2.20", "444", "UNKNOWN"),
])
def test_tcp_checker_matches_exact_target_and_port(
        document, tmp_path, port_state, output_address, output_port, expected):
    receipt_fixture(tmp_path, state=port_state, output_address=output_address,
                    output_port=output_port)
    calls, issues = evidence._registered_receipts(tmp_path)
    assert not issues
    result = backstops.backstop_reachability(
        row=criteria.fact_row(document, "4"), receipts=calls,
        host_map={"target": "192.0.2.20"}, source_bindings={"position-A": "origin"})
    assert result["verdict"] == expected


def test_vantage_name_is_not_a_source_binding(document, tmp_path):
    receipt_fixture(tmp_path)
    calls, _ = evidence._registered_receipts(tmp_path)
    result = backstops.backstop_reachability(
        row=criteria.fact_row(document, "4"), receipts=calls,
        host_map={"target": "192.0.2.20"})
    assert result["verdict"] == "UNKNOWN"
    assert result["reason"] == "SOURCE_BINDING_UNAVAILABLE"


@pytest.mark.parametrize("read_stop", [None, "end_marker"])
def test_real_runner_receipt_and_frame_are_credited(tmp_path, read_stop):
    """A transport receipt needs a real successful frame, including non-console reads."""
    receipt_fixture(tmp_path, read_stop=read_stop)
    calls, issues = evidence._registered_receipts(tmp_path)
    assert len(calls) == 1 and not issues
    assert calls[0]["stdout"].startswith("offline-markerstart\n")
    assert calls[0]["output"].startswith("<nmaprun>")


@pytest.mark.parametrize("stdout", [
    '<nmaprun/>',
    'offline-markerend 0\noffline-markerstart\n',
    'offline-markerstart\n<nmaprun/>\noffline-markerend 0',
    'offline-markerstart\n<nmaprun/>\noffline-markerend 9\n',
    'offline-markerstart\noffline-markerstart\n<nmaprun/>\noffline-markerend 0\n',
])
def test_receipt_label_does_not_replace_frame_evidence(tmp_path, stdout):
    receipt_fixture(tmp_path, stdout=stdout)
    calls, issues = evidence._registered_receipts(tmp_path)
    assert calls == [] and issues


@pytest.mark.parametrize("option", ["request_mismatch", "digest_mismatch"])
def test_registered_request_must_match_actual_command(tmp_path, option):
    receipt_fixture(tmp_path, **{option: True})
    calls, issues = evidence._registered_receipts(tmp_path)
    assert calls == [] and issues


def test_runtime_source_binding_uses_deployment_identity_not_aliases(document):
    scope = {"vantage": "base"}
    assert service._verification_sources(
        document, "2", scope, host_map={"origin": "192.0.2.10"},
        position_host="192.0.2.11") == {}
    assert service._verification_sources(
        document, "2", scope, host_map={"origin": "192.0.2.10"},
        position_host="192.0.2.10") == {"base": "origin"}
    assert service._verification_sources(
        document, "2", scope, host_map={"origin": "192.0.2.10"},
        position_host="192.0.2.10", proxy=["bound-proxy"]) == {}
