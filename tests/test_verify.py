"""验证回合：判据从图上来、结论必须引用本次调用（D62）。"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from agents.verifier import runner as verify       # noqa: E402


def criteria():
    return [{"ref": "6", "type": "OR", "fact": "execCode(pc1,system)", "produced_by": ["7"],
             "validation_kind": "", "validation_fields": {}, "machine_checkable": False},
            {"ref": "39", "type": "LEAF", "fact": "hacl(pc1,dc,tcp,445)", "produced_by": [],
             "validation_kind": "network_reachability", "validation_fields": {"port": "445"},
             "machine_checkable": True}]


def test_the_task_carries_the_facts_the_criteria_and_what_is_already_in_hand():
    task = verify.verification_task(None, "44", harvest=[{"row_type": "session", "kind": "ssh",
                                                          "host": "10.0.0.5"}],
                                    calls=[{"call_id": "call-1", "request": {"tool": "shell"}}],
                                    graph_criteria=criteria(),
                                    must_produce=[{"ref": "43", "fact": "execCode(dc,system)"}])
    #: 本步要产出的事实排在清单最前（role=produce），消费的事实跟在后面（role=consume）——
    #: 只问消费的事实会漏掉"这一步到底成没成"（2026-10-06 烟测实测）。
    assert [row["ref"] for row in task["facts"]] == ["43", "6", "39"]
    assert [row["role"] for row in task["facts"]] == ["produce", "consume", "consume"]
    assert task["backstop"]["machine_checkable"] == ["39"]      # 这条将来由机器兜底
    assert task["harvest"][0]["kind"] == "ssh"
    assert task["calls"][0]["call_id"] == "call-1"
    assert [row["fact"] for row in task["must_produce"]] == ["execCode(dc,system)"]


def test_every_fact_needs_a_verdict_and_a_real_citation():
    """Removing the redundant envelope keeps citation and unknown-provenance checks."""
    payload = {"facts": [
        {"ref": "6", "verdict": "TRUE", "proof": "sufficient", "verifier": "model",
         "call_id": "call-1", "quote": "uid=0(root)"},
        {"ref": "39", "verdict": "UNKNOWN", "proof": "partial", "verifier": "model",
         "reason": "The supplied identity output does not observe this network fact.",
         "checked_calls": ["call-1"]}]}
    read = verify.read_verdict(payload, expected_refs=["6", "39"], credited_calls=["call-1"])
    assert [row["verdict"] for row in read["facts"]] == ["TRUE", "UNKNOWN"]
    assert [row["proof"] for row in read["facts"]] == ["sufficient", "partial"]


def test_a_verdict_must_say_what_its_evidence_proves_and_who_judged():
    """Proof scope and verifier remain mandatory; an unknown states its evidence gap."""
    base = {"ref": "6", "verdict": "TRUE", "call_id": "call-1", "quote": "x"}
    with pytest.raises(ValueError, match="^VERIFY_PROOF_UNKNOWN"):
        verify.read_verdict({"facts": [dict(base, verifier="model")]},
                            expected_refs=["6"], credited_calls=["call-1"])
    with pytest.raises(ValueError, match="^VERIFY_VERIFIER_UNKNOWN"):
        verify.read_verdict({"facts": [dict(base, proof="sufficient")]},
                            expected_refs=["6"], credited_calls=["call-1"])
    parsed = verify.read_verdict({"facts": [
        {"ref": "6", "verdict": "UNKNOWN", "proof": "partial", "verifier": "model",
         "reason": "No completed calls were supplied.", "checked_calls": []}]},
        expected_refs=["6"], credited_calls=[])
    assert parsed["facts"][0]["verdict"] == "UNKNOWN"


def test_a_verdict_that_cites_nothing_real_is_refused():
    payload = {"kind": "verified", "facts": [
        {"ref": "6", "verdict": "TRUE", "proof": "sufficient", "verifier": "model",
         "call_id": "call-invented", "quote": "x"},
        {"ref": "39", "verdict": "TRUE", "proof": "sufficient", "verifier": "model",
         "call_id": "call-1", "quote": "y"}]}
    with pytest.raises(ValueError, match="^VERIFY_CALL_UNCREDITED"):
        verify.read_verdict(payload, expected_refs=["6", "39"], credited_calls=["call-1"])
    # 漏掉一条事实也是拒绝：验证不能只报好看的那条
    with pytest.raises(ValueError, match="^VERIFY_REF_MISSING"):
        verify.read_verdict({"kind": "verified", "facts": [
            {"ref": "6", "verdict": "TRUE", "proof": "sufficient", "verifier": "model",
             "call_id": "call-1", "quote": "x"}]},
            expected_refs=["6", "39"], credited_calls=["call-1"])


def test_the_backstop_table_reuses_the_existing_probe_cards():
    """机器兜底不另起一套：判据种类映射到已有的前置卡；认不出的种类不硬判（交模型）。"""
    assert verify.backstop_for({"validation_kind": "network_reachability"}) == "pre.nmap_tcp_probe"
    assert verify.backstop_for({"validation_kind": "service_exposure"}) == "pre.service_version"
    assert verify.backstop_for({"validation_kind": "credential"}) == "pre.credential_valid"
    assert verify.backstop_for({"validation_kind": "environment_fact"}) == "pre.netsecurity_firewall_state"
    assert verify.backstop_for({"validation_kind": "capability"}) == "pre.tool_present"
    assert verify.backstop_for({"validation_kind": "something_new"}) == ""
    assert verify.backstop_for({}) == ""


@pytest.mark.parametrize("kind", [None, "verified"])
def test_kind_is_optional_but_facts_are_not(kind):
    payload = {"facts": [{"ref": "1", "verdict": "TRUE", "proof": "sufficient",
                          "verifier": "model", "call_id": "call-1", "quote": "open"}]}
    if kind is not None:
        payload["kind"] = kind
    assert verify.read_verdict(payload, expected_refs=["1"],
                               credited_calls=["call-1"])["facts"][0]["verdict"] == "TRUE"
    with pytest.raises(ValueError, match="VERIFY_SHAPE"):
        verify.read_verdict({}, expected_refs=["1"], credited_calls=[])


@pytest.mark.parametrize("change,code", [
    ({"reason": ""}, "VERIFY_UNKNOWN_REASON_MISSING"),
    ({"checked_calls": []}, "VERIFY_UNKNOWN_SOURCE_INVALID"),
    ({"checked_calls": ["invented"]}, "VERIFY_UNKNOWN_SOURCE_INVALID"),
    ({"checked_calls": ["call-1", "call-1"]}, "VERIFY_UNKNOWN_SOURCE_INVALID"),
    ({"verdict": "MAYBE"}, "VERIFY_VERDICT_UNKNOWN"),
])
def test_unknown_cannot_hide_missing_provenance(change, code):
    row = {"ref": "1", "verdict": "UNKNOWN", "proof": "partial", "verifier": "model",
           "reason": "This output does not cover the fact.", "checked_calls": ["call-1"]}
    with pytest.raises(ValueError, match=code):
        verify.read_verdict({"facts": [dict(row, **change)]},
                            expected_refs=["1"], credited_calls=["call-1"])


def test_duplicate_fact_is_refused():
    row = {"ref": "1", "verdict": "TRUE", "proof": "sufficient", "verifier": "model",
           "call_id": "call-1", "quote": "open"}
    with pytest.raises(ValueError, match="VERIFY_REF_DUPLICATE"):
        verify.read_verdict({"facts": [row, row]}, expected_refs=["1"],
                            credited_calls=["call-1"])


@pytest.mark.parametrize("role,address,vantage,node_id", [
    ("origin", "192.0.2.10", "position-A", "2"),
    ("gateway_b", "198.51.100.20", "position-B", "901"),
])
def test_identity_context_is_declaration_not_observation(role, address, vantage, node_id):
    """Explicit deployment identity survives renaming without becoming fact evidence."""
    host_map = {role: address}
    bindings = {vantage: role}
    task = verify.verification_task(
        None, node_id, host_map=host_map, source_bindings=bindings)
    assert task["identity_context"] == {
        "kind": "deployment_declaration",
        "role_addresses": {role: address},
        "vantage_roles": {vantage: role},
        "role_accounts": {},
    }
    assert task["facts"] == []
    assert task["calls"] == []
    assert "assessments" not in task
    task["identity_context"]["role_addresses"][role] = "changed"
    task["identity_context"]["vantage_roles"][vantage] = "changed"
    assert host_map == {role: address}
    assert bindings == {vantage: role}


def test_missing_identity_context_does_not_invent_base_aliases():
    """Missing deployment mappings remain missing rather than implying a source identity."""
    task = verify.verification_task(None, "2")
    assert task["identity_context"] == {
        "kind": "deployment_declaration", "role_addresses": {}, "vantage_roles": {},
        "role_accounts": {},
    }


def test_a_declared_account_role_travels_with_the_identity_context():
    """`domain_administrator` is only a name until the deployment says which account it is.

    walk-134 node 5: kiwi dumped WHOAMIANONY\\Administrator and the fact could not be connected
    to it -- the role binding existed in the deployment's own input and was never handed over.
    """
    roles = {"domain_administrator": {"user": "Administrator", "domain": "WHOAMIANONY"}}
    task = verify.verification_task(None, "5", role_accounts=roles)
    assert task["identity_context"]["role_accounts"] == roles


def test_an_unknown_row_may_say_its_citation_is_absent_with_a_null():
    """`null` for an UNKNOWN row means "no citation", not a malformed reply.

    walk-132 node 5: the verifier had no usable calls, answered UNKNOWN for every fact and wrote
    explicit nulls - and the whole verification turn was thrown away on a shape error.
    """
    parsed = verify.read_verdict(
        {"facts": [{"ref": "6", "verdict": "UNKNOWN", "proof": "partial", "verifier": "model",
                    "call_id": None, "quote": None, "reason": "nothing to read",
                    "checked_calls": []}]},
        expected_refs=["6"], credited_calls=[])
    assert parsed["facts"][0] == {"ref": "6", "verdict": "UNKNOWN", "proof": "partial",
                                  "verifier": "model", "call_id": "", "quote": "",
                                  "reason": "nothing to read", "checked_calls": []}


def test_the_harvest_carries_the_identity_the_run_observed_through_a_session():
    """A session row without its observed identity is a riddle: the step cannot tell whether the
    hand-over it declared came back as the identity its fact names (walk-152 node 44 answered
    "unsatisfied" while the runtime had registered the session as the system account)."""
    task = verify.verification_task(
        None, "44",
        harvest=[{"row_type": "session", "kind": "console_session", "host": "192.0.2.30",
                  "logical": "dc", "session_id": "3", "session_type": "meterpreter",
                  "identity": {"user": "NT AUTHORITY\\SYSTEM", "uid": "", "hostname": "DC",
                               "environment": "host", "call_id": "call-9"},
                  "observation": {"state": "alive", "at": 12.5}}])
    row = task["harvest"][0]
    assert row["observed_identity"] == {"user": "NT AUTHORITY\\SYSTEM", "uid": "",
                                        "hostname": "DC", "environment": "host"}
    assert row["identity_call_id"] == "call-9"
    assert row["observation_state"] == "alive"
    assert row["session_type"] == "meterpreter"
