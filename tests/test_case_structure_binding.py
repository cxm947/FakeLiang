from pathlib import Path
import sys

import pytest

_SRC = str(Path(__file__).resolve().parents[1] / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from graph import cases, rule_catalog
from graph.parser import Graph, Node
from graph.rule_catalog import RuleCase
from graph.terms import atom_value, is_variable, parse_fact


def make_graph(head, premises, *, description="RULE 99 (fixture display text)",
               identities=None):
    if identities is None:
        identities = [
            "1", "2",
            *[str(index + 3) for index in range(len(premises))],
        ]
    assert len(identities) == len(premises) + 2
    assert len(set(identities)) == len(identities)
    head_id, action_id, *refs = identities

    nodes = {
        head_id: Node(head_id, head, "OR", "0"),
        action_id: Node(action_id, description, "AND", "0"),
    }
    for ref, fact in zip(refs, premises):
        nodes[ref] = Node(ref, fact, "LEAF", "0")

    weights = {(ref, action_id): "1" for ref in refs}
    weights[action_id, head_id] = "1"
    return Graph(nodes, weights), action_id, refs


def install_cases(monkeypatch, *items):
    monkeypatch.setattr(cases, "CASES", items)
    monkeypatch.setattr(cases, "PATTERNS", {
        item.id: (
            parse_fact(item.head),
            tuple(parse_fact(fact) for fact in item.body),
        )
        for item in items
    })


def symmetric_case(*, different=(("A", "B"),)):
    return RuleCase(
        "symmetric_fixture",
        "unused display text",
        "outcome(H)",
        ("pair(H,A)", "pair(H,B)"),
        different,
    )


def ground(template):
    fact = parse_fact(template)
    arguments = []
    for term in fact.args:
        if term == "_":
            arguments.append("fixture_wildcard")
        elif is_variable(term):
            arguments.append({
                "Port": "445",
                "Protocol": "tcp",
            }.get(term, "bound_" + term.lower()))
        else:
            arguments.append(term)
    return fact.name + "(" + ",".join(arguments) + ")"


@pytest.mark.parametrize("item", rule_catalog.CASES, ids=lambda item: item.id)
def test_every_catalog_template_matches_its_ground_structure(item):
    graph, action, refs = make_graph(
        ground(item.head),
        [ground(fact) for fact in item.body],
        description="RULE 999 (unrelated display description)",
    )
    selected = cases.select_case(graph, action)

    assert selected["status"] == "matched", selected
    assert selected["case_id"] == item.id
    assert selected["premise_refs"] == refs
    assert selected["candidates"] == [{
        "case_id": item.id,
        "bindings": selected["bindings"],
        "premise_refs": refs,
    }]

    fields, details = cases.extract_fields(graph, action, selected)
    assert fields["target_host"] is not None
    assert details["bindings"] == selected["bindings"]
    assert details["premise_refs"] == refs


def test_description_index_and_host_name_exceptions_are_removed():
    assert not hasattr(rule_catalog, "BY_DESCRIPTION")
    assert not hasattr(cases, "BY_DESCRIPTION")
    for item in rule_catalog.CASES:
        assert all(
            "pc_1" not in pair
            for pair in item.different
        )


@pytest.mark.parametrize("description", [
    "RULE 1 (Direct Network Access)",
    "RULE 787 (Valid Accounts - T1078)",
    "RULE 92 (  renamed    display text  )",
])
def test_description_does_not_select_the_rule(description):
    graph, action, refs = make_graph(
        "netAccess(target,tcp,443)",
        ["attackerLocated(origin)", "hacl(origin,target,tcp,443)"],
        description=description,
    )
    selected = cases.select_case(graph, action)

    assert selected["status"] == "matched"
    assert selected["case_id"] == "direct_network_access"
    assert atom_value(selected["bindings"]["Zone"]) == "origin"
    assert atom_value(selected["bindings"]["H"]) == "target"
    assert selected["premise_refs"] == refs


def test_matching_signatures_do_not_hide_inconsistent_variables():
    graph, action, _ = make_graph(
        "netAccess(target,tcp,443)",
        ["attackerLocated(origin)", "hacl(other,target,tcp,443)"],
    )
    selected = cases.select_case(graph, action)
    assert selected["status"] == "unknown"
    assert selected["reason"] == "signature_value_or_binding_mismatch"

    fields, details = cases.extract_fields(graph, action, selected)
    assert all(value is None for value in fields.values())
    assert len(details["premises"]) == 2
    assert len(details["outputs"]) == 1


@pytest.mark.parametrize("credentialed", [False, True])
@pytest.mark.parametrize(("source", "target", "identities"), [
    (
        "jump", "pc_1",
        ["1", "2", "71", "13", "88", "5", "62", "40", "95"],
    ),
    (
        "renamed_jump", "renamed_target",
        ["90", "60", "41", "77", "22", "53", "11", "85", "33"],
    ),
])
def test_admin_roles_survive_host_and_id_changes(
        credentialed, source, target, identities):
    service = "remote_agent" if credentialed else "winrm"
    premises = [
        f"networkServiceInfo({target},{service},tcp,5985,system)",
        f"hacl({source},{target},tcp,5985)",
        f"execCode({source},admin)",
        f"isFirewall({target},flase)",
        "getAccount(vault,alice,material,admin)",
        f"hasAccount({target},alice,material,admin)",
    ]
    if credentialed:
        premises.insert(
            0,
            f"ttpExists({target},{service},remoteClient,"
            "windowsCredentialRemoteExecution,lateralMovement)",
        )

    graph, action, refs = make_graph(
        f"execCode({target},admin)",
        premises,
        description="RULE 999 (  arbitrary    display text  )",
        identities=identities[:len(premises) + 2],
    )
    expected = (
        "windows_credential_remote_admin_firewall_state"
        if credentialed else "winrm_admin_firewall_state"
    )
    selected = cases.select_case(graph, action)

    assert selected["status"] == "matched", selected
    assert selected["case_id"] == expected
    assert atom_value(selected["bindings"]["HOSTS"]) == source
    assert atom_value(selected["bindings"]["HOSTD"]) == target
    assert selected["premise_refs"] == refs

    fields, details = cases.extract_fields(graph, action, selected)
    assert fields["source_host"] == source
    assert fields["target_host"] == target
    assert fields["service"] == service
    assert details["firewall_state"] == "flase"
    assert details["bindings"] == selected["bindings"]
    assert details["premise_refs"] == refs


@pytest.mark.parametrize(("port", "status"), [
    ("445", "matched"),
    ("2049", "unknown"),
    ("873", "unknown"),
])
def test_real_port_constraints_are_preserved(port, status):
    graph, action, _ = make_graph(
        "execCode(target,admin)",
        [
            "execCode(origin,user)",
            "weakAccount(target,alice,material,admin)",
            f"hacl(origin,target,tcp,{port})",
        ],
    )
    selected = cases.select_case(graph, action)
    assert selected["status"] == status
    if status == "matched":
        assert selected["case_id"] == "weak_account_lateral"


@pytest.mark.parametrize("identities", [
    ["91", "37", "83", "12"],
    ["500", "600", "4", "900"],
])
def test_same_case_retains_every_binding_and_its_refs(monkeypatch, identities):
    install_cases(monkeypatch, symmetric_case())
    graph, action, refs = make_graph(
        "outcome(target)",
        ["pair(target,alpha)", "pair(target,beta)"],
        identities=identities,
    )
    selected = cases.select_case(graph, action)

    assert selected["status"] == "ambiguous"
    assert selected["case_id"] is None
    assert selected["bindings"] == {}
    assert selected["premise_refs"] == []
    actual = {
        (
            row["case_id"],
            atom_value(row["bindings"]["H"]),
            atom_value(row["bindings"]["A"]),
            atom_value(row["bindings"]["B"]),
            tuple(row["premise_refs"]),
        )
        for row in selected["candidates"]
    }
    assert actual == {
        ("symmetric_fixture", "target", "alpha", "beta", tuple(refs)),
        ("symmetric_fixture", "target", "beta", "alpha", tuple(reversed(refs))),
    }

    fields, details = cases.extract_fields(graph, action, selected)
    assert all(value is None for value in fields.values())
    assert details["case_status"] == "ambiguous"
    assert details["case_candidates"] == selected["candidates"]
    assert len(details["premises"]) == 2


def test_same_values_do_not_erase_different_premise_assignments(monkeypatch):
    install_cases(monkeypatch, symmetric_case(different=()))
    graph, action, refs = make_graph(
        "outcome(target)",
        ["pair(target,alpha)", "pair(target,alpha)"],
    )
    selected = cases.select_case(graph, action)

    assert selected["status"] == "ambiguous"
    assert len(selected["candidates"]) == 2
    assert {
        tuple(row["premise_refs"])
        for row in selected["candidates"]
    } == {tuple(refs), tuple(reversed(refs))}


def test_true_variable_inequality_is_preserved(monkeypatch):
    install_cases(monkeypatch, symmetric_case())
    graph, action, _ = make_graph(
        "outcome(target)",
        ["pair(target,alpha)", "pair(target,alpha)"],
    )
    selected = cases.select_case(graph, action)
    assert selected["status"] == "unknown"
    assert selected["candidates"] == []


def test_different_cases_are_not_resolved_by_catalog_order(monkeypatch):
    first = RuleCase(
        "first_fixture", "display one",
        "outcome(H)", ("pair(H,A)",),
    )
    second = RuleCase(
        "second_fixture", "display two",
        "outcome(H)", ("pair(H,A)",),
    )
    install_cases(monkeypatch, first, second)
    graph, action, refs = make_graph(
        "outcome(target)", ["pair(target,alpha)"],
    )
    selected = cases.select_case(graph, action)

    assert selected["status"] == "ambiguous"
    assert selected["case_id"] is None
    assert {row["case_id"] for row in selected["candidates"]} == {
        first.id, second.id,
    }
    assert all(
        row["premise_refs"] == refs
        for row in selected["candidates"]
    )


@pytest.mark.parametrize(("explicit", "status", "reason"), [
    ("dif(origin,target)", "matched", None),
    ("dif(origin,origin)", "unknown", "false_explicit_dif"),
])
def test_explicit_dif_is_checked_before_matching(explicit, status, reason):
    graph, action, refs = make_graph(
        "netAccess(target,tcp,443)",
        [
            "attackerLocated(origin)",
            "hacl(origin,target,tcp,443)",
            explicit,
        ],
    )
    selected = cases.select_case(graph, action)

    assert selected["status"] == status
    assert selected["reason"] == reason
    if status == "matched":
        assert selected["premise_refs"] == refs[:2]
        _, details = cases.extract_fields(graph, action, selected)
        assert len(details["premises"]) == 3


def test_budget_exhaustion_cannot_turn_a_partial_search_into_a_match(monkeypatch):
    item = symmetric_case()
    install_cases(monkeypatch, item)
    graph, action, refs = make_graph(
        "outcome(target)",
        ["pair(target,alpha)", "pair(target,beta)"],
    )
    matcher = cases._match_case
    solutions, exhausted = matcher(
        item,
        graph.facts["1"],
        [(ref, graph.facts[ref]) for ref in refs],
        budget=4,
    )
    assert exhausted is True
    assert len(solutions) == 1

    def limited(case, head, facts):
        return matcher(case, head, facts, budget=4)

    monkeypatch.setattr(cases, "_match_case", limited)
    selected = cases.select_case(graph, action)
    assert selected["status"] == "unknown"
    assert selected["case_id"] is None
    assert selected["bindings"] == {}
    assert selected["premise_refs"] == []
    assert selected["reason"] == "match_budget_exceeded"
    assert len(selected["candidates"]) == 1


def test_field_extraction_does_not_take_the_first_exec_fact(monkeypatch):
    item = RuleCase(
        "two_exec_fixture",
        "unused display text",
        "outcome(H)",
        ("execCode(H,admin)", "execCode(S,user)"),
    )
    install_cases(monkeypatch, item)
    graph, action, _ = make_graph(
        "outcome(target)",
        ["execCode(target,admin)", "execCode(source,user)"],
        identities=["90", "80", "70", "3"],
    )
    selected = cases.select_case(graph, action)
    assert selected["status"] == "matched"
    with pytest.raises(ValueError, match="CASE_FIELD_AMBIGUOUS: execCode/2"):
        cases.extract_fields(graph, action, selected)