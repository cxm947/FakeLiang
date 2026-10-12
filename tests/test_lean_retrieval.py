"""Card knowledge and JSON action permissions share one effective execution view."""
import hashlib
import json
import re
from pathlib import Path
import unittest

import pytest

from skills import lean

from skills import bind  # noqa: E402

from runtime.lean import mask_secrets  # noqa: E402

from runtime import dispatch  # noqa: E402

from graph import rehydrate  # noqa: E402

from tests.test_lean_cards import ROOT


def _retrieval_node(**changes):
    node = {"id": "7", "type": "AND", "attack_id": "T1059", "service": "shared",
            "source_host": "alpha", "target_host": "beta", "description": "display only",
            "semantics": {"case_id": "shared_case"}}
    node.update(changes)
    return node


def _retrieval_card(identity, *rules, technique=("T1059",), categories=("method",)):
    from skills import bind

    rules = [{"field": "service", "state": "preferred", "values": ["shared"]},
             {"field": "case", "state": "preferred", "values": ["shared_case"]}, *rules]
    row = {"id": identity, "path": "skills/" + identity, "technique": list(technique),
           "categories": list(categories), "allowed_tools": ["cmd", "finish"],
           "permission_source": "allowed_tools", "match": rules}
    for field in bind.TERMS:
        row[field] = [value for rule in rules if rule["field"] == field for value in rule["values"]]
    return {"id": identity, "tools": row["allowed_tools"], "body": "Offline fixture",
            "retrieval": bind._entry(row)}


def _retrieval_rule(field, state, *values):
    return {"field": field, "state": state, "values": list(values)}


@pytest.mark.parametrize("technique", [(), ("T1190",), ("T1059.001",)])
def test_retrieval_ttp_is_an_exact_hard_gate(technique):
    """Missing, different, and child TTP declarations cannot pass the requested exact TTP."""
    from skills import bind

    result = bind.retrieve(_retrieval_node(), [_retrieval_card("fixture.other", technique=technique)])
    assert result["state"] == "gap" and result["ranked"] == []
    assert result["rejected"][0]["reasons"][0]["field"] == "technique"


def test_retrieval_required_groups_each_need_one_declared_alternative():
    """Each required group must match; alternatives within a group remain alternatives."""
    from skills import bind

    card = _retrieval_card("fixture.required",
                          _retrieval_rule("aliases", "required", "alpha", "a"),
                          _retrieval_rule("keywords", "required", "remote"))
    missing = bind.retrieve(_retrieval_node(), [card], context={"aliases": ["a"]})
    assert missing["state"] == "gap"
    assert missing["rejected"][0]["reasons"] == [
        {"code": "CARD_REQUIRED_MISSING", "field": "keywords",
         "expected": ["remote"], "actual": []}]
    selected = bind.retrieve(_retrieval_node(), [card],
                             context={"aliases": ["a"], "keywords": ["remote"]})
    assert selected["selected_id"] == card["id"]


def test_retrieval_preferred_orders_without_excluding_and_unspecified_does_nothing():
    """Preferred aliases change ranking, while unspecified terms neither score nor filter."""
    from skills import bind

    cards = [_retrieval_card("fixture.a", _retrieval_rule("aliases", "preferred", "alpha")),
             _retrieval_card("fixture.b", _retrieval_rule("aliases", "preferred", "beta"),
                             _retrieval_rule("keywords", "unspecified", "extra"))]
    empty = bind.retrieve(_retrieval_node(), cards)
    assert empty["state"] == "choice_required"
    ranked = bind.retrieve(_retrieval_node(), cards,
                           context={"aliases": ["alpha"], "keywords": ["extra"]})
    assert ranked["selected_id"] == "fixture.a"
    assert len(ranked["ranked"]) == 2
    assert ranked["ranked"][0]["score"] == ranked["ranked"][1]["score"] + 1


@pytest.mark.parametrize("alias,expected", [("alpha", "fixture.a"), ("beta", "fixture.b")])
def test_retrieval_aliases_separate_cards_with_identical_ttp_service_and_case(alias, expected):
    """Only explicit alias evidence separates otherwise identical required-alias cards."""
    from skills import bind

    cards = [_retrieval_card("fixture.a", _retrieval_rule("aliases", "required", "alpha")),
             _retrieval_card("fixture.b", _retrieval_rule("aliases", "required", "beta"))]
    result = bind.retrieve(_retrieval_node(aliases=[alias]), cards)
    assert result["selected_id"] == expected and len(result["ranked"]) == 1
    assert bind.retrieve(_retrieval_node(), cards)["state"] == "gap"
    assert bind.retrieve(_retrieval_node(aliases=[alias + "-extra"]), cards)["state"] == "gap"


def test_retrieval_equal_alias_scores_keep_a_tie_and_do_not_count_synonyms_twice():
    """Equal alias support stays tied for the model, independent of card order or synonym count."""
    from skills import bind
    from types import SimpleNamespace

    cards = [_retrieval_card("fixture.a", _retrieval_rule("aliases", "preferred", "alpha", "a")),
             _retrieval_card("fixture.b", _retrieval_rule("aliases", "preferred", "beta"))]
    node = _retrieval_node(aliases=["alpha", "a", "beta"])
    report = bind.retrieve(node, cards)
    assert report["state"] == "choice_required"
    assert report["candidates"] == bind.retrieve(node, cards[::-1])["candidates"]
    assert len({row["score"] for row in report["candidates"]}) == 1
    calls = []

    class Client:
        def complete(self, **kwargs):
            calls.append(kwargs)
            payload = json.loads(kwargs["user"])
            assert all(row["reasons"] for row in payload["candidates"])
            assert {row["card_id"] for row in payload["candidates"]} == {"fixture.a", "fixture.b"}
            return SimpleNamespace(ok=True, payload={"card_id": "fixture.b", "reason": "Chosen method."})

    selected, gap, record = bind.bind(node, cards, client=Client(), timeout=3)
    assert selected["id"] == "fixture.b" and gap == ""
    assert record["model_reason"] == "Chosen method."
    assert len(calls) == 1 and calls[0]["task"] == "choose_card" and calls[0]["timeout"] == 3


@pytest.mark.parametrize("answer", [
    {"card_id": "fixture.absent", "reason": "Invented."},
    {"card_id": "fixture.lower", "reason": "Not a top score."},
    {"card_id": "fixture.a", "reason": ""},
    {"card_id": "fixture.a", "reason": "Edited.", "tools": ["invented"]},
])
def test_retrieval_model_cannot_escape_the_top_tie_or_edit_a_card(answer):
    """A model choice is refused if it escapes the tied set or changes the output contract."""
    from skills import bind
    from types import SimpleNamespace

    cards = [_retrieval_card("fixture.a", _retrieval_rule("aliases", "preferred", "shared")),
             _retrieval_card("fixture.b", _retrieval_rule("aliases", "preferred", "shared")),
             _retrieval_card("fixture.lower")]
    client = SimpleNamespace(complete=lambda **kwargs: SimpleNamespace(ok=True, payload=answer))
    selected, gap, record = bind.bind(_retrieval_node(aliases=["shared"]), cards, client=client)
    assert selected is None and gap.startswith("CARD_MODEL_CHOICE_REFUSED:")
    assert "fixture.a" in gap and "fixture.b" in gap


@pytest.mark.parametrize("mode", ["missing", "unavailable", "refused", "raises"])
def test_retrieval_tie_without_a_confirmed_model_answer_blocks(mode):
    """No missing, unavailable, failed, or exceptional model path may select the first tied card."""
    from skills import bind
    from types import SimpleNamespace

    def complete(**kwargs):
        if mode == "raises":
            raise RuntimeError("offline failure")
        if mode == "unavailable":
            pytest.fail("an unavailable model must not be called")
        return SimpleNamespace(ok=False, payload={})

    client = None if mode == "missing" else SimpleNamespace(
        complete=complete, available=mode != "unavailable")
    selected, gap, record = bind.bind(_retrieval_node(),
                              [_retrieval_card("fixture.a"), _retrieval_card("fixture.b")],
                              client=client)
    assert selected is None and gap.startswith("CARD_MODEL_")
    assert "candidates" in gap


def test_retrieval_unique_best_does_not_call_model_and_does_not_mutate_inputs():
    """A unique best card binds mechanically and ignores changes to hosts, IDs, and display text."""
    from skills import bind
    from copy import deepcopy

    cards = [_retrieval_card("fixture.a", _retrieval_rule("aliases", "preferred", "alpha")),
             _retrieval_card("fixture.b", _retrieval_rule("aliases", "preferred", "beta"))]
    node = _retrieval_node(aliases=["alpha"])
    saved = deepcopy((node, cards))

    class Client:
        def complete(self, **kwargs):
            pytest.fail("unique best selection must not call the model")

    selected, gap, record = bind.bind(node, cards, client=Client())
    renamed = dict(node, id="987", source_host="beta", target_host="alpha", description="beta")
    assert record == bind.retrieve(renamed, cards)
    assert selected["id"] == "fixture.a" and gap == ""
    assert (node, cards) == saved


def test_retrieval_no_ttp_uses_verification_and_category_membership_is_multiple():
    """A no-TTP node enters verification; category gates accept any declared membership."""
    from skills import bind

    cards = [_retrieval_card("fixture.verify", technique=(),
                             categories=("verification", "network")),
             _retrieval_card("fixture.method", technique=(), categories=("method",)),
             _retrieval_card("fixture.wrong_ttp", categories=("verification",))]
    result = bind.retrieve(_retrieval_node(attack_id=None, categories=["network"]), cards)
    assert result["selected_id"] == "fixture.verify"
    assert len(result["ranked"]) == 1
    assert bind.retrieve(_retrieval_node(attack_id=None, categories=["local"]), cards)["state"] == "gap"


def test_retrieval_conflicting_ttp_fields_are_refused():
    """Conflicting graph TTP fields cannot silently override one another."""
    from skills import bind

    with pytest.raises(ValueError, match="CARD_QUERY_TECHNIQUE_CONFLICT"):
        bind.retrieve(_retrieval_node(job_id="T1190"), [])


def _retrieval_overlay(monkeypatch, registry, index):
    original = Path.read_text
    contents = {ROOT / "skills" / "registry.json": json.dumps(registry),
                ROOT / "skills" / "index.json": json.dumps(index)}

    def read_text(path, *args, **kwargs):
        return contents[path] if path in contents else original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)


@pytest.mark.parametrize("change", ["index", "tools", "service", "case"])
def test_retrieval_registry_cannot_silently_drift_from_card_declarations(monkeypatch, change):
    """Indexes cannot override effective permissions or the card's declared required match fields."""
    from skills import bind

    registry = json.loads((ROOT / "skills" / "registry.json").read_text(encoding="utf-8"))
    index = bind.build_index(registry)
    if change == "index":
        index["categories"]["invented"] = [registry["skills"][0]["id"]]
        error = "CARD_INDEX_STALE"
    elif change == "tools":
        registry["skills"][0]["allowed_tools"].append("invented")
        index = bind.build_index(registry)
        error = "CARD_PERMISSION_PROJECTION_CHANGED"
    else:
        row = next(row for row in registry["skills"]
                   if any(rule["field"] == change and rule["state"] == "required"
                          for rule in row["match"]))
        next(rule for rule in row["match"] if rule["field"] == change)["state"] = "preferred"
        index = bind.build_index(registry)
        error = "CARD_MATCH_PROJECTION_CHANGED"
    _retrieval_overlay(monkeypatch, registry, index)
    with pytest.raises(ValueError, match=error):
        bind.faces(ROOT)


def test_retrieval_published_indexes_and_real_graph_have_declared_candidates():
    """Published indexes preserve permissions and give real no-TTP actions verification candidates."""
    from skills import bind
    from graph import rehydrate

    registry = json.loads((ROOT / "skills" / "registry.json").read_text(encoding="utf-8"))
    index = json.loads((ROOT / "skills" / "index.json").read_text(encoding="utf-8"))
    assert index == bind.build_index(registry)
    cards = bind.faces(ROOT)
    by_id = {card["id"]: card for card in cards}
    assert set(by_id) == {row["id"] for row in registry["skills"]}
    for row in registry["skills"]:
        assert row["allowed_tools"] == by_id[row["id"]]["tools"]
    document = rehydrate.load_file(ROOT / "tests/fixtures/hongri7/reference.action_graph.json")
    for node in document["nodes"]:
        if node["type"] != "AND":
            continue
        result = bind.retrieve(node, cards)
        assert result["candidates"], (node["id"], result["rejected"])
        if not result["terms"]["technique"]:
            assert all("verification" in by_id[row["card_id"]]["retrieval"]["categories"]
                       for row in result["candidates"])


class _RetrievalMemoryPath:
    def __init__(self, name, files):
        self.name, self.files = name, files

    def __truediv__(self, child):
        return type(self)(self.name + "/" + str(child), self.files)

    def mkdir(self, **kwargs):
        pass

    def write_text(self, text, **kwargs):
        self.files[self.name] = text
        return len(text)


def _retrieval_caller_case(mode):
    from types import SimpleNamespace

    cards = [_retrieval_card("fixture.a"), _retrieval_card("fixture.b")]
    if mode == "unique":
        cards = cards[:1]
    elif mode == "gap":
        cards = []
    calls = []

    class Client:
        available = mode != "blocked"

        def complete(self, **kwargs):
            assert mode == "tie" and kwargs["task"] == "choose_card"
            assert kwargs["timeout"] == 7.5
            candidates = json.loads(kwargs["user"])["candidates"]
            assert {row["card_id"] for row in candidates} == {"fixture.a", "fixture.b"}
            assert all(row["reasons"] for row in candidates)
            calls.append(kwargs)
            return SimpleNamespace(ok=True, payload={
                "card_id": "fixture.b", "reason": "chosen private-pass"})

    expected = "fixture.b" if mode == "tie" else "fixture.a" if mode == "unique" else None
    return cards, Client(), calls, expected


@pytest.mark.parametrize("mode", ["tie", "unique", "blocked", "gap"])
def test_retrieval_run_node_records_real_binding_before_dispatch(monkeypatch, mode):
    """Single-node dispatch consumes a checked selection and blocks missing cards or unavailable tie models."""
    import run_node

    files, sent, closed = {}, [], []
    run_dir = _RetrievalMemoryPath("run", files)
    cards, client, calls, expected = _retrieval_caller_case(mode)
    node = _retrieval_node(id="17", target_host="endpoint", port="443")

    class Executor:
        def __init__(self, *args, **kwargs):
            assert expected is not None

        def close(self):
            closed.append(True)

    def drive(selected, task, scope, executor, **kwargs):
        receipt = json.loads(files["run/card_selection.json"])
        assert receipt["status"] == "selected"
        assert receipt["binding_selection"]["selected_id"] == selected["id"] == expected
        assert kwargs["client"] is client
        sent.append(selected["id"])
        return {"status": "model_reported", "reason": "fixture"}

    monkeypatch.setattr(run_node, "resolve_path",
                        lambda path: run_dir if str(path) == "run" else path)
    monkeypatch.setattr(run_node.rehydrate, "load_file", lambda path: {"nodes": [node]})
    monkeypatch.setattr(run_node.bind, "faces", lambda root: cards)
    monkeypatch.setattr(run_node.model_mod, "client_from_env", lambda **kwargs: client)
    monkeypatch.setattr(run_node, "SshExecutor", Executor)
    monkeypatch.setattr(run_node.run_lean_task, "drive", drive)
    result = run_node.main([
        "--node", "17", "--graph", "fixture.json", "--run-dir", "run",
        "--remote", "attacker@192.0.2.1", "--password", "private-pass",
        "--model", "offline", "--model-timeout", "7.5",
    ])

    assert result == (0 if expected else 3)
    assert len(calls) == (1 if mode == "tie" else 0)
    assert sent == ([expected] if expected else [])
    assert closed == ([True] if expected else [])
    receipt = json.loads(files["run/card_selection.json"])
    assert receipt["status"] == ("selected" if expected else "blocked")
    assert all("private-pass" not in text for text in files.values())
    if expected:
        saved = json.loads(files["run/node_result.json"])
        assert saved["binding_selection"] == receipt["binding_selection"]
    else:
        assert receipt["reason"].startswith("CARD_MODEL_UNAVAILABLE" if mode == "blocked" else "CARD_GAP")
        assert "run/node_result.json" not in files


@pytest.mark.parametrize("mode", ["tie", "unique", "blocked", "gap"])
def test_retrieval_walk_binding_uses_real_selection_and_records_it(monkeypatch, mode):
    """The walk's real binding boundary writes the receipt and the loop publishes it.

    The step lives in ``orchestration/walk_step.py`` now: ``run_step`` holds the binding boundary and
    ``run_walk``'s own ``record_step`` publishes the selection into the planner note. This slices
    the first out of the shipped file and asserts the publish line in the second, so the test still
    exercises production code rather than a copy of it.
    """
    import ast
    from types import SimpleNamespace
    from orchestration import walk as walk_mod, walk_step

    source = Path(walk_step.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    step = next(node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == "run_step")
    body = step.body
    binding = next(index for index, node in enumerate(body)
                   if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                   and isinstance(node.value.func, ast.Attribute)
                   and isinstance(node.value.func.value, ast.Name)
                   and node.value.func.value.id == "bind" and node.value.func.attr == "bind")
    receipt = next(index for index in range(binding + 1, len(body))
                   if isinstance(body[index], ast.Expr)
                   and isinstance(body[index].value, ast.Call)
                   and isinstance(body[index].value.func, ast.Attribute)
                   and body[index].value.func.attr == "write_text")
    boundary = ast.Module(body=body[binding:receipt + 1], type_ignores=[])
    files = {}
    cards, client, calls, expected = _retrieval_caller_case(mode)
    monkeypatch.setattr(bind, "faces", lambda root: cards)
    namespace = {
        "run_dir": _RetrievalMemoryPath("run", files), "node_id": "17",
        "node": _retrieval_node(id="17"), "repository": ROOT, "client": client,
        "limits": SimpleNamespace(model_timeout=7.5), "secrets": ["private-pass"],
        "bind": bind, "json": json, "mask_secrets": mask_secrets,
    }
    exec(compile(boundary, walk_step.__file__, "exec"), namespace)
    receipt = json.loads(files["run/card_selection.json"])
    assert len(calls) == (1 if mode == "tie" else 0)
    assert receipt["status"] == ("selected" if expected else "blocked")
    assert all("private-pass" not in text for text in files.values())
    if expected:
        assert namespace["card"]["id"] == expected
        assert receipt["binding_selection"]["selected_id"] == expected
    else:
        assert namespace["card"] is None
        assert namespace["gap"].startswith("CARD_MODEL_UNAVAILABLE" if mode == "blocked" else "CARD_GAP")

    loop_source = Path(walk_mod.__file__).read_text(encoding="utf-8")
    loop_tree = ast.parse(loop_source)
    loop = next(node for node in loop_tree.body
                if isinstance(node, ast.FunctionDef) and node.name == "run_walk")
    published = [node for node in ast.walk(loop)
                 if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Subscript)
                         and isinstance(target.value, ast.Name)
                         and target.value.id == "planner_note"
                         and isinstance(target.slice, ast.Constant)
                         and target.slice.value == "binding_selection"
                         for target in node.targets)]
    assert published, "run_walk no longer publishes the binding selection"
    assert isinstance(published[0].value, ast.Attribute)
    assert published[0].value.attr == "binding_selection"
    assert isinstance(published[0].value.value, ast.Name)
    assert published[0].value.value.id == "step"
