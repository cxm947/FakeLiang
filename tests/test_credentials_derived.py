"""Derived credential references, provenance, carry and candidate ordering."""
import json
import secrets
from pathlib import Path

import pytest

from tests.test_credentials import ROOT, account_graph, write_source
from runtime import credentials, credential_selection




@pytest.fixture
def derived_supplied(tmp_path):
    assert not tmp_path.resolve().is_relative_to(ROOT)
    run_dir = tmp_path / "runs" / "derived"
    private_dir = tmp_path / "private" / "derived"
    external_path = tmp_path / "private" / "external.json"
    external = write_source(external_path, graph_user="account_material", user="external_login")
    source = credentials.load_source(external_path, run_dirs=(run_dir,))
    document = account_graph()
    mapping = {"workstation": "198.51.100.21", "directory": "198.51.100.22"}
    value = secrets.token_urlsafe(24)
    entry = {"realm": "realm-a", "user": "derived_login", "value": value,
             "kind": "password", "source_call": "call-20261005T140000-cdefab",
             "quote": "realm-a\\derived_login password=" + value}
    rows = credentials.record_proved(run_dir, document=document, node_id="acquire", proved=True,
                                     source=None, materials=[entry], materials_dir=private_dir,
                                     host_map=mapping)
    return run_dir, private_dir, source, external, document, mapping, entry, rows


def test_derived_and_external_candidates_have_fixed_priority(derived_supplied):
    run_dir, _, source, external, document, mapping, entry, rows = derived_supplied
    candidates = credentials.select_candidates(document, document["nodes"][-1], rows,
                                               source=source, host_map=mapping, run_dirs=(run_dir,))
    assert [(item["order"], item["origin"]) for item in candidates] == [(1, "derived"), (2, "external")]
    assert [item["credential_ref"]["secret"] for item in candidates] == [entry["value"], external["secret"]]
    assert candidates[0]["credential_ref"]["user"] == "derived_login"
    assert candidates[1]["credential_ref"]["user"] == "external_login"


def test_a_derived_hash_never_outranks_a_declared_password(derived_supplied, monkeypatch):
    """候选顺序按**能不能用**排：derived 是 NTLM hash、external 是明文口令时，明文必须排第一。

    2026-10-06 walk-68 node 2 实测：order=1 是 node 5 从 LSASS 读出来的 hash，模型照 old 的
    "derived first" 把它填进 `schtasks /p` 与 `net use \\\\host\\C$ /user:<user> <口令>` 这种
    只吃明文的槽位，回执分别是 `错误: 拒绝访问` 与 `发生系统错误 1326 / 登录失败: 未知的用户名或
    错误密码`；同一条命令换成明文候选就成功。两个候选在日志里都被 redaction 抹成 `<redacted>`，
    于是看起来像随机失败，四个回合里白烧了三个。
    """
    run_dir, _, source, external, document, mapping, entry, rows = derived_supplied

    def fake_resolve(row, **_kwargs):
        if row.get("source_kind") == "derived":
            return {"realm": entry["realm"], "user": entry["user"],
                    "secret": "a" * 32, "mode": "ntlm"}
        return dict(external)

    monkeypatch.setattr(credential_selection, "_resolve", fake_resolve)
    candidates = credentials.select_candidates(document, document["nodes"][-1], rows,
                                               source=source, host_map=mapping,
                                               run_dirs=(run_dir,))
    assert [(item["order"], item["origin"], item["credential_ref"].get("mode"))
            for item in candidates] == [(1, "external", None), (2, "derived", "ntlm")]
    # 归因不丢：来源仍留在记录里，只是不再决定用哪个。
    assert {item["origin"] for item in candidates} == {"derived", "external"}


def test_candidates_with_only_derived_material(derived_supplied):
    _, _, _, _, document, mapping, entry, rows = derived_supplied
    candidates = credentials.select_candidates(document, document["nodes"][-1], rows, host_map=mapping)
    assert len(candidates) == 1 and candidates[0]["order"] == 1
    assert candidates[0]["origin"] == "derived"
    assert candidates[0]["credential_ref"]["secret"] == entry["value"]


def test_candidates_with_only_external_material(derived_supplied):
    _, _, source, external, document, mapping, _, _ = derived_supplied
    candidates = credentials.select_candidates(document, document["nodes"][-1], [],
                                               source=source, host_map=mapping)
    #: order 是"交付顺序"，不是来源编号：delivered 列表里的第 N 个就是 order=N。
    assert len(candidates) == 1 and candidates[0]["order"] == 1
    assert candidates[0]["origin"] == "external"
    assert candidates[0]["credential_ref"]["secret"] == external["secret"]


def test_candidates_without_either_material_refuse_by_name(derived_supplied):
    _, _, _, _, document, mapping, _, _ = derived_supplied
    with pytest.raises(ValueError, match="^CREDENTIAL_MISSING$"):
        credentials.select_candidates(document, document["nodes"][-1], [], host_map=mapping)


def test_derived_reference_keeps_masked_quote_and_private_original(derived_supplied):
    run_dir, private_dir, _, _, document, mapping, entry, rows = derived_supplied
    row = rows[0]
    assert row["source_kind"] == "derived"
    assert row["source_call"] == entry["source_call"]
    assert entry["value"] not in row["source_quote"] and "<redacted>" in row["source_quote"]
    assert json.loads(row["source_summary"]) == {"realm": "realm-a", "user": "derived_login", "kind": "password"}
    assert Path(row["source_path"]).parent == private_dir
    private = json.loads(Path(row["source_path"]).read_text(encoding="utf-8"))
    assert private["credentials"]["account_material"]["secret"] == entry["value"]
    assert private["provenance"]["quote"] == entry["quote"]
    assert entry["value"] not in credentials.path_for(run_dir).read_text(encoding="utf-8")
    assert credentials.record_proved(run_dir, document=document, node_id="acquire", proved=True,
                                     source=None, materials=[entry], materials_dir=private_dir,
                                     host_map=mapping) == rows
    assert len(list(private_dir.glob("*.json"))) == 1


def test_external_and_derived_records_coexist_without_duplicate_candidate(derived_supplied):
    run_dir, private_dir, source, external, document, mapping, entry, _ = derived_supplied
    credentials.record_proved(run_dir, document=document, node_id="acquire", proved=True,
                              source=source, materials=[entry], materials_dir=private_dir,
                              host_map=mapping)
    rows = credentials.read(run_dir)
    assert len(rows) == 2
    candidates = credentials.select_candidates(document, document["nodes"][-1], rows,
                                               source=source, host_map=mapping)
    assert [item["credential_ref"]["secret"] for item in candidates] == [entry["value"], external["secret"]]


def test_same_origin_multiple_derived_materials_refuse_ambiguity(derived_supplied):
    run_dir, private_dir, source, _, document, mapping, entry, _ = derived_supplied
    second_value = secrets.token_urlsafe(24)
    second = {**entry, "value": second_value, "quote": "realm-a\\derived_login password=" + second_value}
    credentials.record_proved(run_dir, document=document, node_id="acquire", proved=True,
                              source=None, materials=[second], materials_dir=private_dir, host_map=mapping)
    with pytest.raises(ValueError, match="^CREDENTIAL_AMBIGUOUS$"):
        credentials.select_candidates(document, document["nodes"][-1], credentials.read(run_dir),
                                      source=source, host_map=mapping)


def test_derived_carry_recovers_private_reference_in_new_run(derived_supplied, tmp_path):
    old_run, _, _, _, document, mapping, entry, rows = derived_supplied
    new_run = tmp_path / "runs" / "new"
    carried = credentials.carry(old_run, new_run, host_map=mapping)
    assert carried[0]["parent"] == rows[0]["credential_id"]
    for key in ("source_path", "source_digest", "source_kind", "source_quote", "source_summary"):
        assert carried[0][key] == rows[0][key]
    restored = credentials.select_candidates(document, document["nodes"][-1], credentials.read(new_run),
                                             host_map=mapping, run_dirs=(old_run, new_run))
    assert restored[0]["credential_ref"]["secret"] == entry["value"]
    assert credentials.secrets_for_rows(carried) == [entry["value"]]
    assert entry["value"] not in credentials.path_for(new_run).read_text(encoding="utf-8")


@pytest.mark.parametrize("field", ["material", "quote", "source_call"])
def test_changed_derived_source_refuses_even_when_external_exists(derived_supplied, field):
    _, _, source, _, document, mapping, _, rows = derived_supplied
    path = Path(rows[0]["source_path"])
    private = json.loads(path.read_text(encoding="utf-8"))
    if field == "material":
        private["credentials"]["account_material"]["secret"] = secrets.token_urlsafe(24)
    else:
        private["provenance"][field] += " altered"
    path.write_text(json.dumps(private), encoding="utf-8", newline="")
    with pytest.raises(ValueError, match="^CREDENTIAL_SOURCE_CHANGED$"):
        credentials.select_candidates(document, document["nodes"][-1], rows,
                                      source=source, host_map=mapping)


@pytest.mark.parametrize("change,code", [("kind", "DERIVED_INVALID"), ("source_call", "DERIVED_INVALID"),
                                        ("quote", "DERIVED_QUOTE_MISMATCH")])
def test_invalid_derived_material_writes_no_partial_ledger(derived_supplied, tmp_path, change, code):
    _, _, source, _, document, mapping, entry, _ = derived_supplied
    run_dir = tmp_path / "runs" / "rejected"
    private_dir = tmp_path / "private" / "rejected"
    invalid = {**entry, change: "invalid"}
    with pytest.raises(ValueError, match="^CREDENTIAL_" + code + "$"):
        credentials.record_proved(run_dir, document=document, node_id="acquire", proved=True,
                                  source=source, materials=[entry, invalid], materials_dir=private_dir,
                                  host_map=mapping)
    assert not credentials.path_for(run_dir).exists()
    assert not private_dir.exists()


def test_derived_multiple_fact_binding_refuses_instead_of_guessing(derived_supplied, tmp_path):
    _, _, source, _, document, _, entry, _ = derived_supplied
    document["nodes"].append({"id": "other", "type": "OR",
                              "description": "getAccount(workstation,other_role,other_material,admin)",
                              "dependencies": [{"ref": "acquire", "type": "AND"}]})
    with pytest.raises(ValueError, match="^CREDENTIAL_DERIVED_BINDING_AMBIGUOUS$"):
        credentials.record_proved(tmp_path / "new", document=document, node_id="acquire", proved=True,
                                  source=source, materials=[entry], materials_dir=tmp_path / "private")


def test_derived_private_directory_required_and_outside_all_run_roots(derived_supplied, tmp_path):
    _, _, _, _, document, _, entry, _ = derived_supplied
    run_dir = tmp_path / "runs" / "rejected"
    carried_root = tmp_path / "old_run"
    for destination, code in ((None, "MATERIALS_DIR_REQUIRED"),
                              (run_dir / "private", "SOURCE_NOT_PRIVATE"),
                              (ROOT / "private", "SOURCE_NOT_PRIVATE"),
                              (carried_root / "private", "SOURCE_NOT_PRIVATE"),
                              (tmp_path / "output", "SOURCE_NOT_PRIVATE")):
        with pytest.raises(ValueError, match="^CREDENTIAL_" + code + "$"):
            credentials.record_proved(run_dir, document=document, node_id="acquire", proved=True,
                                      source=None, materials=[entry], materials_dir=destination,
                                      run_dirs=(carried_root,))
    assert not credentials.path_for(run_dir).exists()


def test_derived_short_value_and_cookie_quote_never_enter_public_ledger(derived_supplied, tmp_path):
    _, _, _, _, document, _, entry, _ = derived_supplied
    short = "!?"
    cookie = "cookie-" + secrets.token_urlsafe(18)
    entry = {**entry, "value": short, "quote": "realm-a\\derived_login password=" + short
             + "\nCookie: sid=" + cookie}
    run_dir = tmp_path / "runs" / "short"
    rows = credentials.record_proved(run_dir, document=document, node_id="acquire", proved=True,
                                     source=None, materials=[entry], materials_dir=tmp_path / "private" / "short")
    public = credentials.path_for(run_dir).read_text(encoding="utf-8")
    assert short not in public and cookie not in public
    assert credentials.secrets_for_rows(rows) == [short]


def test_unproved_derived_material_creates_no_private_or_public_files(derived_supplied, tmp_path):
    _, _, _, _, document, _, entry, _ = derived_supplied
    run_dir, private_dir = tmp_path / "runs" / "unproved", tmp_path / "private" / "unproved"
    assert credentials.record_proved(run_dir, document=document, node_id="acquire", proved=False,
                                     source=None, materials=[entry], materials_dir=private_dir) == []
    assert not run_dir.exists() and not private_dir.exists()


@pytest.mark.parametrize("origin,target,graph_user,symbol,realm,login,kind", [
    ("gateway", "storage", "storage_role", "storage_login", "realm-storage", "storage_operator", "password"),
    ("worknode", "controller", "controller_role", "controller_login", "realm-control", "control_operator", "ntlm"),
])
def test_derived_candidates_use_replaced_graph_and_host_map_data(
        tmp_path, origin, target, graph_user, symbol, realm, login, kind):
    document = account_graph(source=origin, target=target, graph_user=graph_user,
                             symbol=symbol, privilege="service_operator")
    mapping = {origin: "203.0.113.51", target: "203.0.113.52"}
    run_dir = tmp_path / "runs" / graph_user
    value = secrets.token_hex(16) if kind == "ntlm" else secrets.token_urlsafe(24)
    entry = {"realm": realm, "user": login, "value": value, "kind": kind,
             "source_call": "call-20261005T150000-abcdef-test",
             "quote": realm + "\\" + login + " " + kind + "=" + value}
    rows = credentials.record_proved(run_dir, document=document, node_id="acquire", proved=True,
                                     source=None, materials=[entry], materials_dir=tmp_path / "private",
                                     host_map=mapping)
    candidates = credentials.select_candidates(document, document["nodes"][-1], rows, host_map=mapping)
    assert rows[0]["logical"] == origin and rows[0]["host"] == mapping[origin]
    assert rows[0]["source_key"] == symbol
    assert candidates == [{"order": 1, "origin": "derived", "credential_ref": {
        "user": login, "secret": value, "domain": realm, "mode": kind}}]
