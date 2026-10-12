"""Offline account supply: references, direct graph binding, carry and honest refusals."""
import json
import secrets
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from runtime import credentials, credential_selection   # noqa: E402


def account_graph(source="workstation", target="directory", graph_user="operator_role",
                  symbol="account_material", privilege="administrator"):
    acquired = f"getAccount({source},{graph_user},{symbol},{privilege})"
    owned = f"hasAccount({target},{graph_user},{symbol},{privilege})"
    consumer = {"id": "consume", "type": "AND", "target_host": target,
                "dependencies": [{"ref": "account", "description": acquired,
                                  "produced_by": ["acquire"]},
                                 {"description": owned}]}
    return {"nodes": [{"id": "acquire", "type": "AND", "dependencies": []},
                      {"id": "account", "type": "OR", "description": acquired,
                       "dependencies": [{"ref": "acquire", "type": "AND"}]}, consumer]}


def write_source(path, *, graph_user="operator_role", user="operator", realm="realm-a",
                 secret=None, **extra):
    material = {"user": user, "realm": realm,
                "secret": secrets.token_urlsafe(24) if secret is None else secret, **extra}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"credentials": {graph_user: material}}),
                    encoding="utf-8", newline="")
    return material


@pytest.fixture
def supplied(tmp_path):
    # pytest's temporary directory holds the private source; no credential fixture is committed
    # or put in an output/run directory. Refuse a repository-local --basetemp configuration.
    assert not tmp_path.resolve().is_relative_to(ROOT)
    path = tmp_path / "private" / "context.json"
    material = write_source(path)
    run_dir = tmp_path / "runs" / "first"
    source = credentials.load_source(path, run_dirs=(run_dir,))
    document = account_graph()
    mapping = {"workstation": "192.0.2.10", "directory": "192.0.2.20"}
    rows = credentials.record_proved(run_dir, document=document, node_id="acquire",
                                     proved=True, source=source, host_map=mapping,
                                     source_call="call-20261005T120000-abcdef")
    return path, material, run_dir, source, document, mapping, rows


def test_producer_representations_are_deduplicated_and_unproved_records_nothing(tmp_path):
    document = account_graph()
    assert credentials.produced_facts(document, "acquire") == [
        ("workstation", "operator_role", "account_material", "administrator")]
    assert credentials.record_proved(tmp_path, document=document, node_id="acquire",
                                     proved=False, source=None) == []
    assert not credentials.path_for(tmp_path).exists()
    assert credentials.record_proved(tmp_path, document=document, node_id="consume",
                                     proved=True, source=None) == []
    with pytest.raises(ValueError, match="^CREDENTIAL_SOURCE_BINDING_MISSING$"):
        credentials.record_proved(tmp_path, document=document, node_id="acquire",
                                  proved=True, source=None)


def test_quoted_fact_atoms_and_unresolved_variables():
    document = account_graph(source="'host,one'", graph_user="'operator.role'")
    assert credentials.produced_facts(document, "acquire")[0][:2] == (
        "host,one", "operator.role")
    with pytest.raises(ValueError, match="^CREDENTIAL_FACT_INVALID$"):
        credentials.produced_facts(account_graph(graph_user="Unbound"), "acquire")


def test_ledger_records_only_reference_and_provenance(supplied):
    path, material, run_dir, source, document, mapping, rows = supplied
    assert credentials.read(run_dir) == rows
    assert rows[0]["source_path"] == str(path.resolve())
    assert rows[0]["source_key"] == "operator_role"
    assert rows[0]["source_node"] == "acquire"
    assert rows[0]["source_call"] == "call-20261005T120000-abcdef"
    assert rows[0]["parent"] == ""
    assert "secret" not in rows[0] and "user" not in rows[0]
    assert material["secret"] not in credentials.path_for(run_dir).read_text(encoding="utf-8")
    assert credentials.known_secrets(source) == [material["secret"]]
    again = credentials.record_proved(run_dir, document=document, node_id="acquire",
                                      proved=True, source=source, host_map=mapping)
    assert again == rows
    assert credentials.read(run_dir) == rows


def test_source_must_be_outside_repository_output_and_all_run_roots(supplied, tmp_path):
    path, _, run_dir, _, _, _, _ = supplied
    for blocked in (path.parent, tmp_path):
        with pytest.raises(ValueError, match="^CREDENTIAL_SOURCE_NOT_PRIVATE$"):
            credentials.load_source(path, run_dirs=(run_dir, blocked))
    with pytest.raises(ValueError, match="^CREDENTIAL_SOURCE_NOT_PRIVATE$"):
        credentials.load_source(path, repository=path.parent)
    with pytest.raises(ValueError, match="^CREDENTIAL_SOURCE_NOT_PRIVATE$"):
        credentials.load_source(tmp_path / "output" / "context.json")


def test_direct_cross_host_binding_supplies_actual_login_not_graph_role(supplied):
    _, material, run_dir, _, document, mapping, rows = supplied
    chosen = credentials.select(document, document["nodes"][-1], rows,
                                host_map=mapping, run_dirs=(run_dir,),
                                user="operator", realm="realm-a")
    assert chosen == {"user": "operator", "secret": material["secret"],
                      "domain": "realm-a", "mode": "password"}


def test_direct_or_reference_resolves_label_and_producer(supplied):
    _, _, _, _, document, mapping, rows = supplied
    consumer = document["nodes"][-1]
    consumer["dependencies"][0] = {"ref": "account"}
    assert credentials.select(document, consumer, rows, host_map=mapping)["user"] == "operator"
    assert credentials.produced_facts(document, "acquire") == [
        ("workstation", "operator_role", "account_material", "administrator")]


def test_same_host_accepts_exact_account_fact_without_cross_host_binding(supplied):
    _, _, _, _, document, mapping, rows = supplied
    node = {"target_host": "workstation", "dependencies": [{
        "description": "hasAccount(workstation,operator_role,account_material,administrator)"}]}
    assert credentials.select(document, node, rows, host_map=mapping)["user"] == "operator"


@pytest.mark.parametrize("change", ["no_account", "other_symbol", "other_privilege", "other_producer"])
def test_no_username_only_or_transitive_cross_host_reuse(supplied, change):
    _, _, _, _, document, mapping, rows = supplied
    node = document["nodes"][-1]
    if change == "no_account":
        node["dependencies"].pop()
    elif change == "other_producer":
        node["dependencies"][0]["produced_by"] = ["different_producer"]
    else:
        old = "account_material" if change == "other_symbol" else "administrator"
        node["dependencies"][1]["description"] = node["dependencies"][1]["description"].replace(
            old, "different")
    with pytest.raises(ValueError, match="^CREDENTIAL_(BINDING_MISSING|MISSING)$"):
        credentials.select(document, node, rows, host_map=mapping)


def test_missing_ambiguous_stale_user_and_realm_failures(supplied):
    _, _, _, _, document, mapping, rows = supplied
    node = document["nodes"][-1]
    with pytest.raises(ValueError, match="^CREDENTIAL_MISSING$"):
        credentials.select(document, node, [], host_map=mapping)
    second = {**rows[0], "credential_id": "cred-second", "source_run": str(ROOT.parent)}
    with pytest.raises(ValueError, match="^CREDENTIAL_AMBIGUOUS$"):
        credentials.select(document, node, rows + [second], host_map=mapping)
    with pytest.raises(ValueError, match="^CREDENTIAL_STALE_HOST$"):
        credentials.select(document, node, rows, host_map={**mapping, "workstation": "192.0.2.11"})
    with pytest.raises(ValueError, match="^CREDENTIAL_USER_CONFLICT$"):
        credentials.select(document, node, rows, host_map=mapping, user="operator_role")
    with pytest.raises(ValueError, match="^CREDENTIAL_REALM_CONFLICT$"):
        credentials.select(document, node, rows, host_map=mapping, realm="realm-b")


def test_carry_keeps_private_reference_and_can_resolve_in_an_independent_run(supplied, tmp_path):
    path, material, old_run, _, document, mapping, rows = supplied
    new_run = tmp_path / "runs" / "second"
    carried = credentials.carry(old_run, new_run, host_map=mapping)
    assert len(carried) == 1
    assert carried[0]["parent"] == rows[0]["credential_id"]
    assert carried[0]["credential_id"] != rows[0]["credential_id"]
    for key in ("source_path", "source_key", "source_digest", "source_node", "source_call", "source_run"):
        assert carried[0][key] == rows[0][key]
    assert credentials.secrets_for_rows(credentials.read(new_run), run_dirs=(old_run, new_run)) == [
        material["secret"]]
    assert credentials.select(document, document["nodes"][-1], credentials.read(new_run),
                              host_map=mapping, run_dirs=(old_run, new_run))["secret"] == material["secret"]
    assert credentials.carry(old_run, new_run, host_map=mapping) == []
    assert path.is_file()
    for artifact in new_run.rglob("*"):
        if artifact.is_file():
            assert material["secret"] not in artifact.read_text(encoding="utf-8")


def test_carry_refuses_stale_map_without_partial_append(supplied, tmp_path):
    _, _, old_run, _, _, mapping, _ = supplied
    new_run = tmp_path / "runs" / "second"
    with pytest.raises(ValueError, match="^CREDENTIAL_STALE_HOST$"):
        credentials.carry(old_run, new_run, host_map={**mapping, "workstation": "192.0.2.12"})
    assert not credentials.path_for(new_run).exists()


@pytest.mark.parametrize("change,code", [("secret", "SOURCE_CHANGED"), ("user", "SOURCE_CHANGED"),
                                        ("realm", "SOURCE_CHANGED"), ("remove", "SOURCE_BINDING_MISSING"),
                                        ("missing", "SOURCE_UNAVAILABLE")])
def test_changed_or_missing_material_is_never_silently_rebound(supplied, change, code):
    path, material, _, _, document, mapping, rows = supplied
    if change == "missing":
        path.unlink()
    else:
        changed = {**material, change: secrets.token_urlsafe(24)}
        path.write_text(json.dumps({"credentials": {} if change == "remove" else {
            "operator_role": changed}}), encoding="utf-8", newline="")
    with pytest.raises(ValueError, match="^CREDENTIAL_" + code + "$") as error:
        credentials.select(document, document["nodes"][-1], rows, host_map=mapping)
    assert material["secret"] not in str(error.value)


def test_private_entry_requires_real_user_and_consistent_realm(tmp_path):
    path = tmp_path / "private.json"
    secret = secrets.token_urlsafe(24)
    for entry, code in (({"secret": secret}, "SOURCE_BINDING_MISSING"),
                        ({"user": "operator", "secret": secret, "realm": "one", "domain": "two"},
                         "REALM_CONFLICT"),
                        ({"user": "operator", "secret": secret, "mode": "unsupported"},
                         "SOURCE_MODE_UNSUPPORTED")):
        path.write_text(json.dumps({"credentials": {"operator_role": entry}}), encoding="utf-8", newline="")
        with pytest.raises(ValueError, match="^CREDENTIAL_" + code + "$") as error:
            credentials.load_source(path)
        assert secret not in str(error.value)


def test_corrupt_ledger_is_not_silently_skipped(tmp_path):
    credentials.path_for(tmp_path).write_text("not json\n", encoding="utf-8", newline="")
    with pytest.raises(ValueError, match="^CREDENTIAL_LEDGER_INVALID$"):
        credentials.read(tmp_path)


@pytest.mark.parametrize("hosts,addresses,graph_user,realm", [
    (("origin", "service"), ("198.51.100.11", "198.51.100.12"), "service_role", "service-realm"),
    (("edge", "archive"), ("203.0.113.31", "203.0.113.32"), "archive_role", "archive-realm"),
])
def test_supply_uses_graph_and_host_map_data(supplied, tmp_path, hosts, addresses, graph_user, realm):
    path = tmp_path / "private" / "alternative.json"
    material = write_source(path, graph_user=graph_user, user="runtime_login", realm=realm)
    document = account_graph(source=hosts[0], target=hosts[1], graph_user=graph_user,
                             symbol="alternate_material", privilege="service_operator")
    mapping = dict(zip(hosts, addresses))
    run_dir = tmp_path / "runs" / graph_user
    rows = credentials.record_proved(run_dir, document=document, node_id="acquire", proved=True,
                                     source=credentials.load_source(path), host_map=mapping)
    chosen = credentials.select(document, document["nodes"][-1], rows, host_map=mapping,
                                user="runtime_login", realm=realm)
    assert rows[0]["host"] == addresses[0]
    assert chosen["secret"] == material["secret"]
    assert chosen["domain"] == realm


def test_short_secret_is_collectable_and_never_written(tmp_path):
    path = tmp_path / "private.json"
    short = "".join(secrets.choice("!?") for _ in range(2))
    write_source(path, secret=short)
    source = credentials.load_source(path)
    run_dir = tmp_path / "run"
    rows = credentials.record_proved(run_dir, document=account_graph(), node_id="acquire",
                                     proved=True, source=source)
    assert credentials.known_secrets(source) == [short]
    assert credentials.secrets_for_rows(rows, run_dirs=(run_dir,)) == [short]
    assert short not in credentials.path_for(run_dir).read_text(encoding="utf-8")


def test_record_refuses_secret_in_graph_metadata_before_creating_a_ledger(supplied, tmp_path):
    _, material, _, source, _, _, _ = supplied
    document = account_graph(symbol="'" + material["secret"] + "'")
    run_dir = tmp_path / "runs" / "rejected"
    with pytest.raises(ValueError, match="^CREDENTIAL_METADATA_CONTAINS_SECRET$"):
        credentials.record_proved(run_dir, document=document, node_id="acquire",
                                  proved=True, source=source)
    assert not credentials.path_for(run_dir).exists()


def test_carry_refuses_secret_metadata_before_writing(supplied, tmp_path, monkeypatch):
    _, material, old_run, _, _, mapping, rows = supplied
    new_run = tmp_path / "runs" / "rejected"
    contaminated = {**rows[0], "source_call": material["secret"]}
    monkeypatch.setattr(credentials, "read", lambda root: [contaminated] if root == old_run else [])
    with pytest.raises(ValueError, match="^CREDENTIAL_METADATA_CONTAINS_SECRET$"):
        credentials.carry(old_run, new_run, host_map=mapping)
    assert not credentials.path_for(new_run).exists()


def test_record_missing_binding_does_not_write_partial_batch(supplied, tmp_path):
    _, _, _, source, document, _, _ = supplied
    document["nodes"].append({"id": "unbound_account", "type": "OR",
                              "description": "getAccount(workstation,other_role,other_material,admin)",
                              "dependencies": [{"ref": "acquire", "type": "AND"}]})
    run_dir = tmp_path / "runs" / "rejected"
    with pytest.raises(ValueError, match="^CREDENTIAL_SOURCE_BINDING_MISSING$"):
        credentials.record_proved(run_dir, document=document, node_id="acquire",
                                  proved=True, source=source)
    assert not credentials.path_for(run_dir).exists()


def test_incomplete_final_jsonl_line_is_not_accepted(supplied):
    _, _, run_dir, _, _, _, rows = supplied
    credentials.path_for(run_dir).write_text(json.dumps(rows[0]), encoding="utf-8", newline="")
    with pytest.raises(ValueError, match="^CREDENTIAL_LEDGER_INVALID$"):
        credentials.read(run_dir)


def test_source_accepts_existing_utf8_bom_context(supplied):
    path, material, run_dir, _, _, _, _ = supplied
    text = path.read_text(encoding="utf-8")
    path.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
    source = credentials.load_source(path, run_dirs=(run_dir,))
    assert credentials.known_secrets(source) == [material["secret"]]


@pytest.mark.parametrize("operation", ["record", "carry"])
def test_transport_secret_metadata_is_refused_before_append(supplied, tmp_path, monkeypatch, operation):
    _, material, old_run, source, document, mapping, rows = supplied
    transport = secrets.token_urlsafe(30)
    assert transport != material["secret"]
    new_run = tmp_path / "runs" / "transport_rejected"
    with pytest.raises(ValueError, match="^CREDENTIAL_METADATA_CONTAINS_SECRET$"):
        if operation == "record":
            credentials.record_proved(new_run, document=document, node_id="acquire",
                                      proved=True, source=source, host_map=mapping,
                                      source_call=transport, secrets=[transport])
        else:
            contaminated = {**rows[0], "source_call": transport}
            monkeypatch.setattr(credentials, "read", lambda root: [contaminated] if root == old_run else [])
            credentials.carry(old_run, new_run, host_map=mapping, secrets=[transport])
    assert not credentials.path_for(new_run).exists()


def test_external_candidate_prefers_declared_symbol_over_legacy_user(supplied):
    path, old, run_dir, _, document, mapping, _ = supplied
    chosen = {**old, "user": "declared_login", "secret": secrets.token_urlsafe(24)}
    path.write_text(json.dumps({"credentials": {"operator_role": old, "account_material": chosen}}),
                    encoding="utf-8", newline="")
    source = credentials.load_source(path, run_dirs=(run_dir,))
    candidates = credentials.select_candidates(document, document["nodes"][-1], [],
                                               source=source, host_map=mapping)
    assert candidates[0]["credential_ref"]["user"] == "declared_login"
    assert candidates[0]["credential_ref"]["secret"] == chosen["secret"]


def test_two_representations_of_one_account_are_not_ambiguous(monkeypatch):
    """同一个账号的明文口令 + NTLM hash 是一份凭据的两种写法（kiwi 的 creds_all 一次给两种）。

    2026-10-06 walk-47 实测：把它们当"两个凭据"，node 48 / 2 / 44 整条支线全卡在
    CREDENTIAL_AMBIGUOUS —— 跨网段那一步永远走不到。挑法写明，并且把手里的表示交给下游：
    密码优先（一个明文口令哪里都能登，hash 要对方支持传哈希）。
    """
    from runtime import credentials

    def row(node, key, digest, kind):
        return {"logical": "pc1", "graph_user": "Administrator", "symbol": "lab_domain_credential",
                "privilege": "system", "host": "192.168.52.30", "source_node": node,
                "source_call": "call-20261006T010203-abcdef", "source_path": "priv.json",
                "source_key": key, "source_digest": digest, "source_run": "run",
                "source_kind": "derived"}

    materials = {
        "pw": {"user": "Administrator", "domain": "WHOAMIANONY", "secret": "cleartext-1",
               "mode": "password"},
        "nt": {"user": "Administrator", "domain": "WHOAMIANONY", "secret": "aabbccdd",
               "mode": "ntlm"},
    }

    def fake_resolve(entry, **_kwargs):
        return materials[entry["source_key"]]

    monkeypatch.setattr(credential_selection, "_resolve", fake_resolve)
    picked = credentials._select_records([row("5", "pw", "d1", "password"),
                                          row("5", "nt", "d2", "ntlm")])
    assert picked["mode"] == "password" and picked["representation"] == "password"

    # 真正的两套凭据（两个账号）仍然报歧义 —— 放宽只针对"同一账号的两种表示"。
    other = dict(materials["pw"], user="someone_else")
    monkeypatch.setattr(credential_selection, "_resolve", lambda entry, **_k: (
        other if entry["source_key"] == "pw" else materials["nt"]))
    with pytest.raises(ValueError, match="^CREDENTIAL_AMBIGUOUS$"):
        credentials._select_records([row("5", "pw", "d1", "password"), row("5", "nt", "d2", "ntlm")])


def test_declared_roles_carries_identity_and_never_the_secret(tmp_path):
    """The verifier is told which account a graph role is; it is never handed the material."""
    path = tmp_path / "private" / "context.json"
    write_source(path)
    source = credentials.load_source(path)
    roles = credentials.declared_roles(source)
    assert roles == {"operator_role": {"user": "operator", "domain": "realm-a"}}
    assert "secret" not in json.dumps(roles)


def test_graph_symbols_links_the_credential_symbol_to_its_account():
    """`getAccount(h,user,symbol,p)` names both; the deployment declares the material once.

    walk-139 node 5: the dump showed WHOAMIANONY\\Administrator, the fact wanted
    lab_domain_credential, and the verifier could only answer UNKNOWN -- the link was in the
    graph all along.
    """
    linked = credentials.graph_symbols({"nodes": [
        {"id": "5", "description": "RULE 6 (OS Credential Dumping LSASS Memory - T1003.001)",
         "dependencies": [
             {"ref": "3", "description": "hasAccount(dc,domain_administrator,lab_domain_credential,system)"},
             {"ref": "36", "description": "hasAccount(pc1,domain_administrator,lab_domain_credential,system)"},
             {"description": "networkServiceInfo(pc1,lsass,tcp,80,admin)"}]},
        {"id": "49", "description": "RULE 9",
         "dependencies": [{"description": "getAccount(pc2,domain_administrator,lab_domain_credential,system)"}]}]})
    assert linked == {"domain_administrator": ["lab_domain_credential"]}
    assert credentials.graph_symbols({}) == {}
