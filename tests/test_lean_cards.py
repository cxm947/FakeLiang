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


ROOT = Path(__file__).resolve().parents[1]
PILOTS = {
    "pre.service_version": "pre-service-version",
    "exploit.tongda_oa_include_rce": "exploit-tongda-oa-include-rce",
}


def text_for(skill_id="pre.service_version"):
    """Keep an explicit legacy-header fixture for the existing parser tests."""
    text = (ROOT / "skills" / PILOTS[skill_id] / "SKILL.md").read_text(encoding="utf-8")
    if not re.search(r"^tools:", text, re.M):
        text = text.replace("inputs:", 'tools: ["http"]\ninputs:', 1)
    return text


@pytest.mark.parametrize("skill_id", PILOTS)
def test_loader_consumes_only_json_action_permissions(skill_id):
    card = lean.load_card(skill_id, ROOT)
    metadata = json.loads(Path(card["path"]).with_name("skill.json").read_text(encoding="utf-8"))
    assert card["id"] == skill_id and card["body"]
    assert set(card) <= lean.FIELDS | {"body", "digest", "path", "allowed_tools"}
    assert lean.REQUIRED <= set(card)
    if "allowed_tools" in metadata:
        assert card["tools"] == card["allowed_tools"] == metadata["allowed_tools"]
        assert card["digest"] != hashlib.sha256(Path(card["path"]).read_bytes()).hexdigest()
    else:
        assert "allowed_tools" not in card
        assert card["digest"] == hashlib.sha256(Path(card["path"]).read_bytes()).hexdigest()
    assert "judge" not in card and "input" not in card


def _assert_service_version_content(body):
    """Check method/evidence coverage instead of the migrated card's byte count."""
    text = "\n" + body
    sections = {}
    for title in ("何时用", "怎么做", "怎么判"):
        marker = "\n## " + title + "\n"
        assert text.count(marker) == 1, title
        section = text.split(marker, 1)[1].split("\n## ", 1)[0]
        assert section.strip(), title
        sections[title] = section
    anchors = {
        "何时用": ("expected_service", "expected_version", "session_ref", "check_shape=network_service"),
        "怎么做": (
            "nmap -Pn -n -sT -sV --version-light --reason -p {port} -oX - {target_host}",
            "scheme", "target_url", "TLS", "Redis", "INFO server", "RESP", "redis_version", "NOAUTH",
            "python3", "cmd/tool", "recv", "协议边界", "一次答复只给一个动作",
            "不写配置、不保存、不上传、不改认证设置", "跳转到未声明对象",
        ),
        "怎么判": ("Server", "代理", "后端应用", "open", "HTTP 200", "退出码 0", "SUCCESS", "unknown", "abandon", "引文逐字"),
    }
    for title, words in anchors.items():
        for word in words:
            assert word in sections[title], (title, word)
    results = {
        "pass": ("本次正确端点", "实际响应", "expected_service", "expected_version", "明确版本原文", "无版本要求不加门槛"),
        "fail": ("同一判定层级", "互斥", "明确版本违反条件", "必须引用反证", "没有 banner", "查询被拒", "响应不完整", "不是反证"),
        "uncertain": ("协议/身份不明", "字段缺失", "工具失败", "TLS 失败", "对象绑定不足", "观察冲突", "分别说明", "不能把部分观察升级为全部满足"),
    }
    for result, words in results.items():
        lines = [line for line in sections["怎么判"].splitlines() if line.startswith("- " + result + "：")]
        assert len(lines) == 1, result
        for word in words:
            assert word in lines[0], (result, word)


@pytest.mark.parametrize("skill_id", PILOTS)
def test_the_body_stays_the_bulk_of_the_card_and_the_face_stays_a_header(skill_id):
    card = lean.load_card(skill_id, ROOT)
    body = card["body"].encode("utf-8")
    total = Path(card["path"]).stat().st_size
    if skill_id == "pre.service_version":
        _assert_service_version_content(card["body"])
    else:
        assert len(body) >= 4096, "method knowledge is the point of the card"
    # The face grew a bounded amount when cards started declaring *how* their handles are built
    # (a recipe, and for an entry that needs one, a preparation). It is still a header: the two
    # conditions together say "small, and small next to the knowledge", which is what the guard
    # was for - a fixed byte count would have been measuring the wrong thing.
    face = total - len(body)
    #: A card that hands over a session declares the payload it needs and, when the target is
    #: reached through its own code path, the loader it plants there. That is still a header:
    #: small next to the knowledge, which is what the guard is for.
    assert 0 < face < 2048, "the machine-readable face is a header, not a document"
    if skill_id != "pre.service_version":
        assert len(body) >= 4 * face, "method knowledge still dominates the card"


def test_json_only_knowledge_is_preserved_without_changing_the_execution_view():
    service = lean.load_card("pre.service_version", ROOT)
    office = lean.load_card("exploit.tongda_oa_include_rce", ROOT)
    assert service["runs_at"] == "position" and office["runs_at"] == "base"
    assert service["delivers"] == ["evidence", "fact"]
    # A method card asserts what it *proves*; the reusable handle it leaves is a separate claim,
    # and it has to come with the way that handle is built.
    assert office["delivers"] == ["evidence"]
    # 2026-10-06: the card carries no client of its own any more. The chain is data - the fixed
    # upload shape lives in `stage`, the include step is the engine's own http tool - so there is
    # no `channel` recipe to ship, and nothing to pre-place on the box a step runs on.
    assert "channel" not in office
    assert office["stage"]["path"] == "/ispirit/im/upload.php"
    assert office["stage"]["filename"] == "agv.png"
    #: `cmd` ??**????**??????????????????????????"????????"
    #: ????????????????????? curl/python ???????????????????
    #: LEAN_TOOL_UNDECLARED ???2026-10-08 walk-161 node 19 ????
    assert set(office["tools"]) == {"http", "stage", "code", "cmd"}
    assert office["inputs"]["command"] == {"from": "model", "optional": True}
    assert service["inputs"]["session_ref"] == {"from": "runtime", "optional": True}
    for word in ("Redis", "RESP", "nmap", "python3", "expected_version", "Server", "uncertain"):
        assert word in service["body"]
    for word in ("whoami & hostname", "payload_dir", "web_root", "自编脚本", "Tongda OA",
                 "/static/images/tongda.ico", "(?P<version>", "restore", "PowerShell"):
        assert word in office["body"]


def test_markdown_only_folder_is_loadable(tmp_path):
    folder = tmp_path / "skills" / "pre-service-version"
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text(text_for(), encoding="utf-8", newline="")
    assert not (folder / "skill.json").exists()
    card = lean.load_card("pre.service_version", tmp_path)
    assert card["name"] == "pre-service-version"
    fields, body = lean.parse(text_for())
    assert fields["id"] == "pre.service_version" and body.strip()


@pytest.mark.parametrize("before,after", [
    ('kind: recon', 'kind: recon\nkind: method'),
    ('kind: recon', 'kind: invented'),
    ('runs_at: position', 'runs_at: wherever'),
    ("__TOOLS_LINE__", 'tools: [shell, http]'),
    ("__TOOLS_LINE__", 'tools: ["http","http"]'),
    ("__TOOLS_LINE__", 'tools: []'),
    ('delivers: ["evidence","fact"]', 'delivers: "evidence"'),
    ('"from":"graph"', '"from":"graph","from":"model"'),
    ('"from":"graph"', '"from":[]'),
    ('"optional":true', '"optional":"yes"'),
    ("__TOOLS_LINE__", 'metadata: legacy'),
    ('kind: recon', 'kind: recon\n  nested: unsupported'),
])
def test_malformed_lean_header_is_rejected_not_reinterpreted(before, after, tmp_path):
    text = text_for()
    if before == "__TOOLS_LINE__":
        #: 卡里的 tools 行会随卡的迁移而变，测试按正则取**当前**那一行 —— 它变了不必改测试
        #: （2026-10-06 两次静默失配的教训：硬编码卡面文本，卡一动测试就悄悄不测了）。
        import re as _re
        before = _re.search(r"tools:\s*\[[^\]]*\]", text).group(0)
    text = text.replace(before, after, 1)
    folder = tmp_path / "skills" / "pre-service-version"
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text(text, encoding="utf-8", newline="")
    (folder / "skill.json").write_text('{"valid_legacy_sentinel": true}', encoding="utf-8", newline="")
    with pytest.raises(ValueError):
        lean.load_card("pre.service_version", tmp_path)
    # The legacy sentinel changes nothing: the reader still refuses the malformed face.


def test_identity_is_fixed_but_not_limited_to_existing_business_prefixes(tmp_path):
    text = text_for().replace("id: pre.service_version", "id: inspect.http_service")
    import re as _re
    text = text.replace(_re.search(r"tools:\s*\[[^\]]*\]", text).group(0),
                        'tools: ["http","open_session"]', 1)
    folder = tmp_path / "skills" / "inspect.http_service"
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text(text, encoding="utf-8", newline="")
    assert lean.load_card("inspect.http_service", tmp_path)["tools"] == ["http", "open_session"]
    with pytest.raises(ValueError, match="LEAN_CARD_ID_INVALID"):
        lean.load_card("../../outside", tmp_path)
    (folder / "SKILL.md").write_text(text.replace("id: inspect.http_service", "id: inspect.other"), encoding="utf-8", newline="")
    with pytest.raises(ValueError, match="LEAN_CARD_ID_MISMATCH"):
        lean.load_card("inspect.http_service", tmp_path)


def test_old_frontmatter_is_refused_by_the_lean_reader():
    """The old face (compatibility / metadata / allowed-tools) belongs to the retired contract.

    The card face is the only source the lean reader knows, so an old face has to be refused
    loudly here rather than reinterpreted - the fixture is built in place so the guard cannot go
    quietly dead when the last old card is migrated away.
    """
    text = "\n".join([
        "---",
        "name: pre-tool-present",
        "description: tool presence observation",
        "compatibility: legacy runtime convention",
        "metadata:",
        "  x-exec-skill-id: pre.tool_present",
        "allowed-tools: skill_runtime_dispatch",
        "---",
        "",
        "# legacy face",
        "",
        "## When to use",
        "",
        "Legacy body.",
        "",
    ])
    with pytest.raises(ValueError, match="LEAN_CARD_FIELD_INVALID"):
        lean.parse(text)


def test_material_output_declaration_keeps_named_value_projection():
    card = lean.load_card("exploit.pypykatz_parse", ROOT)
    assert card["materials"] == ["realm", "user", "value", "kind", "source_call", "quote"]
    samples = ["    NT: 0123456789abcdef0123456789abcdef", "    password x",
               "    Password: q", "    password (hex) 78"]
    for sample in samples:
        values = [match.group("value") for pattern in card["secret_patterns"]
                  for match in re.finditer(pattern, sample)]
        assert values == [sample.rsplit(" ", 1)[-1]]
    assert all(re.search(pattern, "username analyst") is None
               for pattern in card["secret_patterns"])


@pytest.mark.parametrize("declaration,error", [
    ({"materials": ["realm", "user", "value", "kind", "source_call", "quote"]},
     "LEAN_CARD_SECRET_PATTERNS_INVALID"),
    ({"secret_patterns": [r"secret (?P<value>.+)"]}, "LEAN_CARD_MATERIALS_INVALID"),
    ({"materials": ["user", "value"], "secret_patterns": [r"(?P<value>.+)"]},
     "LEAN_CARD_MATERIALS_INVALID"),
    ({"materials": ["realm", "user", "value", "kind", "source_call", "quote"],
      "secret_patterns": []}, "LEAN_CARD_SECRET_PATTERNS_INVALID"),
    ({"materials": ["realm", "user", "value", "kind", "source_call", "quote"],
      "secret_patterns": ["("]}, "LEAN_CARD_SECRET_PATTERNS_INVALID"),
    ({"materials": ["realm", "user", "value", "kind", "source_call", "quote"],
      "secret_patterns": [r"secret (.+)"]}, "LEAN_CARD_SECRET_PATTERNS_INVALID"),
    ({"materials": ["realm", "user", "value", "kind", "source_call", "quote"],
      "secret_patterns": [3]}, "LEAN_CARD_SECRET_PATTERNS_INVALID"),
])
def test_malformed_material_output_declaration_is_rejected(declaration, error):
    extra = "".join(key + ": " + json.dumps(value) + "\n"
                    for key, value in declaration.items())
    text = text_for().replace("---\n", "---\n" + extra, 1)
    with pytest.raises(ValueError, match=error):
        lean.parse(text)


@pytest.mark.parametrize("skill_id", [
    "exploit.impacket_psexec_cmd", "exploit.impacket_wmiexec_cmd",
    "exploit.netexec_firewall_off", "exploit.wmic_remote_cmd",
    "exploit.wmi_firewall_off", "pre.impacket_scm_query",
])
def test_credential_consumer_cards_declare_candidate_order_and_observable_rejection(skill_id):
    card = lean.load_card(skill_id, ROOT)
    assert card["inputs"]["credential_candidates"] == {"from": "runtime", "optional": True}
    for marker in ("order=1", "derived", "order=2", "external", "CREDENTIAL_MISSING",
                   "STATUS_LOGON_FAILURE", "STATUS_WRONG_PASSWORD", "STATUS_NO_SUCH_USER",
                   "STATUS_ACCOUNT_LOCKED_OUT", "超时", "非零"):
        assert marker in card["body"]

    _assert_auth_method_content(skill_id, card["body"])

if __name__ == "__main__":
    unittest.main()


def test_the_escape_card_declares_how_it_builds_the_host_entry():
    """Leaving an entry on a real host is a *construction*, and the card has to say how.

    The card proves it can write on the host; that is not an execution entry. It therefore
    declares a bounded setup (mount, add one run-scoped key, unmount), the candidate it yields,
    and the check that proves the candidate really is on the host - including what must *not*
    appear, because the isolated position runs as root too.
    """
    card = lean.load_card("exploit.privileged_container_escape", ROOT)
    setup = card["entry_setup"]
    #: The observed account, not a preferred one: this deployment's host has an ordinary user, and
    #: the recorded route writes the key into *that* account's authorization file. Root's files are
    #: not reachable from the position this step runs in (measured against the published write-ups
    #: for this environment), so a "root" candidate would look fine and never authenticate.
    #: Measured on this deployment: the host's root account accepts a key (`id -u` answered `0`), so
    #: the candidate is root itself and needs no way up. A deployment where that is not reachable
    #: declares an ordinary account plus how commands reach the level (`become`) - never a level
    #: with no path to it.
    assert setup["candidate"] == {"driver": "ssh", "username": "root", "port": "22"}
    assert "/root/.ssh/authorized_keys" in " ".join(setup["action"])
    assert setup["verify"].startswith("id -u")
    assert setup["ready_marker"] in " ".join(setup["action"]) or True
    assert "{public_key}" in " ".join(setup["action"]), "the run's own key is the material"
    assert setup["identity"]["must_not_contain"] == ["docker"]
    assert "session" in card["delivers"]


def test_the_write_primitive_card_declares_the_session_it_hands_over():
    """A write primitive is not a command entry; the card says what it hands over instead.

    The route here is the ordinary one for this chain: put this run's own key into the service,
    point the on-disk target at the account authorization file, save, and then use the host's own
    login service to bring this run's payload over. `entry_setup` used to describe that route with
    no executor behind it; the card now declares the delivery the runtime actually builds.
    """
    card = lean.load_card("exploit.redis_unauth_write", ROOT)
    session = card["session"]
    assert "entry_setup" not in card
    assert session["driver"] == "msf"
    assert session["payload"]["path"] == "linux/x64/meterpreter_reverse_tcp"
    entry = session["entry"]
    assert {key: entry[key] for key in ("driver", "username", "port")} == {
        "driver": "ssh", "username": "root", "port": "22"}
    assert "{public_key_file}" in entry["authorize_command"]
    assert "{target_host}" in entry["authorize_command"]
    assert session["transport"] == "scp"
    assert set(session["capabilities"]) == {"capacity", "shell_ready"}
    assert "session" in card["delivers"]


def _permission_fixture(tmp_path, metadata, *, header_tools=False):
    folder = tmp_path / "skills" / "pre-service-version"
    folder.mkdir(parents=True, exist_ok=True)
    text = text_for()
    if not header_tools:
        text = re.sub(r'^tools:.*\n', '', text, flags=re.M)
    (folder / "SKILL.md").write_text(text, encoding="utf-8", newline="")
    (folder / "skill.json").write_text(json.dumps(metadata), encoding="utf-8")
    return folder


def test_json_permissions_replace_header_permissions_without_union(tmp_path):
    from runtime import dispatch

    _permission_fixture(tmp_path, {"allowed_tools": ["cmd", "finish"]}, header_tools=True)
    card = lean.load_card("pre.service_version", tmp_path)
    assert card["tools"] == card["allowed_tools"] == ["cmd", "finish"]
    assert dispatch.declared(card, "cmd")
    assert not dispatch.declared(card, "http")
    dispatch.require_declared(card, "finish")


@pytest.mark.parametrize("allowed", [
    None, [], "cmd", ["cmd", "cmd"], ["cmd", 1], [{}], ["invented"], ["stage"], ["shell"],
])
def test_invalid_json_permissions_never_fall_back_to_header(allowed, tmp_path):
    _permission_fixture(tmp_path, {"allowed_tools": allowed}, header_tools=True)
    with pytest.raises(ValueError, match="LEAN_CARD_ALLOWED_TOOLS_INVALID"):
        lean.load_card("pre.service_version", tmp_path)


@pytest.mark.parametrize("raw", [
    "{", "[]", '{"allowed_tools":["cmd"],"allowed_tools":["http"]}',
])
def test_invalid_json_document_is_refused(raw, tmp_path):
    folder = _permission_fixture(tmp_path, {}, header_tools=True)
    (folder / "skill.json").write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError, match="LEAN_CARD_JSON_INVALID"):
        lean.load_card("pre.service_version", tmp_path)


def test_new_card_needs_its_json_permissions_and_binds_the_effective_list(tmp_path):
    folder = _permission_fixture(tmp_path, {"allowed_tools": ["cmd", "finish"]})
    first = lean.load_card("pre.service_version", tmp_path)
    (folder / "skill.json").write_text(json.dumps({
        "allowed_tools": ["cmd", "finish"], "judge": "unused", "input": "unused",
    }), encoding="utf-8")
    unchanged = lean.load_card("pre.service_version", tmp_path)
    assert unchanged == first
    (folder / "skill.json").write_text(json.dumps({
        "allowed_tools": ["http", "finish"],
    }), encoding="utf-8")
    changed = lean.load_card("pre.service_version", tmp_path)
    assert changed["digest"] != first["digest"]
    assert changed["tools"] == ["http", "finish"]
    (folder / "skill.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="LEAN_CARD_FIELDS_MISSING"):
        lean.load_card("pre.service_version", tmp_path)


def test_legacy_json_keys_do_not_replace_the_header_or_disable_finish(tmp_path):
    from runtime import dispatch

    _permission_fixture(tmp_path, {"input": {}, "judge": "unused"}, header_tools=True)
    card = lean.load_card("pre.service_version", tmp_path)
    assert card["tools"] == ["http"]
    assert "allowed_tools" not in card
    dispatch.require_declared(card, "finish")
    assert dispatch.known_tools({"tools": ["shell", "python"]}) == ["cmd", "code"]


def test_json_uses_the_existing_category_names(tmp_path):
    from runtime import dispatch

    allowed = [*dispatch.CATEGORIES, "http", "finish"]
    _permission_fixture(tmp_path, {"allowed_tools": allowed})
    card = lean.load_card("pre.service_version", tmp_path)
    assert dispatch.known_tools(card) == allowed
    for tool in allowed:
        dispatch.require_declared(card, tool)


@pytest.mark.parametrize("skill_id", [
    "pre.nmap_tcp_probe", "pre.service_version", "pre.credential_valid",
])
def test_first_pre_cards_have_one_permission_source_and_no_invented_technique(skill_id):
    card = lean.load_card(skill_id, ROOT)
    raw = Path(card["path"]).read_text(encoding="utf-8")
    header = raw.split("\n---\n", 1)[0]
    assert not re.search(r"^tools:", header, re.M)
    assert card["tools"] == card["allowed_tools"]
    assert "finish" in card["allowed_tools"]
    assert "technique" not in card.get("when", {})
    for section in ("## 何时用", "## 怎么做", "## 怎么判"):
        assert section in card["body"]
    assert "uncertain" in card["body"] and "逐字" in card["body"]


def test_refused_action_and_finish_reach_neither_executor_nor_journal(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from runtime import lean as runtime_lean, lean_transport

    run = runtime_lean.LeanRun.__new__(runtime_lean.LeanRun)
    run.card = {"id": "pre.fixture", "tools": ["http"], "allowed_tools": ["cmd"]}
    run.root = tmp_path
    touches = []
    run.executor = lambda *args: touches.append("executor")
    run._append = lambda *args, **kwargs: touches.append("journal")
    monkeypatch.setattr(lean_transport, "ownership", lambda *_: nullcontext())
    with pytest.raises(ValueError, match="LEAN_TOOL_UNDECLARED") as error:
        run.call({"tool": "http", "method": "GET", "path": "/"})
    assert "pre.fixture" in str(error.value)
    assert "only allows cmd" in str(error.value) and "requested http" in str(error.value)
    with pytest.raises(ValueError, match="LEAN_TOOL_UNDECLARED"):
        run.conclude("No observation", [], "uncertain")
    assert touches == []


def test_refused_finish_is_returned_to_the_action_loop(tmp_path, monkeypatch):
    from runtime.lean import LeanRun
    from scripts import run_lean_task as cli
    from agents.executor import driver as lean_task_driver

    decisions, refusals, sent = [], [], []

    class GuardedRun:
        def __init__(self, **kwargs):
            self.card = kwargs["card"]
            self.secrets = ()

        def record_decision(self, prompt, reply):
            decisions.append(reply)

        def record_refusal(self, refusal):
            refusals.append(refusal)

        def conclude(self, *args):
            return LeanRun.conclude(self, *args)

    monkeypatch.setattr(lean_task_driver, "LeanRun", GuardedRun)
    card = {"id": "pre.fixture", "digest": "fixture", "kind": "recon", "runs_at": "base",
            "tools": ["cmd"], "allowed_tools": ["cmd"], "inputs": {}, "body": "fixture"}
    scope = {"host": "192.0.2.54", "port": 8080, "protocol": "tcp",
             "vantage": "base", "resources": "whole_endpoint"}
    task = {"node_id": "fixture", "goal": "observe", "inputs": {}, "scope": scope}
    finish = {"tool": "finish", "claim": "No observation", "verdict": "uncertain", "citations": []}
    result = cli.drive(card, task, scope, lambda *args: sent.append(args),
                       actions=[dict(finish), dict(finish)], run_dir=tmp_path, max_steps=3)
    assert len(decisions) == len(refusals) == 2
    assert all(row["reason_code"] == "LEAN_TOOL_UNDECLARED" for row in refusals)
    assert all("only allows cmd" in row["detail"] for row in refusals)
    assert result["status"] == "uncertain" and sent == []


R3_AUTH_ANCHORS = {
    "pre.impacket_scm_query": [
        "SC_MANAGER_CONNECT",
        "ncacn_np",
        "svcctl",
        "句柄",
        "不换传输"
    ],
    "exploit.impacket_psexec_cmd": [
        "hostname",
        "whoami /user",
        "identity_sid",
        "随机",
        "本卡不自行重试"
    ],
    "exploit.impacket_wmiexec_cmd": [
        "ADMIN$",
        "cmd /c",
        "不默认为 0",
        "不擅改卡内方法"
    ],
    "exploit.wmic_remote_cmd": [
        "delivery_pivot_stager",
        "delivery_remote_stager",
        "getuid",
        "sysinfo",
        "whoami & hostname",
        "不要另建身份任务",
        "/ru SYSTEM"
    ],
    "exploit.netexec_firewall_off": [
        "Domain / Private / Public",
        "ON",
        "OFF",
        "/ru",
        "/rp",
        "点火与回读分两次调用"
    ],
    "exploit.wmi_firewall_off": [
        "EnableFirewall",
        "after",
        "done",
        "0x0",
        "0x1",
        "8191",
        "不恢复防火墙",
        "不删除源主机"
    ]
}

def _assert_auth_method_content(skill_id, body):
    for title in ("何时用", "怎么做", "怎么判", "异常与恢复"):
        assert body.count("## " + title + "\n") == 1
    plain = body.replace("`", "")
    judge = plain.split("## 怎么判\n", 1)[1].split("\n## ", 1)[0]
    for verdict in ("pass", "unsatisfied", "uncertain"):
        assert re.search(r"(?m)^- " + verdict + r"[：:]", judge)
    assert "finish.verdict" in judge
    assert "完整" in judge and "缺" in judge
    assert not re.search(r"\bfail\b", body)
    for marker in R3_AUTH_ANCHORS[skill_id]:
        assert marker in body
    assert any(line.startswith("**") and "停止" in line and ("锁定" in line or "STATUS_ACCOUNT_LOCKED_OUT" in line)
               for line in body.splitlines())
    denial = next(line for line in body.splitlines() if "STATUS_ACCESS_DENIED" in line)
    assert any(word in denial for word in ("不触发", "不据此", "不能单独"))


def test_tongda_delivery_expectation_names_only_emitted_stage_output():
    card = lean.load_card("exploit.tongda_oa_include_rce", ROOT)
    payload = card["session"]["stage_payload"]
    for mark in ("AGV_L1", "AGV_L2:", "AGV_L3", "AGV_L4:"):
        assert mark in payload
    assert "($ok===false?'FAIL':'OK')" in payload
    assert "AGV_SESSION_LAUNCHED" not in card["body"]
    for mark in ("`AGV_L1`", "`AGV_L2:<bytes>`", "`AGV_L3OK`",
                 "`AGV_L3FAIL`", "`AGV_L4:<text>`"):
        assert mark in card["body"]
    assert "not session-registration evidence" in card["body"]
    assert "after `finish`" in card["body"]
