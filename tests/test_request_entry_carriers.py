"""Offline contracts for explicit console actions, bindings, and observed registration."""
import re
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from runtime import dispatch  # noqa: E402

from orchestration import evidence  # noqa: E402

from orchestration import positions  # noqa: E402

from orchestration import preparation  # noqa: E402

from graph import rehydrate  # noqa: E402

from orchestration import reporting  # noqa: E402

from orchestration import session_flow  # noqa: E402

from runtime import session_registry  # noqa: E402

from tests.test_request_carriers import ROOT, row
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from runtime import channels, dispatch, lean, session_registry
from runtime.runner import ExecOutcome
import run_node
import run_plan
from runtime import session_registry
from tests.graph_fixtures import loaded_graph


WEB_RECIPE = {"kind": "asset_command", "asset": "/srv/app/entry.php",
              "url_args": ["-q", "http://192.0.2.7/entry.php?token=fixture"],
              "command_flag": "-d", "platform": "linux"}


def test_a_web_position_takes_a_command_and_refuses_anything_else():
    """One web entry recipe carries one command line; a structured request or a foreign tool is refused."""
    binding = row(session_type="web", recipe=dict(WEB_RECIPE))
    action = dispatch.bind_console({"tool": "cmd", "cmd": "id"}, binding, marker="m")
    assert action["operation"] == "asset" and action["recipe"] == WEB_RECIPE
    assert action["text"] == "id" and action["completion"] == {"marker": "m"}
    for bad, name in (({"tool": "http", "method": "GET", "path": "/"}, "LEAN_WEB_COMMAND_ONLY"),
                      ("not-an-object", "LEAN_REQUEST_INVALID")):
        with pytest.raises(ValueError, match=name):
            dispatch.bind_console(bad, binding, marker="m")
    with pytest.raises(ValueError, match="LEAN_WEB_RECIPE_MISSING"):
        dispatch.bind_console({"tool": "cmd", "cmd": "id"}, row(session_type="web"), marker="m")


def test_the_web_entry_argv_runs_one_framed_command_through_the_named_client():
    """The entry client receives the command as its own argument, framed by the engine's marker."""
    from runtime import lean_web

    argv = lean_web.command_argv(dict(WEB_RECIPE), "id -u", "agvmark", python="python3")
    assert argv[:4] == ["python3", "/srv/app/entry.php", "-q",
                        "http://192.0.2.7/entry.php?token=fixture"]
    assert argv[4] == "-d" and "agvmark" in argv[5] and "id -u" in argv[5]
    #: 命令必须是**一条给 shell 的命令行**，不是装着参数表的元组（walk-155 node 26 真机：
    #: 元组字面量到了目标上，每条命令都 127）。
    assert "/bin/sh -c 'id -u'" in argv[5]
    with pytest.raises(ValueError, match="LEAN_WEB_RECIPE_INVALID"):
        lean_web.command_argv(dict(WEB_RECIPE, asset="relative/entry.php"), "id", "m")
    with pytest.raises(ValueError, match="LEAN_WEB_RECIPE_MISSING"):
        lean_web.command_argv({"kind": "http"}, "id", "m")


POSITION_CARD = {"id": "method.fixture", "provides_position": {
    "kind": "web", "recipe": {"kind": "asset_command", "asset": "/tmp/agv-tools/x/poc.py",
                              "url_args": ["-u", "http://{host}:{port}/", "--flag", "fixed"],
                              "command_flag": "-c", "platform": "linux"}}}


SSH_RECIPE = {"kind": "argv_command", "platform": "linux",
              "argv": ["/usr/bin/ssh", "-i", "/run/entry-key", "-o", "BatchMode=yes", "-p", "22",
                       "root@192.0.2.20"], "command_flag": ""}


def test_an_entry_recipe_that_is_an_argv_appends_the_command_line():
    """An ssh entry is the same idea as a web one: the command is the last argument it sends."""
    from runtime import lean_web

    argv = lean_web.command_argv(dict(SSH_RECIPE), "id -u", "agvmark")
    assert argv[0] == "/usr/bin/ssh" and argv[-2] == "root@192.0.2.20"
    assert "id -u" in argv[-1] and "agvmark" in argv[-1]
    with pytest.raises(ValueError, match="LEAN_WEB_RECIPE_INVALID"):
        lean_web.command_argv(dict(SSH_RECIPE, argv=[]), "id", "m")
    binding = row(session_type="entry", position_kind="ssh", recipe=dict(SSH_RECIPE))
    action = dispatch.bind_console({"tool": "cmd", "cmd": "id"}, binding, marker="m")
    assert action["operation"] == "asset" and action["recipe"]["kind"] == "argv_command"


def test_an_entry_position_call_is_rebuilt_the_way_the_lane_sent_it():
    """The ledger row for an entry position is the control-end argv, and the checker rebuilds that

    (walk-157 node 26: every command ran and the receipt carried root evidence, but the checker
    rebuilt a console three-part line, rejected all four rows, and the step was reported as having
    no evidence at all).
    """
    from runtime import lean_web
    from runtime.redact import redact_argv

    binding = row(session_type="entry", position_kind="web", recipe=dict(WEB_RECIPE))
    manifest = {"binding": {"session": binding, "python": "python3"}}
    request = {"tool": "cmd", "cmd": "id -u"}
    marker = "agvmark"
    action = dispatch.bind_console(request, binding, marker=marker)
    #: 账本里存的是**脱敏后**的那条 argv（这一发正好带一个像令牌的查询串）。
    argv = redact_argv(lean_web.command_argv(action["recipe"], action["text"], marker))
    assert evidence._receipt_request_matches({"argv": argv}, request, marker, manifest)
    assert not evidence._receipt_request_matches(
        {"argv": ["console", action["operation"], action["text"]]}, request, marker, manifest)


def test_an_identifier_survives_masking_so_a_rerun_can_name_it():
    """An identifier is not a credential: the id the model is told to quote back stays whole.

    A call id ends in 32 hex characters, which the NTLM shape rule masked, so every "this
    request already ran" refusal handed the model a *truncated* id. `retry_of` could never
    match it, which made the one sanctioned way to re-run a settled call dead on arrival -
    109 such refusals in the history and exactly zero model-declared reruns (measured
    2026-10-09). The shape rules themselves are unchanged for actual material.
    """
    from runtime.redact import redact_text

    call_id = "call-20261008T135645-e8cfef-2ac14a493eb1407f8835b615085748cd"
    channel = "session-1b7df72e299296e684187b121dfda5e75d8556b028432a78b025555ccc9cf2f8"
    text = "already ran as %s via %s (pw=hunter2)" % (call_id, channel)
    masked = redact_text(text, ["hunter2"])
    assert call_id in masked, masked
    assert channel in masked, masked
    assert "hunter2" not in masked and "<redacted>" in masked, masked
    assert redact_text("digest 2ac14a493eb1407f8835b615085748cd") == "digest <redacted>"


def test_a_declared_position_is_frozen_with_the_deployment_address(tmp_path):
    """The step that plants the entry names where it is; later steps re-observe, never re-plant."""
    document = loaded_graph([("28", "RULE 4 (fixture action)", "AND"),
                             ("29", "execCode(web2_docker,www_data)", "OR")], [("28", "29")])
    row = positions.register_declared_position(
        card=deepcopy(POSITION_CARD), node_id="28", document=document,
        host_map={"web2_docker": "192.0.2.54"}, scope={"host": "192.0.2.54", "port": 81},
        root=tmp_path)
    assert row["session_type"] == "entry" and row["logical"] == "web2_docker"
    assert row["host"] == "192.0.2.54" and row["observation"]["state"] == "unknown"
    assert row["recipe"]["url_args"] == ["-u", "http://192.0.2.54:81/", "--flag", "fixed"]
    assert positions.register_declared_position(card={"id": "x"}, node_id="28", document=document,
                                               root=tmp_path) is None


def test_a_web_position_is_offered_to_the_step_that_needs_that_host():
    """A row without a console endpoint is still a position once its host is the required one."""
    document = loaded_graph([("26", "RULE 19 (fixture action)", "AND"),
                             ("27", "execCode(web2_docker,www_data)", "OR")], [("27", "26")])
    node = next(item for item in document["nodes"] if item["id"] == "26")
    web = {"channel_id": "web-1", "kind": "console_session", "session_type": "web",
           "logical": "web2_docker", "host": "192.0.2.54", "lifecycle": "registered",
           "observation": {"state": "unknown"},
           "recipe": {"kind": "asset_command", "asset": "/tmp/x.py", "url_args": ["-u"],
                      "command_flag": "-c", "platform": "linux"}}
    found = positions.channel_candidates(document, node, [web],
                                        host_map={"web2_docker": "192.0.2.54"})
    assert [item[0]["channel_id"] for item in found] == ["web-1"]
    assert found[0][1] == "declared web position"
    assert positions.channel_candidates(document, node, [dict(web, recipe={})],
                                       host_map={"web2_docker": "192.0.2.54"}) == []


ENTRY_CARD = {"id": "method.fixture", "entry_setup": {
    "action": ["/bin/sh", "-c", "mount /dev/sda1 /mnt/host && echo {public_key} >> "
                               "/mnt/host/root/.ssh/authorized_keys; echo AGV_ENTRY_READY"],
    "ready_marker": "AGV_ENTRY_READY",
    "candidate": {"driver": "ssh", "username": "root", "port": "22"},
    "verify": "id -u; hostname; grep -o docker /proc/1/cgroup | head -1",
    "identity": {"uid": "0", "must_not_contain": ["docker"]},
    "cleanup": ["/bin/sh", "-c", "umount /mnt/host"]}}


def entry_executor(seen, *, verify_body):
    """Stand in for the control end: it writes the run's key and answers each framed call."""
    from runtime.runner import ExecOutcome

    def executor(argv, timeout):
        seen.append(list(argv))
        if argv[0] == "/bin/sh" and "ssh-keygen" in str(argv[-1]):
            #: 控制端一次性建键并回读公钥（与既有交付同一约定），所以这里只回内容。
            assert "mkdir -p /tmp/agv-materials" in str(argv[-1])
            #: ?????????? sshd ? ssh-rsa(SHA-1)??? ed25519?2026-10-08 ????
            assert "-t ed25519" in str(argv[-1]) and "agv-entry-" in str(argv[-1])
            return ExecOutcome(0, "ssh-ed25519 AAAAGV run@agv\n")
        marker = re.search(r"(agv[0-9a-z]+)start", str(argv[-1])).group(1)
        body = verify_body if "ssh" in str(argv[0]) and "/bin/sh" not in str(argv[0]) \
            else "AGV_ENTRY_READY\n"
        return ExecOutcome(0, "%sstart\n%s\n%send 0\n" % (marker, body, marker),
                           read_stop="end_marker")

    return executor


def entry_document():
    return loaded_graph([("22", "RULE 20 (fixture action)", "AND"),
                         ("21", "execCode(web2,root)", "OR")], [("22", "21")])


def test_a_card_that_builds_its_own_entry_registers_it_only_after_it_answers(tmp_path):
    """The run authorises itself, runs the card's action through the position it owns, then proves
    the new entry through itself -- ssh, as the account and identity the card names."""
    seen = []
    carrier = row(session_type="entry", position_kind="web", recipe=dict(WEB_RECIPE))
    result = positions.build_entry_position(
        card=deepcopy(ENTRY_CARD), node_id="22", document=entry_document(),
        host_map={"web2": "192.0.2.20"}, root=tmp_path, carrier=carrier,
        executor=entry_executor(seen, verify_body="0\nweb2\n"))
    assert result["state"] == "registered" and result["host"] == "192.0.2.20"
    #: 卡里的动作是**运行层**跑出去的，而且用的是运行层自己的公钥（不是模型编的一行）。
    action_call = next(item for item in seen if item[0] == "python3")
    assert "AAAAGV" in action_call[-1]
    assert "/mnt/host/root/.ssh/authorized_keys" in action_call[-1]
    stored = [item for item in session_registry.snapshot(tmp_path)
              if item.get("position_kind") == "ssh"]
    assert stored[0]["session_type"] == "entry" and stored[0]["logical"] == "web2"
    #: ?? ssh ??? root ?????? uid 0??????????? root ??????????
    assert stored[0]["privilege"] == "root"
    assert stored[0]["recipe"]["kind"] == "argv_command"
    assert stored[0]["recipe"]["argv"][2].startswith("/tmp/agv-materials/agv_entry_")
    #: 身份证据是**正面**的：回答来自"连到这台主机这条连接"，不是"没看到容器标记"。
    assert result["connection"] == {"host": "192.0.2.20", "port": "22", "account": "root",
                                    "via": "entry ssh"}
    #: The engine keeps no end-of-round cleanup ledger any more: the durable facts of this step
    #: are the registered entry (above) and the observation below; the lab snapshot rolls back.
    observed = session_registry.observations(tmp_path)
    assert [item["environment"] for item in observed] == ["host"]
    assert observed[0]["identity"]["observed"] == "0\nweb2"


def test_an_entry_identity_can_require_a_positive_marker(tmp_path):
    """A card may name what must be *seen* (not only what must not); a miss refuses the entry."""
    seen = []
    carrier = row(session_type="entry", position_kind="web", recipe=dict(WEB_RECIPE))
    strict = deepcopy(ENTRY_CARD)
    strict["entry_setup"]["identity"] = {"uid": "0", "must_contain": ["web2"]}
    result = positions.build_entry_position(
        card=strict, node_id="22", document=entry_document(), host_map={"web2": "192.0.2.20"},
        root=tmp_path / "ok", carrier=carrier,
        executor=entry_executor(seen, verify_body="0\nweb2\n"))
    assert result["state"] == "registered"
    result = positions.build_entry_position(
        card=deepcopy(strict), node_id="22", document=entry_document(),
        host_map={"web2": "192.0.2.20"}, root=tmp_path / "miss", carrier=carrier,
        executor=entry_executor(seen, verify_body="0\nsomewhere-else\n"))
    assert result["state"] == "failed" and result["reason"] == "ENTRY_SETUP_IDENTITY_UNCONFIRMED"


def test_an_entry_that_answers_from_the_wrong_side_is_not_registered(tmp_path):
    """The same verify command answering from inside the container is refused, and nothing is kept."""
    seen = []
    carrier = row(session_type="entry", position_kind="web", recipe=dict(WEB_RECIPE))
    result = positions.build_entry_position(
        card=deepcopy(ENTRY_CARD), node_id="22", document=entry_document(),
        host_map={"web2": "192.0.2.20"}, root=tmp_path / "run", carrier=carrier,
        executor=entry_executor(seen, verify_body="33\nweb2_docker\ndocker\n"))
    assert result["state"] == "failed" and result["reason"] == "ENTRY_SETUP_IDENTITY_UNCONFIRMED"
    assert result["cleanup"] == ["/bin/sh", "-c", "umount /mnt/host"]
    assert [item for item in session_registry.snapshot(tmp_path / "run")
            if item.get("position_kind") == "ssh"] == []


def test_two_entries_on_one_host_are_told_apart_by_the_privilege_the_premise_names():
    """A position step has no endpoint of its own: the port its recipe needs is a graph fact."""
    """Privilege belongs to the execution context: a step whose premise says root is not asked to
    pick between the container's web account and the root entry on the same address."""
    document = loaded_graph([("22", "RULE 20 (fixture action)", "AND"),
                             ("21", "execCode(web2,root)", "OR")], [("21", "22")])
    node = next(item for item in document["nodes"] if item["id"] == "22")

    def entry(channel_id, privilege):
        return {"channel_id": channel_id, "kind": "console_session", "session_type": "entry",
                "position_kind": "web", "logical": "web2", "host": "192.0.2.20",
                "privilege": privilege, "lifecycle": "registered",
                "observation": {"state": "unknown"},
                "recipe": {"kind": "asset_command", "asset": "/tmp/x.py", "url_args": ["-u"],
                           "command_flag": "-c", "platform": "linux"}}

    rows = [entry("web-www", "www_data"), entry("web-root", "root")]
    found = positions.channel_candidates(document, node, rows, host_map={"web2": "192.0.2.20"})
    assert [item[0]["channel_id"] for item in found] == ["web-root"]


def test_a_position_without_an_endpoint_reads_its_port_from_the_plan(tmp_path):
    """The recipe may need the service port; that number is a graph fact, so it is read, not guessed."""
    import project_graph
    from graph import rehydrate

    inputs = ROOT / "data" / "inputs" / "hongri7"
    assert project_graph.main([str(inputs / "Hongri7_v2.txt"), "--output-dir", str(tmp_path),
                               "--host-map", str(inputs / "host_ip_map.csv"),
                               "--assets", str(inputs / "assets.json"),
                               "--json-only", "--force"]) == 0
    view = rehydrate.load_file(tmp_path / "json" / "Hongri7_v2.action_graph.json")
    #: 这份计划把容器里的那个 web 服务记在 81 上；位置步骤的 scope 里没有端口，所以从图里读。
    assert positions.graph_service_port(view, "web2_docker") == "81"
    assert positions.graph_service_port(view, "nowhere") == ""


def test_a_cards_own_tool_path_is_answered_when_the_shape_is_unambiguous():
    """One placed tool and one empty path-shaped config input: bind it, do not make the step hunt."""
    card = {"inputs": {"target_url": {"from": "model"}, "command": {"from": "runtime",
                                                                    "optional": True},
                       "poc_path": {"from": "config", "type": "path", "optional": True}}}
    task = {"inputs": {"target_url": "http://192.0.2.7:81/"}}
    assert preparation.bind_config_paths(card, task, ["/tmp/agv-tools/x/poc.py"]) == {
        "poc_path": "/tmp/agv-tools/x/poc.py"}
    #: ????????????????????????
    assert preparation.bind_config_paths(card, task, ["/a.py", "/b.py"]) == {}
    assert preparation.bind_config_paths(card, {"inputs": {"poc_path": "/already.py"}},
                                      ["/a.py"]) == {}
    assert preparation.bind_config_paths({"inputs": {}}, task, ["/a.py"]) == {}


def test_a_declared_privilege_is_shown_or_the_position_is_refused(tmp_path):
    """A position that declares root is asked who it runs as; a different answer refuses it."""
    seen = []
    carrier = row(session_type="entry", position_kind="web", recipe=dict(WEB_RECIPE))
    card = deepcopy(POSITION_CARD)
    card["provides_position"]["privilege"] = "root"

    def executor(argv, timeout):
        seen.append(list(argv))
        marker = re.search(r"(agv[0-9a-z]+)start", str(argv[-1])).group(1)
        return ExecOutcome(0, "%sstart\n33\nwww-data\n%send 0\n" % (marker, marker),
                           read_stop="end_marker")

    refused = positions.register_declared_position(
        card=card, node_id="28", document=loaded_graph(
            [("28", "RULE 4 (fixture action)", "AND"),
             ("29", "execCode(web2_docker,www_data)", "OR")], [("28", "29")]),
        host_map={"web2_docker": "192.0.2.54"}, scope={"host": "192.0.2.54", "port": 81},
        root=tmp_path / "no", executor=executor)
    assert refused["state"] == "failed" and refused["reason"].startswith(
        "POSITION_PRIVILEGE_MISMATCH")

    def root_executor(argv, timeout):
        marker = re.search(r"(agv[0-9a-z]+)start", str(argv[-1])).group(1)
        return ExecOutcome(0, "%sstart\n0\nroot\n%send 0\n" % (marker, marker),
                           read_stop="end_marker")

    kept = positions.register_declared_position(
        card=deepcopy(card), node_id="28", document=loaded_graph(
            [("28", "RULE 4 (fixture action)", "AND"),
             ("29", "execCode(web2_docker,www_data)", "OR")], [("28", "29")]),
        host_map={"web2_docker": "192.0.2.54"}, scope={"host": "192.0.2.54", "port": 81},
        root=tmp_path / "yes", executor=root_executor)
    assert kept["privilege"] == "root" and kept["session_type"] == "entry"


def test_a_recipe_that_cannot_be_frozen_is_refused_not_registered(tmp_path):
    """An empty port would look like a working entry and fail on every later use."""
    card = {"id": "method.fixture", "provides_position": {
        "kind": "web", "recipe": {"kind": "asset_command", "asset": "/tmp/x.py",
                                  "url_args": ["-u", "http://{host}:{port}/"], "command_flag": "-c",
                                  "platform": "linux"}}}
    result = positions.register_declared_position(
        card=card, node_id="28", document=loaded_graph(
            [("28", "RULE 4 (fixture action)", "AND"),
             ("29", "execCode(web2_docker,www_data)", "OR")], [("28", "29")]),
        host_map={"web2_docker": "192.0.2.54"}, scope={"host": "192.0.2.54"}, root=tmp_path)
    assert result["state"] == "failed" and result["reason"] == "POSITION_PORT_UNRESOLVED"
    assert result["logical"] == "web2_docker"
    with pytest.raises(ValueError, match="POSITION_RECIPE_UNBOUND"):
        positions.resolve_position_recipe({"url_args": ["http://{host}/{unknown}/"]},
                                         address="192.0.2.1", port="81")
