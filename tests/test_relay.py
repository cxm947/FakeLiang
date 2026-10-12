"""中继：访问方向（SOCKS5）与回程方向（portproxy）都要能自证，且语义分得清。"""
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests import support   # noqa: E402 - shared test helpers
from runtime import relay, tunnel, session_io
from types import SimpleNamespace
pass  # no runtime module
def bound_console(*, session_type="shell", platform="windows"):
    return {"kind": "console_session", "channel_id": "test-session", "host": "192.0.2.20",
            "endpoint": {"host": "127.0.0.1", "port": 55553, "ssl": False},
            "session_id": "2", "session_type": session_type, "platform": platform,
            "shell_ready": True,
            "capacity": {"max_bytes": 65536, "source": "test declaration"}}


def relay_calls(monkeypatch, *, confirmed=True, responses=()):
    calls = []
    pending = list(responses)
    unsettled = False

    def call(binding, request, timeout):
        nonlocal unsettled
        if unsettled:
            raise ValueError("CHANNEL_CALL_UNRESOLVED")
        calls.append((binding, request, timeout))
        complete = confirmed and request["tool"] != "msf"
        unsettled = not complete
        text = pending.pop(0) if pending else (
            "0.0.0.0 2090 10.0.0.9 1090\n" if "show" in request.get("args", []) else "")
        outcome = SimpleNamespace(stdout=text, stderr="", returncode=0, timed_out=False,
                                  tool_error=None, read_stop="end_marker" if complete else "idle")
        return {"outcome": outcome, "confirmed": complete,
                "command_rc": 0 if complete else None}

    monkeypatch.setattr(session_io, 'call_bound', call)
    return calls

ROOT = Path(__file__).resolve().parents[1]


def test_the_shipped_scripts_compile():
    for name, source in (("socks5", relay.SOCKS5_SERVER), ("probe", relay.RELAY_PROBE)):
        compile(source, "<relay:%s>" % name, "exec")


def test_the_return_relay_reads_back_a_meterpreter_portfwd(monkeypatch):
    """`portfwd list` 的真机原文（2026-10-08 实测）。

    以前这条路线对 meterpreter 的读回判定**恒为 False**，于是 `arm_return` 永远报
    `RETURN_RELAY_UNCONFIRMED`（哪怕 add 的 rc=0）—— 回程门装了却当没装。
    """
    listing = ("\nActive Port Forwards\n====================\n\n"
               "   Index  Local                Remote     Direction\n"
               "   -----  -----                ------     ---------\n"
               "   1      192.0.2.9:1090       [::]:2090  Reverse\n\n"
               "1 total active port forwards.\n\n")
    calls = []

    def call(binding, request, timeout):
        calls.append(request)
        text = listing if str(request.get("cmd") or "").startswith("portfwd list") else ""
        outcome = SimpleNamespace(stdout=text, stderr="", returncode=0, timed_out=False,
                                  tool_error=None, read_stop="end_marker")
        return {"outcome": outcome, "confirmed": True, "command_rc": 0}

    monkeypatch.setattr(session_io, 'call_bound', call)
    plan = relay.arm_return(None, carrier=bound_console(session_type="meterpreter"),
                            listen_host="192.0.2.20", listen_port=2090,
                            console_host="192.0.2.9", console_port=1090,
                            route="meterpreter-portfwd")
    assert plan["ok"] is True and plan["listening"] is True, plan
    assert "portfwd add -R -l 1090 -L 192.0.2.9 -p 2090" == str(calls[0].get("cmd"))


def test_the_return_relay_uses_the_systems_own_portproxy():
    add = relay.portproxy_argv(listen_port=2090, connect_host="10.0.0.9", connect_port=1090)
    assert add[:5] == ["netsh", "interface", "portproxy", "add", "v4tov4"]
    assert "listenport=2090" in add and "connectaddress=10.0.0.9" in add and "connectport=1090" in add
    delete = relay.portproxy_argv(listen_port=2090, delete=True)
    assert delete[:5] == ["netsh", "interface", "portproxy", "delete", "v4tov4"]
    assert delete[-1] == "listenport=2090"


def test_the_shell_route_installs_the_relay_with_netsh_and_records_both_rows(tmp_path, monkeypatch):
    """A declared system route still records both undo actions after confirmed readback."""
    calls = relay_calls(monkeypatch)
    binding = bound_console()
    plan = relay.start_return(None, binding, listen_port=2090, connect_host="10.0.0.9",
                              connect_port=1090, route="netsh-portproxy", run_dir=tmp_path,
                              node="step")
    from runtime import artifacts
    rows = artifacts.read(tmp_path)
    assert [row["kind"] for row in rows] == ["config", "firewall"]
    assert rows[0]["undo"][:6] == ["netsh", "interface", "portproxy", "delete", "v4tov4",
                                    "listenaddress=0.0.0.0"]
    assert rows[1]["undo"][-1] == "name=agv-return-2090"
    assert plan["ok"] is True and plan["route"] == "netsh-portproxy"
    assert all(item[0] is binding and item[1]["tool"] == "tool" for item in calls)
    assert any("firewall" in item[1]["args"] for item in calls)


def test_the_native_route_without_a_frame_remains_unconfirmed(tmp_path, monkeypatch):
    """The declared native route is sent, but unframed listing text cannot prove installation."""
    calls = relay_calls(monkeypatch, responses=["accepted", "1 0.0.0.0:1090 [::]:2090 Reverse"])
    binding = bound_console(session_type="meterpreter", platform="linux")
    plan = relay.start_return(None, binding, listen_port=2090, connect_host="10.0.0.9",
                              connect_port=1090, route="meterpreter-portfwd", run_dir=tmp_path,
                              node="step", attempts=1)
    from runtime import artifacts
    rows = artifacts.read(tmp_path)
    assert [row["kind"] for row in rows] == ["config"]
    assert rows[0]["undo"] == [] and rows[0]["state"] == "declared"
    assert plan["ok"] is False and plan["reason"] == "RETURN_RELAY_UNCONFIRMED"
    assert [item[1]["cmd"] for item in calls] == [
        "portfwd add -R -l 1090 -L 10.0.0.9 -p 2090"]

def test_probe_over_relay_separates_the_three_answers():
    class Executor:
        def __init__(self, text):
            self.text = text

        def __call__(self, argv, timeout):
            return type("O", (), {"stdout": self.text, "returncode": 0})()

    ok = Executor("AGV_RELAY_CONNECTED\n")
    refused = Executor("AGV_RELAY_REFUSED\n")
    broken = Executor("AGV_RELAY_ERROR reason=relay_unreachable detail=ConnectionRefusedError\n")
    assert relay.probe_over_relay(ok, "socks5://h:1080", target_host="10.1.1.1", target_port=445)[0] == "connected"
    assert relay.probe_over_relay(refused, "socks5://h:1080", target_host="10.1.1.1", target_port=1)[0] == "refused"
    state, why = relay.probe_over_relay(broken, "socks5://h:1080", target_host="10.1.1.1", target_port=445)
    assert state == "relay_error" and "relay_unreachable" in why


def test_the_socks5_client_really_connects_and_really_refuses(tmp_path):
    """真机（本机回环）验证：经 SOCKS5 探开放端口 = connected，探关闭端口 = refused。"""
    target = socket.socket()
    target.bind(("127.0.0.1", 0))
    target.listen(4)
    open_port = target.getsockname()[1]
    script = tmp_path / "agv_socks5.py"
    script.write_text(relay.SOCKS5_SERVER, encoding="utf-8")
    server = subprocess.Popen([sys.executable, str(script), "127.0.0.1", "18099"],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(2.0)
    try:
        class Executor:
            def __call__(self, argv, timeout):
                done = subprocess.run([sys.executable, "-c"] + [str(x) for x in argv[2:]],
                                      capture_output=True, text=True, timeout=30)
                return type("O", (), {"stdout": done.stdout, "returncode": done.returncode})()

        assert relay.probe_over_relay(Executor(), "socks5://127.0.0.1:18099",
                                      target_host="127.0.0.1",
                                      target_port=open_port)[0] == "connected"
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        closed_port = closed.getsockname()[1]
        closed.close()
        assert relay.probe_over_relay(Executor(), "socks5://127.0.0.1:18099",
                                      target_host="127.0.0.1",
                                      target_port=closed_port)[0] == "refused"
    finally:
        server.terminate()
        target.close()


def test_the_pivot_address_is_the_one_the_target_can_reach(monkeypatch):
    """Address selection still uses observed target-side addresses on the exact binding."""
    carrier = bound_console(session_type="meterpreter")
    listed = "IPv4: 192.168.52.30\nIPv4: 192.168.93.20\n"
    calls = relay_calls(monkeypatch, responses=[listed, listed, "nothing here"])
    assert relay.pivot_address(None, target_host="192.168.93.30", carrier=carrier) == "192.168.93.20"
    assert relay.pivot_address(None, target_host="192.168.52.99", carrier=carrier) == "192.168.52.30"
    assert relay.pivot_address(None, target_host="192.168.93.30", carrier=carrier) == ""
    assert all(item[0] is carrier and item[1]["name"] == "ipconfig" for item in calls)


def test_an_unconfirmed_portproxy_is_not_reported_as_installed(monkeypatch, tmp_path):
    """Unconfirmed writes still retain receipts and never become installed artifacts."""
    calls = relay_calls(monkeypatch, confirmed=False)
    binding = bound_console()
    plan = relay.start_return(None, binding, listen_port=2090, connect_host="10.0.0.9",
                              connect_port=1090, route="netsh-portproxy", run_dir=tmp_path,
                              node="step", evidence_dir=tmp_path / "relay")
    from runtime import artifacts
    assert plan["ok"] is False and plan["reason"] == "RETURN_RELAY_UNCONFIRMED"
    assert [row["state"] for row in artifacts.read(tmp_path)] == ["declared"]
    receipts = json.loads((tmp_path / "relay" / "relay-2090.json").read_text(encoding="utf-8"))
    assert plan["tried"] == 1 and receipts["ok"] is False
    assert [step["attempt"] for step in receipts["steps"]] == [1]
    assert receipts["steps"][0]["add"]["command_rc"] is None
    assert receipts["steps"][0]["add"]["read_stop"] == "idle"
    assert calls


def test_declared_route_and_complete_tuple_are_required(monkeypatch, tmp_path):
    """The caller must declare the route, and another endpoint cannot satisfy readback."""
    binding = bound_console()
    relay_calls(monkeypatch, responses=["", "0.0.0.0 2090 10.0.0.99 1090\n", ""])
    plan = relay.start_return(None, binding, listen_port=2090, connect_host="10.0.0.9",
                              connect_port=1090, route="netsh-portproxy", attempts=1)
    assert plan["ok"] is False
    with pytest.raises(ValueError, match="RETURN_RELAY_ROUTE_UNDECLARED"):
        relay.start_return(None, binding, listen_port=2090, connect_host="10.0.0.9",
                           connect_port=1090, route="")


def test_tunnel_record_keeps_the_exact_binding_without_a_session_row(monkeypatch):
    """A tunnel is one resource and never fabricates another reusable session."""
    written = []
    monkeypatch.setattr(tunnel.harvest, "record",
                        lambda root, kind, row: written.append((kind, row)) or row)
    binding = bound_console()
    row = tunnel.record("unused", session_row=binding, mappings={("192.0.2.30", "445"): 1445},
                        proxy_port=1085, alive=True, note="observed")
    assert [kind for kind, _ in written] == ["tunnel"]
    assert row["session_binding"] == binding
    binding["endpoint"]["port"] = 1
    assert row["session_binding"]["endpoint"]["port"] == 55553


def test_tunnel_prefixes_are_observed_instead_of_defaulted(monkeypatch):
    """Interface evidence preserves its real prefix instead of assuming /24."""
    binding = bound_console(platform="linux")
    relay_calls(monkeypatch, responses=[json.dumps([
        {"addr_info": [{"local": "10.25.18.9", "prefixlen": 20}]}])])
    assert tunnel.local_subnets(None, binding) == ["10.25.16.0/20"]


def test_tunnel_ports_must_be_assigned_before_dispatch(monkeypatch):
    """No automatic base-port scan or port increment is used for tunnel setup."""
    calls = relay_calls(monkeypatch)
    with pytest.raises(ValueError, match="TUNNEL_LISTENERS_UNDECLARED"):
        tunnel.arm(None, bound_console(), targets=[("192.0.2.30", 445)],
                   run_dir="unused", proxy_port=1085, listeners={})
    assert calls == []


def test_unconfirmed_tunnel_undo_keeps_the_resource_open(monkeypatch):
    """An unconfirmed undo neither closes its resource nor clears the proxy map."""
    relay_calls(monkeypatch, confirmed=False)
    recorded, cleared = [], []
    monkeypatch.setattr(tunnel.harvest, "record", lambda *args: recorded.append(args))
    row = {"channel_id": "tunnel-test", "session_binding": bound_console(),
           "tunnel_ports": [{"listen": "1445"}]}
    result = tunnel.reclaim(lambda *args: cleared.append(args), "unused", row)
    assert result["state"] == "unknown"
    assert recorded == [] and cleared == []


def test_relay_intent_precedes_dispatch_and_unknown_stops_the_workflow(monkeypatch):
    """An unresolved write has a cleanup intent and cannot trigger another session action."""
    from runtime import artifacts
    recorded, sent = [], []
    monkeypatch.setattr(artifacts, "record", lambda *a, **kw: recorded.append(kw) or kw)

    def call(binding, request, timeout):
        assert recorded and recorded[0]["state"] == "declared"
        assert sent == []
        sent.append(request)
        return {"confirmed": False, "command_rc": None,
                "outcome": SimpleNamespace(stdout="", stderr="", returncode=None,
                                            timed_out=True, read_stop="deadline")}

    monkeypatch.setattr(session_io, 'call_bound', call)
    plan = relay.start_return(None, bound_console(), listen_port=2090,
                              connect_host="10.0.0.9", connect_port=1090,
                              route="netsh-portproxy", run_dir="unused")
    assert plan["ok"] is False and plan["tried"] == 1 and len(sent) == 1


def test_an_unconfirmed_portfwd_is_not_reported_as_installed(monkeypatch, tmp_path):
    """An unanswered native route still records an unknown result and the sent requests."""
    calls = relay_calls(monkeypatch, confirmed=False)
    binding = bound_console(session_type="meterpreter", platform="linux")
    plan = relay.start_return(None, binding, listen_port=2090, connect_host="10.0.0.9",
                              connect_port=1090, route="meterpreter-portfwd", run_dir=tmp_path,
                              node="step", evidence_dir=tmp_path / "relay")
    assert plan["ok"] is False and plan["route"] == "meterpreter-portfwd"
    receipts = json.loads((tmp_path / "relay" / "relay-2090.json").read_text(encoding="utf-8"))
    assert [step["attempt"] for step in receipts["steps"]] == [1]
    assert receipts["steps"][0]["add"]["request"]["cmd"].startswith("portfwd add -R")
    from runtime import artifacts
    rows = artifacts.read(tmp_path)
    assert [row["state"] for row in rows] == ["declared"]
    console = SimpleNamespace(singles=[item[1]["cmd"] for item in calls])
    assert any("portfwd" in item for item in console.singles), "动词确实送进了会话"
