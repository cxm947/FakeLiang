"""The tunnel's port allocator: the ledger and the local listeners both speak before it claims."""
import json
from types import SimpleNamespace

import pytest

from runtime import session_io, session_registry, tunnel


def listing(*ports):
    lines = ["State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"]
    for port in ports:
        lines.append("LISTEN 0 128 0.0.0.0:%d 0.0.0.0:* users:((\"x\",pid=1,fd=3))" % port)
    return "\n".join(lines) + "\n"


def executor(text=""):
    return lambda argv, timeout: SimpleNamespace(stdout=text, stderr="", returncode=0)


def test_free_ports_skips_what_the_ledger_already_holds(tmp_path):
    """A port another plan reserved is never handed out again."""
    session_registry.reserve_resources(
        tmp_path, owner="plan-a",
        resources=[{"host": "192.0.2.128", "port": 1445, "protocol": "tcp"}])
    chosen = tunnel.free_ports(executor(), tmp_path, owner="relay-1", host="192.0.2.128",
                               band=(1445, 1446, 1447), count=2)
    assert chosen == [1446, 1447]
    held = session_registry.held_resources(tmp_path, host="192.0.2.128")
    assert sorted(held) == [["192.0.2.128", 1445], ["192.0.2.128", 1446],
                            ["192.0.2.128", 1447]]


def test_free_ports_skips_what_the_local_box_already_listens_on(tmp_path):
    """A port already listening where the executor runs is skipped before it is claimed."""
    chosen = tunnel.free_ports(executor(listing(1185)), tmp_path, owner="relay-1",
                               host="192.0.2.128", band=(1185, 1086, 1087), count=1, local=True)
    assert chosen == [1086]


def test_free_ports_claims_atomically_so_two_owners_never_share_a_port(tmp_path):
    """Two allocations in a row come back disjoint -- the second owner sees the first claim."""
    first = tunnel.free_ports(executor(), tmp_path, owner="relay-1", host="192.0.2.128",
                              band=(1445, 1446), count=2)
    with pytest.raises(ValueError, match="TUNNEL_PORT_RANGE_EXHAUSTED"):
        tunnel.free_ports(executor(), tmp_path, owner="relay-2", host="192.0.2.128",
                          band=(1445, 1446), count=1)
    assert first == [1445, 1446]


def test_free_ports_refuses_an_exhausted_or_malformed_band(tmp_path):
    """A band with nothing left, or with a value that is not a port, is a named refusal."""
    tunnel.free_ports(executor(), tmp_path, owner="relay-1", host="192.0.2.128",
                      band=(1445, 1446), count=2)
    with pytest.raises(ValueError, match="TUNNEL_PORT_RANGE_EXHAUSTED"):
        tunnel.free_ports(executor(), tmp_path, owner="relay-2", host="192.0.2.128",
                          band=(1445, 1446), count=1)
    with pytest.raises(ValueError, match="TUNNEL_PORT_BAND_UNDECLARED"):
        tunnel.free_ports(executor(), tmp_path, owner="relay-2", host="192.0.2.128",
                          band=(0, 70000), count=1)
    with pytest.raises(ValueError, match="TUNNEL_PORT_COUNT_UNDECLARED"):
        tunnel.free_ports(executor(), tmp_path, owner="relay-2", host="192.0.2.128",
                          band=(1447,), count=0)


def test_local_listeners_reads_both_ss_and_netstat_shapes():
    """The local check understands the two listings the control box may answer with."""
    assert tunnel.local_listeners(executor(listing(1185, 1445))) == {1185, 1445}
    netstat = ("Proto Recv-Q Send-Q Local Address Foreign Address State\n"
               "tcp 0 0 0.0.0.0:1185 0.0.0.0:* LISTEN\n")
    assert tunnel.local_listeners(executor(netstat)) == {1185}


def test_targets_for_uses_the_graph_ports_and_the_host_map_offsets():
    """Only the addresses the control box cannot reach are wanted, with the graph's own ports."""
    document = {"nodes": [{"dependencies": [
        {"description": "netAccess(worker,tcp,445)"},
        {"description": "hacl(base,edge,tcp,8080)"},
        {"description": "netAccess(base,tcp,81)"}]}]}
    #: the control box's own /24 is what `covering_subnets` drops, so only the far side is wanted
    host_map = {"worker": "192.168.93.40", "edge": "192.168.93.30", "base": "192.168.52.128"}
    assert tunnel.targets_for(document, host_map) == [("192.168.93.30", "8080"),
                                                      ("192.168.93.40", "445")]


def test_init_for_session_reserves_the_ports_then_arms_the_relay(tmp_path, monkeypatch):
    """One attempt: the proxy port and one listen port per target are claimed before arm runs."""
    calls = []

    def fake_arm(executor, session_row, *, targets, run_dir, proxy_port, listeners, node="",
                 timeout=60.0):
        calls.append({"targets": targets, "proxy_port": proxy_port, "listeners": listeners,
                      "node": node})
        return {"state": "completed", "port": proxy_port, "proved": ["192.0.2.30:445"],
                "forwards": [], "local_subnets": [], "reason": "", "row": {"channel_id": "t-1"}}

    monkeypatch.setattr(tunnel, "arm", fake_arm)
    row = {"host": "192.0.2.20", "logical": "web2", "session_id": "5", "platform": "linux"}
    result = tunnel.init_for_session(executor(), row, run_dir=tmp_path,
                                     targets=[("192.0.2.30", 445)], owner="relay-1",
                                     node="19", control_host="192.0.2.128")
    assert result["state"] == "completed"
    assert calls == [{"targets": [["192.0.2.30", 445]], "proxy_port": 1185,
                      "listeners": {"192.0.2.30:445": 1445}, "node": "19"}]
    held = session_registry.held_resources(tmp_path)
    assert sorted(held) == [["192.0.2.128", 1185], ["192.0.2.20", 1445]]


def test_init_for_session_reports_a_failed_arm_without_touching_the_session(tmp_path, monkeypatch):
    """A relay that did not prove its flow is reported as such -- the caller's session stays."""
    monkeypatch.setattr(tunnel, "arm", lambda *a, **k: {
        "state": "unknown", "reason": "TUNNEL_FLOW_UNCONFIRMED", "forwards": [],
        "proved": [], "local_subnets": [], "row": {"channel_id": "t-2"}})
    row = {"host": "192.0.2.20", "session_id": "5"}
    result = tunnel.init_for_session(executor(), row, run_dir=tmp_path,
                                     targets=[("192.0.2.30", 445)], owner="relay-1")
    assert result["state"] == "unknown" and result["reason"] == "TUNNEL_FLOW_UNCONFIRMED"


def test_init_for_session_refuses_without_a_target_or_a_pivot(tmp_path):
    """No graph target, or no pivot address to install the forward on, is a named refusal."""
    assert tunnel.init_for_session(executor(), {"host": "192.0.2.20"}, run_dir=tmp_path,
                                   targets=[], owner="relay-1")["reason"] == "TUNNEL_NO_TARGET"
    assert tunnel.init_for_session(executor(), {}, run_dir=tmp_path,
                                   targets=[("192.0.2.30", 445)],
                                   owner="relay-1")["reason"] == "TUNNEL_PIVOT_UNKNOWN"


def test_an_attempt_that_installed_nothing_hands_its_ports_back(tmp_path, monkeypatch):
    """Nothing was started, so nothing needs a cleanup receipt -- the band returns to the ledger."""
    monkeypatch.setattr(tunnel, "arm", lambda *a, **k: {
        "state": "unknown", "reason": "TUNNEL_FLOW_UNCONFIRMED", "forwards": [], "proved": [],
        "local_subnets": [], "row": {"channel_id": "t-3"}})
    result = tunnel.init_for_session(executor(), {"host": "192.0.2.20", "session_id": "5"},
                                     run_dir=tmp_path, targets=[("192.0.2.30", 445)],
                                     owner="relay-1", control_host="192.0.2.128")
    assert result["released"] is True
    assert session_registry.held_resources(tmp_path) == []
    #: the next attempt may claim the same ports again
    again = tunnel.free_ports(executor(), tmp_path, owner="relay-2", host="192.0.2.20",
                              band=(1445, 1446), count=1)
    assert again == [1445]


def test_an_attempt_that_started_a_forward_keeps_its_lease(tmp_path, monkeypatch):
    """A forward that answered is a started resource: it keeps its lease until cleanup is confirmed."""
    monkeypatch.setattr(tunnel, "arm", lambda *a, **k: {
        "state": "unknown", "reason": "TUNNEL_FLOW_UNCONFIRMED",
        "forwards": [{"target": "192.0.2.30", "port": 445, "listen": 1445, "confirmed": True,
                      "command_rc": 0}],
        "proved": [], "local_subnets": [], "row": {"channel_id": "t-4"}})
    result = tunnel.init_for_session(executor(), {"host": "192.0.2.20", "session_id": "5"},
                                     run_dir=tmp_path, targets=[("192.0.2.30", 445)],
                                     owner="relay-1", control_host="192.0.2.128")
    assert "released" not in result
    assert sorted(session_registry.held_resources(tmp_path)) == [["192.0.2.128", 1185],
                                                                 ["192.0.2.20", 1445]]


def test_release_unstarted_records_the_reason_instead_of_a_receipt(tmp_path):
    """The ledger keeps the reason, and the ports become claimable again."""
    session_registry.reserve_resources(
        tmp_path, owner="relay-1",
        resources=[{"host": "192.0.2.20", "port": 1445, "protocol": "tcp"}])
    released = session_registry.release_unstarted(tmp_path, owner="relay-1",
                                                 reason="TUNNEL_NO_OBSERVED_ROUTE")
    assert session_registry.held_resources(tmp_path) == []
    ledger = json.loads((session_registry._resource_root(tmp_path) / "sessions.json")
                        .read_text(encoding="utf-8"))
    assert ledger["releases"]["relay-1"]["reason"] == "TUNNEL_NO_OBSERVED_ROUTE"
    assert released


def test_prefix_from_mask_takes_a_contiguous_netmask_only():
    """A dotted netmask converts; a non-contiguous one is refused instead of guessed."""
    assert tunnel._prefix_from_mask("255.255.255.0") == 24
    assert tunnel._prefix_from_mask("255.255.0.0") == 16
    with pytest.raises(ValueError, match="TUNNEL_MASK_NOT_CONTIGUOUS"):
        tunnel._prefix_from_mask("255.0.255.0")


def test_windows_prefixes_read_wmi_set_syntax():
    """WMI prints multi-valued properties as WQL sets; both adapters come back as prefixes."""
    text = ("C:\\Windows\\system32>wmic nicconfig where IPEnabled=true get IPAddress,IPSubnet "
            "/format:list\n"
            'IPAddress={"192.0.2.30","fe80::1"}\n\nIPSubnet={"255.255.255.0","64"}\n\n'
            'IPAddress={"192.0.2.20"}\nIPSubnet={"255.255.0.0"}\n\n'
            "C:\\Windows\\system32>echo done\n")
    assert tunnel._windows_prefixes(text) == {"192.0.2.0/24", "192.0.0.0/16"}


def test_local_subnets_reads_a_pretty_printed_framed_document(monkeypatch):
    """`ip -j` answers a pretty-printed array inside the frame; the whole document is the answer."""
    body = ('[\n    {\n        "ifname": "eth0",\n        "addr_info": [\n'
            '            {"family": "inet", "local": "192.168.52.10", "prefixlen": 24}\n'
            "        ]\n    }\n]\n")
    framed = "agvabcstart\n" + body + "agvabcend 0\n"

    def call(binding, request, timeout):
        return {"confirmed": True, "command_rc": 0, "marker": "agvabc",
                "outcome": SimpleNamespace(stdout=framed, stderr="")}

    monkeypatch.setattr(session_io, "call_bound", call)
    assert tunnel.local_subnets(None, {"platform": "linux"}) == ["192.168.52.0/24"]


def test_local_subnets_refuses_an_unknown_platform():
    """A session whose platform nobody declared gets a named refusal, not an empty guess."""
    with pytest.raises(ValueError, match="TUNNEL_PLATFORM_UNDECLARED"):
        tunnel.local_subnets(None, {})


def test_init_for_session_reuses_the_proxy_that_is_already_listening(tmp_path, monkeypatch):
    """The control box's mapper is one shared listener: a second relay must not demand a new port."""
    seen = []
    monkeypatch.setattr(tunnel, "arm", lambda executor, row, **kwargs:
                        seen.append(kwargs["proxy_port"]) or {
                            "state": "completed", "forwards": [], "proved": [], "local_subnets": [],
                            "row": {"channel_id": "t-x"}})
    executor = lambda argv, timeout: SimpleNamespace(stdout=listing(1185), stderr="", returncode=0)
    tunnel.init_for_session(executor, {"host": "192.0.2.20", "session_id": "5"},
                            run_dir=tmp_path, targets=[("192.0.2.30", 445)], owner="relay-1",
                            control_host="192.0.2.128")
    assert seen == [1185]


def test_init_for_session_skips_when_a_live_relay_already_covers_the_targets(tmp_path, monkeypatch):
    """Arming a second relay for a flow that already has one is not an improvement."""
    monkeypatch.setattr(tunnel, "record", lambda run_dir, **kwargs: {
        "channel_id": "tunnel-live", "kind": "proxy", "host": "192.0.2.20", "alive": True,
        "note": "", "tunnel_ports": [{"target": "192.0.2.30", "port": "445", "listen": "1445"}],
        "tunnel_proxy_port": 1185})
    monkeypatch.setattr(tunnel.harvest, "record", lambda run_dir, kind, row: row)
    monkeypatch.setattr(tunnel.harvest, "read", lambda run_dir, row_type="": [
        {"channel_id": "tunnel-live", "kind": "proxy", "host": "192.0.2.20", "alive": True,
         "tunnel_ports": [{"target": "192.0.2.30", "port": "445", "listen": "1445"}]}])
    monkeypatch.setattr(tunnel, "arm", lambda *a, **k: pytest.fail("a covered target needs no relay"))
    result = tunnel.init_for_session(executor(), {"host": "192.0.2.20", "session_id": "5"},
                                     run_dir=tmp_path, targets=[("192.0.2.30", 445)],
                                     owner="relay-1")
    assert result["reason"] == "TUNNEL_ALREADY_LIVE"
