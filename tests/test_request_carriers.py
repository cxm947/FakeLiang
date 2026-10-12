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

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from runtime import channels, dispatch, lean, session_registry
from runtime.runner import ExecOutcome
import run_node
import run_plan
from runtime import session_registry
from tests.graph_fixtures import loaded_graph

CARD = {"id": "method.fixture", "kind": "method", "runs_at": "position", "inputs": {},
        "tools": ["cmd"], "body": "Run one bounded command.", "digest": "fixture-card-v1"}
TASK = {"node_id": "fixture-node", "goal": "Run one command", "inputs": {}}
ENDPOINT_SCOPE = {"host": "192.0.2.54", "port": 18081, "protocol": "tcp", "vantage": "base",
                  "resources": "whole_endpoint"}


class Calls:
    def __init__(self):
        self.seen = []

    def __call__(self, argv, timeout):
        self.seen.append(list(argv))
        return ExecOutcome(0, "base output\n")


def row(**extra):
    binding = {"channel_id": "ch-bound-1", "kind": "console_session", "session_id": "17",
               "endpoint": {"host": "127.0.0.1", "port": 55553, "ssl": False},
               "host": "192.0.2.54", "logical": "web2_docker", "privilege": "www_data",
               "session_type": "meterpreter", "platform": "linux", "shell_ready": True,
               "capacity": {"max_bytes": 65536, "source": "offline payload declaration"}}
    binding.update(extra)
    return binding


def record(root, *, host="web2", level="root", card=None, carrier=None, executor=None,
           delivery=None):
    document = loaded_graph(
        [("22", "RULE 1 (fixture action)", "AND"),
         ("21", "execCode(%s,%s)" % (host, level), "OR")],
        [("22", "21")])
    if delivery is None:
        delivery = {"node_id": "22", "state": "completed", "delivery_owner": "delivery-fixture",
                    "reason": "SESSION_DELIVERY_MATCHED_REGISTERED_CARRIER_OBSERVED",
                    "carrier": (carrier or {}).get("channel_id") or "ch-bound-1"}
    return session_flow.record_channels(
        node_id="22", document=document, host_map={host: "192.0.2.54"}, root=root,
        delivery=delivery)
def test_one_command_becomes_one_explicit_bound_console_action(monkeypatch):
    """One requested command still produces one send, with its complete binding and rendered text."""
    seen = []
    outcome = ExecOutcome(0, "capture", read_stop="end_marker")
    monkeypatch.setattr(channels, "console_call", lambda binding, action, timeout:
                        seen.append((binding, action, timeout)) or outcome)
    binding = row()
    request = {"tool": "cmd", "cmd": "id -u"}
    returned = dispatch.invoke(request, session=binding, marker="agvtest", timeout=3)
    assert returned is outcome
    assert seen == [(binding, dispatch.bind_console(request, binding, marker="agvtest"), 3)]


def test_a_recipe_is_not_a_session_binding():
    """A historical request recipe cannot become an execution position without an observed session."""
    recipe = {"kind": "web", "recipe": ["entry", "{command}"]}
    with pytest.raises(ValueError, match="LEAN_SESSION_TYPE_UNSUPPORTED"):
        dispatch.bind_console({"tool": "cmd", "cmd": "id"}, recipe, marker="m")


def test_the_generic_dispatcher_and_the_explicit_action_take_the_same_path(monkeypatch):
    """Generic category dispatch and an explicitly rendered action reach the same console entry point."""
    seen = []
    monkeypatch.setattr(channels, "console_call", lambda binding, action, timeout:
                        seen.append((binding, action, timeout)) or ExecOutcome(None))
    binding = row()
    request = {"tool": "cmd", "cmd": "whoami"}
    dispatch.invoke(request, session=binding, marker="m", timeout=3)
    channels.console_call(binding, dispatch.bind_console(request, binding, marker="m"), 3)
    assert seen[0] == seen[1]


@pytest.mark.parametrize("session_type", [None, "unknown"])
def test_missing_or_unknown_session_types_are_refused(session_type):
    """A missing or unknown session type replaces recipe guesses with a named refusal."""
    with pytest.raises(ValueError, match="LEAN_SESSION_TYPE_UNSUPPORTED"):
        dispatch.bind_console({"tool": "cmd", "cmd": "id"},
                              row(session_type=session_type), marker="m")


def test_a_position_scope_must_name_its_explicit_session_binding(tmp_path):
    """The position scope still identifies its actual carrier, now through an explicit binding."""
    scope = {"host": "192.0.2.54", "vantage": "position", "resources": "execution_position",
             "carrier": "ch-bound-1", "logical": "web2_docker"}
    for name, binding in (("unbound", None), ("wrong", row(channel_id="another"))):
        with pytest.raises(ValueError, match="LEAN_EXECUTION_BINDING_INVALID"):
            lean.LeanRun(tmp_path / name, card=deepcopy(CARD), task=deepcopy(TASK),
                         scope=deepcopy(scope), executor=Calls(), session=binding)
    run = lean.LeanRun(tmp_path / "bound", card=deepcopy(CARD), task=deepcopy(TASK),
                       scope=deepcopy(scope), executor=Calls(), session=row())
    assert run.scope["carrier"] == run.session["channel_id"]


def test_a_position_scope_refuses_a_structured_request(tmp_path):
    """A position without an endpoint still refuses an HTTP request instead of inventing a port."""
    scope = {"host": "192.0.2.54", "vantage": "position", "resources": "execution_position",
             "carrier": "ch-bound-1"}
    run = lean.LeanRun(tmp_path, card=dict(deepcopy(CARD), tools=["http"]), task=deepcopy(TASK),
                       scope=scope, executor=Calls(), session=row())
    with pytest.raises(ValueError, match="LEAN_HTTP_NEEDS_ENDPOINT"):
        run.call({"tool": "http", "method": "GET", "path": "/"})


def test_using_a_session_does_not_register_a_new_privilege(tmp_path, monkeypatch):
    """Reusing a session preserves its observed identity and cannot create the produced fact's privilege."""
    pipe = row()
    before = deepcopy(pipe)
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [])
    rows, note = record(tmp_path, host="web2_docker", carrier=pipe)
    assert rows == [] and note["reason"] == "SESSION_DELIVERY_CARRIER_NOT_REGISTERED"
    assert pipe == before


def test_a_card_entry_declaration_does_not_register_a_session(tmp_path, monkeypatch):
    """An entry declaration still describes intent; only an observed console session may be registered."""
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [])
    card = {"id": "method.fixture", "channel": {"kind": "web", "recipe": ["entry", "{command}"]}}
    rows, note = record(tmp_path, card=card)
    assert rows == [] and note["reason"] == "SESSION_DELIVERY_CARRIER_NOT_REGISTERED"


def test_a_new_entry_does_not_borrow_the_existing_sessions_endpoint(tmp_path, monkeypatch):
    """A new entry cannot acquire an endpoint by copying an unrelated carrier's declaration."""
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [])
    pipe = row()
    card = {"id": "method.fixture", "channel": {"recipe": ["entry", "http://{host}:{port}"]}}
    before = deepcopy((card, pipe))
    assert record(tmp_path, card=card, carrier=pipe)[0] == []
    assert (card, pipe) == before


def test_migration_reports_the_registered_session_identity(tmp_path):
    """Migration reports an observed console session without deriving another identity from host labels."""
    observed = row(source_node="22")
    result = reporting.migration_note(recorded=[observed])
    assert result["state"] == "registered"
    assert result["reason"] == "CONSOLE_SESSION_OBSERVED"
    assert result["handles"] == [observed["channel_id"]]
    assert result["sessions"] == [observed["session_id"]]


def test_a_step_without_an_endpoint_is_prepared_on_the_handle_it_runs_through():
    """Endpoint-free preparation still identifies the selected session without requiring a service port."""
    node = {"id": "26", "type": "AND", "target_host": "web2_docker", "port": "",
            "dependencies": []}
    card = {"inputs": {"session_ref": {"from": "runtime", "optional": True}}}
    with pytest.raises(ValueError, match="LEAN_NODE_NO_ENDPOINT"):
        run_node.prepare(node, {"web2_docker": "192.0.2.54"}, card)
    task, scope = run_node.prepare(node, {"web2_docker": "192.0.2.54"}, card, carrier=row())
    assert scope == {"host": "192.0.2.54", "vantage": "position",
                     "resources": "execution_position", "carrier": "ch-bound-1",
                     "logical": "web2_docker"}
    assert task["scope"] == scope


def test_the_host_map_third_column_declares_which_positions_are_isolated(tmp_path):
    """The deployment host map remains the source of isolated-position declarations."""
    path = tmp_path / "map.csv"
    path.write_text("web1,192.0.2.10\nweb2_docker,192.0.2.10,container\nkali,192.0.2.128\n",
                    encoding="utf-8")
    assert positions.host_contexts(path) == {"web2_docker": "container"}


def test_a_real_host_fact_cannot_relabel_an_isolated_session(tmp_path, monkeypatch):
    """A session from another host is not registered under a newly produced host fact."""
    isolated = row(host="192.0.2.10", source_node="22")
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [isolated])
    rows, note = record(tmp_path, host="web2", carrier=isolated)
    assert rows == [] and note["reason"] == "SESSION_DELIVERY_CARRIER_HOST_MISMATCH"
    assert isolated["logical"] == "web2_docker"


def test_only_a_registered_session_from_this_step_answers_its_output(tmp_path, monkeypatch):
    """Output collection still requires observed registration with the producing step and target host."""
    observed = row(logical="web2", source_node="22", source_call="call-observed")
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [observed])
    rows, note = record(tmp_path)
    assert rows == [observed]
    assert rows[0]["source_call"] == "call-observed"
    assert note["state"] == "registered" and note["reason"] == "CONSOLE_SESSION_OBSERVED"
    assert note["carrier"] == "ch-bound-1"


def test_a_carrier_named_by_this_step_keeps_the_source_it_was_registered_with(tmp_path,
                                                                             monkeypatch):
    """The delivery names the carrier explicitly, so its original source is preserved, not relabelled."""
    observed = row(logical="web2", source_node="another", source_call="call-original")
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [observed])
    rows, note = record(tmp_path)
    assert rows == [observed]
    assert rows[0]["source_node"] == "another" and rows[0]["source_call"] == "call-original"
    assert note["reason"] == "CONSOLE_SESSION_OBSERVED"


def test_a_carrier_off_the_fact_host_is_not_registered(tmp_path, monkeypatch):
    """A carrier this step's delivery names still has to sit on the produced fact's host."""
    candidate = row(source_node="22", host="192.0.2.99")
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [candidate])
    rows, note = record(tmp_path)
    assert rows == [] and note["reason"] == "SESSION_DELIVERY_CARRIER_HOST_MISMATCH"


def test_an_ordinary_login_does_not_implicitly_apply_become(monkeypatch):
    """An ordinary login declaration cannot gain an administrative session through hidden command rewriting."""
    sent = []
    monkeypatch.setattr(channels, "console_call", lambda *args: sent.append(args))
    with pytest.raises(ValueError, match="LEAN_SESSION_TYPE_UNSUPPORTED"):
        dispatch.invoke({"tool": "cmd", "cmd": "id -u"},
                        session={"kind": "ssh", "user": "ubuntu", "become": "sudo -n"},
                        marker="m", timeout=3)
    assert sent == []


def test_an_output_fact_does_not_upgrade_a_registered_sessions_privilege(tmp_path, monkeypatch):
    """A fact's requested privilege cannot replace the actual privilege recorded for its session."""
    observed = row(logical="web2", privilege="www_data", source_node="22")
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [observed])
    rows, note = record(tmp_path, level="root")
    assert rows[0]["privilege"] == "www_data"
    assert note["state"] == "registered"


def test_an_entry_declaration_cannot_trigger_unbound_setup_actions(tmp_path, monkeypatch):
    """Deployment entry parameters stay declarations until an explicit bound action is dispatched."""
    monkeypatch.setattr(session_registry, 'snapshot', lambda root: [])
    executor = Calls()
    card = {"id": "method.fixture", "entry_setup": {
        "action": ["entry", "{host}", "{port}", "{public_key}"],
        "candidate": {"driver": "ssh", "username": "root", "port": "22"}}}
    before = deepcopy(card)
    rows, note = record(tmp_path, card=card, executor=executor)
    assert rows == [] and note["reason"] == "SESSION_DELIVERY_CARRIER_NOT_REGISTERED"
    assert executor.seen == [] and card == before


def test_the_summary_says_which_plan_it_is_and_what_is_still_undecided(tmp_path):
    """A pass claim needs the plan's identity and the undecided list next to it."""
    import project_graph
    from graph import rehydrate

    inputs = ROOT / "data" / "inputs" / "hongri7"
    assert project_graph.main([str(inputs / "Hongri7_v2.txt"), "--output-dir", str(tmp_path / "g"),
                               "--host-map", str(inputs / "host_ip_map.csv"),
                               "--assets", str(inputs / "assets.json"),
                               "--json-only", "--force"]) == 0
    view = rehydrate.load_file(tmp_path / "g" / "json" / "Hongri7_v2.action_graph.json")
    state = {"22": {"status": "proved",
                    "verification": {"receipt_issues": ["call-x: RECEIPT_REQUEST_DIGEST_MISMATCH"]},
                    "entry_setup": {"state": "failed", "reason": "ENTRY_SETUP_IDENTITY_UNCONFIRMED"}}}
    identity = reporting.plan_identity(view, state)
    assert identity["final_goal"] == ["43", "47"] and identity["schema_version"] == "1.2.0"
    steps = {row["node_id"]: row for row in identity["mandatory_steps"]}
    assert sorted(steps) == ["12", "14", "19", "2", "22", "26", "28", "30", "44", "48", "5", "7"]
    assert steps["22"]["status"] == "proved"
    assert steps["26"]["must_produce"] and steps["26"]["status"] == "not_attempted"
    kinds = {row["kind"] for row in reporting.undecided_rows(state, tmp_path)}
    #: no cleanup rows any more: the engine does not keep an end-of-round cleanup ledger
    assert {"receipt", "entry"} <= kinds and "cleanup" not in kinds


def test_undecided_lists_only_what_was_actually_promised(tmp_path):
    """A step that never promised a handle is not "undecided" when it has none."""
    state = {
        "14": {"status": "proved", "card": "pre.nmap_tcp_probe",
               "migration": {"entry": {"state": "not_established", "reason": "NO_EXEC_OUTPUT_FACT"}}},
        "28": {"status": "proved", "card": "exploit.laravel_ignition_rce",
               "migration": {"entry": {"state": "not_established",
                                       "reason": "NO_REGISTERED_OUTPUT_SESSION"}}},
        "44": {"status": "proved", "card": "exploit.wmic_remote_cmd",
               "migration": {"entry": {"state": "unknown", "reason": "SESSION_DELIVERY_FAILED"}}},
    }
    rows = reporting.undecided_rows(state, tmp_path)
    kinds = [(row["node"], row["kind"]) for row in rows]
    assert ("14", "delivery") not in kinds           # ???????????
    assert ("28", "delivery") in kinds               # ?????????????????
    assert ("44", "delivery") in kinds               # ???????

def test_the_real_card_that_asks_where_its_tool_is_gets_the_placed_path():
    """The card's front matter has no `type` field, so the binding must not require one.

    walk-166 node 28 hand-rolled the ignition chain with urllib although the card ships the PoC:
    the rule demanded `type: path` and cards do not carry it, so `poc_path` was never answered.
    """
    from skills import lean as skills_lean

    card = skills_lean.load_card("exploit.laravel_ignition_rce", ROOT)
    bound = preparation.bind_config_paths(card, {"inputs": {}},
                                       ["/tmp/agv-tools/CVE-2021-3129/CVE-2021-3129.py"])
    assert bound == {"poc_path": "/tmp/agv-tools/CVE-2021-3129/CVE-2021-3129.py"}
    #: ?????????????suid ?????????
    suid = skills_lean.load_card("exploit.suid_path_hijack", ROOT)
    assert preparation.bind_config_paths(suid, {"inputs": {}}, ["/a.py", "/b.py"]) == {}
