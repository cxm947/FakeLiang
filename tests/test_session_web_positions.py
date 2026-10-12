"""Observed session lifecycle, explicit binding, and resource ownership regressions."""
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from orchestration import evidence  # noqa: E402

from runtime import msfservice  # noqa: E402

from runtime import session_io  # noqa: E402

from runtime import session_registry  # noqa: E402

from runtime import sessions  # noqa: E402

from tests.test_session_carry import ROOT
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from runtime import session_identity, session_io, session_registry, sessions
import run_plan
from runtime import msfservice, session_registry, session_io
from runtime.runner import ExecOutcome


WEB_RECIPE = {"kind": "asset_command", "asset": "/srv/app/entry.php",
              "url_args": ["-q", "http://192.0.2.7/entry.php?token=fixture"],
              "command_flag": "-d", "platform": "linux"}


def test_a_web_position_is_a_leftover_resource_not_a_connection(tmp_path):
    """The row says where the entry is and how this run talks to it; it observes no privilege."""
    row = sessions.register_web_position(tmp_path, host="192.0.2.7", logical="web2_docker",
                                        recipe=dict(WEB_RECIPE), source_node="28",
                                        source_call="call-a")
    assert row["session_type"] == "entry" and row["position_kind"] == "web"
    assert row["recipe"] == WEB_RECIPE
    assert row["observation"]["state"] == "unknown"
    assert row["endpoint"] == {"host": "", "port": 0, "ssl": False}
    listed = [item for item in session_registry.snapshot(tmp_path) if item["session_type"] == "entry"]
    assert [item["host"] for item in listed] == ["192.0.2.7"]


def test_a_web_position_refuses_a_recipe_that_is_not_an_entry_command(tmp_path):
    """A non-entry recipe or a missing host is refused by name instead of becoming a vague binding."""
    with pytest.raises(ValueError, match="SESSION_WEB_RECIPE_UNSUPPORTED"):
        sessions.register_web_position(tmp_path, host="192.0.2.7", logical="web2",
                                      recipe={"kind": "http"})
    with pytest.raises(ValueError, match="SESSION_WEB_HOST_REQUIRED"):
        sessions.register_web_position(tmp_path, host="  ", logical="web2",
                                      recipe=dict(WEB_RECIPE))


WEB_POSITION = {"channel_id": "web-1", "session_type": "web",
                "recipe": {"kind": "asset_command", "asset": "/tmp/agv-tools/x/client.py",
                           "url_args": ["-u", "http://192.0.2.7:81/"], "command_flag": "-c",
                           "platform": "linux"}}


def test_a_web_position_proves_itself_through_its_own_entry():
    """The entry's own answer is the proof: one framed command through the client, nothing replayed."""
    import re

    from runtime.runner import ExecOutcome

    seen = []

    def executor(argv, timeout):
        seen.append(list(argv))
        marker = re.search(r"(agv[0-9a-z]+)start", str(argv[-1])).group(1)
        return ExecOutcome(0, "%sstart\nagv-entry-ok\n33\n%send 0\n" % (marker, marker),
                           read_stop="end_marker")

    alive, reason = sessions.probe(dict(WEB_POSITION), executor)
    assert alive and reason == "WEB_ENTRY_CONFIRMED"
    assert seen[0][1] == "/tmp/agv-tools/x/client.py" and seen[0][-2] == "-c"
    assert "agv-entry-ok; id -un" in seen[0][-1]

    def silent(argv, timeout):
        return ExecOutcome(0, "client said nothing\n")

    alive, reason = sessions.probe(dict(WEB_POSITION), silent)
    assert not alive and reason.startswith("WEB_ENTRY_UNCONFIRMED")

    def failed(argv, timeout):
        marker = re.search(r"(agv[0-9a-z]+)start", str(argv[-1])).group(1)
        return ExecOutcome(0, "%sstart\nsh: 1: not found\n\n%send 127\n" % (marker, marker),
                           read_stop="end_marker")

    alive, reason = sessions.probe(dict(WEB_POSITION), failed)
    assert not alive and reason == "WEB_ENTRY_UNCONFIRMED"
def test_a_process_without_the_entry_client_does_not_put_a_position_out_of_service(tmp_path):
    """The resident prober has no entry client: it reports what it saw and writes nothing down."""
    row = sessions.register_web_position(tmp_path, host="192.0.2.7", logical="web2_docker",
                                        recipe=dict(WEB_POSITION["recipe"]), source_node="28")
    assert sessions.probe(row, None) == (False, "SESSION_PROBE_OBSERVER_REQUIRED")
    stored = next(item for item in session_registry.snapshot(tmp_path)
                  if item["channel_id"] == row["channel_id"])
    assert stored["observation"] == row["observation"]
