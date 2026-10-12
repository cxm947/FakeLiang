"""Lossless migration, isolation, history pairing, and offline preview."""
import copy
import json
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

import pytest

from agents.prompting.render import ENV, assemble, fragment

ROOT = Path(__file__).resolve().parents[1]


def example():
    return json.loads(files("agents.prompting").joinpath("example.json").read_text(
        encoding="utf-8"))


def test_all_legacy_fragments_round_trip():
    for package in ("agents._model", "agents.executor", "agents.planner",
                    "agents.verifier", "skills"):
        for source in files(package).joinpath("templates").iterdir():
            if source.name.endswith(".txt"):
                assert fragment(package, "templates/" + source.name) == source.read_bytes().decode("utf-8")


def test_scope_is_checked_before_history_and_rendering():
    for field in ("run_id", "node_id", "attempt_id", "agent_role"):
        data = example()
        data["memory"]["scope"][field] += "-other"
        data["memory"]["recent_messages"] = [{"role": "bad"}]
        with pytest.raises(ValueError, match="MEMORY_SCOPE_MISMATCH"):
            assemble(data)
    from jinja2 import UndefinedError
    with pytest.raises(UndefinedError):
        ENV.from_string("{{ missing }}").render({})


def test_complete_tool_pairs_only():
    data = example()
    pair = [
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "provider-1", "type": "function",
             "function": {"name": "evidence", "arguments": "{\"call_id\":\"local-1\"}"}}]},
        {"role": "tool", "tool_call_id": "provider-1", "content": "saved observation"},
    ]
    data["memory"]["recent_messages"] = pair
    assert len(assemble(data)["messages"]) == 4
    for history in (pair[:1], pair[1:], [pair[0], pair[1], pair[1]]):
        bad = copy.deepcopy(data)
        bad["memory"]["recent_messages"] = history
        with pytest.raises(ValueError, match="HISTORY_"):
            assemble(bad)


def test_preview_never_uses_an_api_key(monkeypatch):
    monkeypatch.setenv("AGV_MODEL_API_KEY", "offline-key-must-not-appear")
    out = subprocess.check_output(
        [sys.executable, "-X", "utf8", "-m", "agents.prompting.preview"],
        cwd=ROOT, text=True, encoding="utf-8")
    request = json.loads(out)
    assert request["tools"] == [] and len(request["messages"]) == 2
    assert "offline-key-must-not-appear" not in out
