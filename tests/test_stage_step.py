import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from runtime import lean_http  # noqa: E402
from skills.lean import load_card  # noqa: E402

CARD = "exploit.tongda_oa_include_rce"


def test_the_stage_step_materialises_the_card_wire_shape():
    card = load_card(CARD, ROOT)
    request = lean_http.stage_request(card["stage"], {"tool": "stage"})
    assert request["method"] == "POST" and request["path"] == "/ispirit/im/upload.php"
    ctype = request["headers"]["Content-Type"]
    assert ctype.startswith("multipart/form-data; boundary=")
    body = request["body"]
    assert 'name="DEST_UID"' in body and 'filename="agv.png"' in body
    assert "<?php" in body and body.rstrip().endswith("--")
    assert "\r\n" in body, "a multipart body is CRLF-delimited"


def test_the_model_may_override_the_payload_but_not_the_shape():
    card = load_card(CARD, ROOT)
    mine = lean_http.stage_request(card["stage"], {"tool": "stage", "payload": "<?php echo 1; ?>"})
    assert "<?php echo 1; ?>" in mine["body"] and "popen" not in mine["body"]
    for bad, why in (({"tool": "stage", "path": "/x"}, "LEAN_STAGE_REQUEST_INVALID"),):
        try:
            lean_http.stage_request(card["stage"], bad)
        except ValueError as error:
            assert why in str(error)
        else:
            raise AssertionError("a stage call may only carry tool and payload")
    try:
        lean_http.stage_request(None, {"tool": "stage"})
    except ValueError as error:
        assert "LEAN_STAGE_UNDECLARED" in str(error)
    else:
        raise AssertionError("a card without a stage step must refuse by name")


def test_a_scripted_stage_action_runs_the_multipart_request(tmp_path):
    """Drive the executor with a scripted action: no model, but the same call path."""
    import run_lean_task

    card = load_card(CARD, ROOT)
    task = {"node_id": "7", "goal": "run one command through the include chain",
            "inputs": {"target_url": "http://192.0.2.54:8080", "command": "id"},
            "scope": {"host": "192.0.2.54", "port": 8080, "protocol": "tcp",
                      "resources": "whole_endpoint", "vantage": "base"}}
    seen = []

    class Native:
        def __call__(self, argv, timeout):
            seen.append(argv)
            payload = base64.b64encode(json.dumps({"ok": True}).encode("utf-8")).decode("ascii")
            return type("O", (), {"returncode": 0, "stdout": payload, "stderr": "",
                                  "timed_out": False, "tool_error": None})()

    result = run_lean_task.drive(card, task, task["scope"], Native(),
                                 actions=[{"kind": "call", "request": {"tool": "stage"}}],
                                 run_dir=tmp_path, python="python3", timeout=5, max_steps=1)
    assert isinstance(result, dict)
    argv = seen[0]
    assert argv[0] == "python3" and "-c" == argv[1]
    packed = json.loads(base64.b64decode(argv[3]).decode("utf-8"))
    assert packed["method"] == "POST" and "multipart/form-data" in packed["headers"]["Content-Type"]
    assert "DEST_UID" in packed["body"] and "<?php" in packed["body"]


def test_the_stage_step_carries_the_session_cookie_when_the_route_needs_one():
    """A route that starts with an auth step puts a cookie on every later call - including this
    one. Dropping it would make the convenient action unusable exactly where it matters."""
    card = load_card(CARD, ROOT)
    request = lean_http.stage_request(card["stage"], {"tool": "stage",
                                                      "cookie": "PHPSESSID=abc123"})
    assert request["headers"]["Cookie"] == "PHPSESSID=abc123"
    assert request["headers"]["Content-Type"].startswith("multipart/form-data; boundary=")
    with_headers = lean_http.stage_request(card["stage"], {"tool": "stage",
                                                           "headers": {"X-Probe": "1"}})
    assert with_headers["headers"]["X-Probe"] == "1"
    for bad in ({"tool": "stage", "headers": {"X": 1}}, {"tool": "stage", "cookie": 5, "payload": "x"}):
        try:
            lean_http.stage_request(card["stage"], bad)
        except ValueError as error:
            assert "LEAN_STAGE" in str(error)
        else:
            raise AssertionError("non-string header/cookie values must be refused")
