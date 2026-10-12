"""Offline transport, backend, recovery and native driver acceptance."""
from copy import deepcopy
import json
import threading
import time
from types import SimpleNamespace

import pytest

from agents._model.backend import freeze_backend
from agents._model.chat import ChatModel, secret_echo
from agents._model.contract import ModelReply, EMPTY_CONTENT_ERROR, TRUNCATED_ERROR
from agents.executor.driver import drive
from agents.executor.native_tools import NativeSession, action_for, schemas
from runtime.lean import LeanRun
from runtime.recovery import RecoveryModel, digest, model_reply_record
from tests.test_lean_task_support import SCOPE, card, task, native_client


class Clock:
    def __init__(self):
        self.now, self.epoch, self.waits = 0.0, time.time(), []
    def monotonic(self):
        return self.now
    def time(self):
        return self.epoch + self.now
    def sleep(self, seconds):
        self.waits.append(seconds)
        self.now += seconds


class StatusError(Exception):
    def __init__(self, status):
        self.status_code = status


def message(name, args, provider_id="provider-1"):
    return {"role": "assistant", "content": "", "tool_calls": [
        {"id": provider_id, "type": "function", "function": {
            "name": name, "arguments": json.dumps(args)}}]}


def answer(content='{"decision":"continue"}', calls=None, finish="stop"):
    wire = {"role": "assistant", "content": content}
    if calls is not None:
        wire["tool_calls"] = calls
    result = SimpleNamespace(
        content=content, response_metadata={"finish_reason": finish},
        usage_metadata={"input_tokens": 11, "output_tokens": 7,
                        "output_token_details": {"reasoning": 3}},
        additional_kwargs={"tool_calls": calls} if calls is not None else {},
        tool_calls=[], invalid_tool_calls=[], wire=wire)
    result.model_dump = lambda: {
        "content": result.content, "additional_kwargs": result.additional_kwargs,
        "response_metadata": result.response_metadata}
    return result


class Factory:
    def __init__(self, events):
        self.events = iter(events)
        self.options, self.bindings, self.sent = [], [], []
    def __call__(self, **options):
        self.options.append(options)
        return self
    def bind(self, **options):
        self.bindings.append(options)
        return self
    def bind_tools(self, tools, **options):
        self.bindings.append({"tools": tools, **options})
        return self
    def invoke(self, messages, config):
        self.sent.append((deepcopy(messages), config))
        result = next(self.events)
        if isinstance(result, BaseException):
            raise result
        return result


def model(factory, clock=None, **options):
    return ChatModel(name="deepseek-flash", base_url="https://example.invalid/v1",
                     api_key="transport-private-value", factory=factory,
                     converter=lambda result: deepcopy(result.wire),
                     clock=clock or Clock(), **options)


def complete(client, **options):
    return client.complete(task="planner", system="Return JSON", user="fixture", **options)


def test_confirmed_502_bonus_uses_one_fixed_deadline():
    clock = Clock()
    factory = Factory([StatusError(502)] * 4 + [answer()])
    result = complete(model(factory, clock), retries=0, timeout=90,
                      deadline_at=clock.time() + 90)
    assert result.ok and result.attempts == 5
    assert clock.waits == [5.0, 10.0, 15.0, 20.0]
    clock = Clock()
    factory = Factory([StatusError(502)] * 20)
    result = complete(model(factory, clock), retries=4, timeout=90,
                      deadline_at=clock.time() + 40)
    assert not result.ok and result.response_confirmed
    assert result.attempts == len(factory.sent) == 4 and clock.now == 40
    assert [row["timeout"] for row in factory.options] == [40, 35, 25, 10]


def test_unknown_transport_is_not_resent_by_recovery():
    factory = Factory([TimeoutError("transport-private-value")])
    state = {}
    client = RecoveryModel(model(factory), {"state": state, "save": lambda value: None},
                           ["transport-private-value"])
    for _ in range(2):
        with pytest.raises(ValueError, match="MODEL_CALL_UNKNOWN") as error:
            complete(client, retries=4, timeout=90)
        assert "transport-private-value" not in str(error.value)
    assert len(factory.sent) == 1
    assert state["model_calls"][0]["phase"] == "unknown"
    assert "transport-private-value" not in json.dumps(state)


def test_empty_bad_json_and_401_fail_once():
    for event in (answer(""), answer("not-json"), StatusError(401)):
        factory = Factory([event])
        result = complete(model(factory), retries=4)
        assert not result.ok and result.response_confirmed
        assert result.attempts == len(factory.sent) == 1
    assert complete(model(Factory([answer("")]))).error == EMPTY_CONTENT_ERROR


def test_native_usage_ids_and_truncation():
    call = message("cmd", {"cmd": "fixture-command"}, "provider-7")["tool_calls"]
    tools = schemas({"allowed_tools": ["cmd"]})
    for finish in ("tool_calls", "length"):
        factory = Factory([answer("", calls=call, finish=finish)])
        result = model(factory).invoke_tools(
            task="lean_action", messages=[{"role": "user", "content": "fixture"}],
            tools=tools, max_tokens=500)
        assert result.native_message["tool_calls"] == call
        assert (result.prompt_tokens, result.completion_tokens, result.reasoning_tokens) == (11, 7, 3)
        assert result.max_tokens == 500 and result.payload is None
        assert factory.bindings == [
            {"tools": tools, "tool_choice": "auto", "parallel_tool_calls": False}]
        if finish == "length":
            assert not result.ok and result.error == TRUNCATED_ERROR
        else:
            assert result.ok


def test_escaped_key_echo_is_refused_even_in_broken_json():
    secret = "transport-private-value"
    escaped = "".join("\\u%04x" % ord(char) for char in secret)
    assert secret_echo('{"cmd":"' + escaped, secret)
    call = message("cmd", {}, "provider-secret")["tool_calls"]
    call[0]["function"]["arguments"] = '{"cmd":"' + escaped + '"}'
    result = model(Factory([answer("", calls=call)])).invoke_tools(
        task="lean_action", messages=[{"role": "user", "content": "fixture"}],
        tools=schemas({"allowed_tools": ["cmd"]}))
    assert not result.ok and result.text == "" and result.payload is None
    assert result.native_message is None
    assert "provider response included" in result.error
    assert secret not in json.dumps(result.to_json())


def test_effort_caps_retries_and_responses_wire():
    factory = Factory([answer(), answer()])
    client = model(factory, reasoning_effort="none")
    assert complete(client).ok and complete(client, max_tokens=321).ok
    first, second = factory.options
    assert "max_tokens" not in first and second["max_tokens"] == 321
    assert first["extra_body"] == {"thinking": {"type": "disabled"}}
    assert first["max_retries"] == second["max_retries"] == 0
    responses = Factory([answer()])
    assert complete(model(responses, wire="responses", reasoning_effort="none")).ok
    assert responses.options[0]["use_responses_api"] is True
    assert responses.options[0]["reasoning_effort"] == "none"
    assert "extra_body" not in responses.options[0]
    with pytest.raises(ValueError, match="MODEL_WIRE_UNKNOWN"):
        model(Factory([]), wire="unknown")


def test_late_worker_has_no_result_or_retry_authority():
    release = threading.Event()
    factory = Factory([])
    def blocked(messages, config):
        factory.sent.append((messages, config))
        release.wait(1)
        return answer()
    factory.invoke = blocked
    client = model(factory, clock=time)
    try:
        with pytest.raises(ValueError, match="MODEL_CALL_UNKNOWN"):
            complete(client, deadline_at=time.time() + 0.03)
    finally:
        release.set()
    assert len(factory.sent) <= 1


def test_backend_is_frozen_and_unset_environment_resumes(tmp_path, monkeypatch):
    monkeypatch.delenv("AGV_MODEL_BACKEND", raising=False)
    assert freeze_backend(tmp_path) == "legacy"
    with pytest.raises(ValueError, match="MODEL_BACKEND_CHANGED"):
        freeze_backend(tmp_path, "native")
    fresh = tmp_path / "new-native"
    assert freeze_backend(fresh, "native") == "native"
    assert freeze_backend(fresh) == "native"
    old = tmp_path / "old"
    old.mkdir()
    (old / "existing.txt").write_text("existing")
    with pytest.raises(ValueError, match="MODEL_BACKEND_LEGACY_RUN"):
        freeze_backend(old, "native")
    assert freeze_backend(old) == "legacy"


def test_saved_native_arguments_are_masked_without_destroying_ids():
    value = message("finish", {
        "claim": "fixture", "verdict": "uncertain", "citations": [],
        "materials": [{"realm": "r", "user": "u", "value": "private-material",
                       "kind": "password", "source_call": "registered-call", "quote": "fixture"}]},
        "provider-stable")
    reply = ModelReply(ok=True, native_message=value, text=json.dumps(value),
                       response_confirmed=True)
    original, saved = model_reply_record(reply)
    assert "private-material" not in json.dumps(saved)
    assert saved["native_message"]["tool_calls"][0]["id"] == "provider-stable"
    assert digest(saved) != original


@pytest.mark.parametrize("name,args,kind", [
    ("msf", {"cmd": "getuid"}, "call"),
    ("cmd", {"cmd": "echo fixture"}, "call"),
    ("pws", {"cmd": "Write-Output fixture"}, "call"),
    ("tool", {"name": "printf", "args": []}, "call"),
    ("code", {"code": "print(1)"}, "call"),
    ("http", {"method": "GET", "path": "/"}, "call"),
    ("stage", {}, "call"),
    ("evidence", {"call_id": "local-1", "limit": 2000}, "evidence"),
    ("abandon", {"call_id": "local-1", "reason": "stop waiting"}, "abandon"),
    ("finish", {"claim": "not established", "verdict": "uncertain", "citations": []}, "finish"),
])
def test_native_schema_translates_to_existing_internal_contract(name, args, kind):
    result = action_for(message(name, args), dict(card(), tools=[name]))
    assert result["kind"] == kind
    if kind == "call":
        assert result["request"]["tool"] == name
    locked = dict(card(), allowed_tools=["http"])
    assert {row["function"]["name"] for row in schemas(locked)} == {
        "http", "evidence", "abandon"}
    with pytest.raises(ValueError, match="LEAN_TOOL_UNDECLARED"):
        action_for(message("finish", {
            "claim": "x", "verdict": "uncertain", "citations": []}), locked)


class FakeNative:
    backend = "native"
    _api_key = "private-model-key"
    def __init__(self, answers):
        self.answers, self.requests = iter(answers), []
    def available(self):
        return True
    def invoke_tools(self, **request):
        self.requests.append(request)
        value = next(self.answers)
        if isinstance(value, BaseException):
            raise value
        return ModelReply(ok=True, text=json.dumps(value), native_message=value,
                          response_confirmed=True)


def lean_run(root):
    return LeanRun(root, card=card(), task=task(), scope=SCOPE, timeout=30,
                   executor=lambda *args: pytest.fail("no target call authorized"))


def test_native_pairs_keep_provider_and_verified_receipt_ids(tmp_path, monkeypatch):
    executor, calls = native_client(monkeypatch)
    client = FakeNative([
        message("http", {"method": "GET", "path": "/"}, "provider-http"),
        message("finish", {"claim": "page observed", "verdict": "pass",
                           "citations": [{"quote": "Quartz Portal"}]}, "provider-finish")])
    result = drive(card(), task(), SCOPE, executor, client=client,
                   run_dir=tmp_path, max_steps=4)
    assert result["status"] == "model_reported"
    assert result["claimed_verdict"] == "pass"
    assert result["citations"] and not result["rejections"]
    assert len([row for row in calls if row[0] == "request"]) == 1
    conversation = client.requests[1]["messages"]
    assistant = next(row for row in conversation if row["role"] == "assistant")
    tool = next(row for row in conversation if row["role"] == "tool")
    assert assistant["tool_calls"][0]["id"] == tool["tool_call_id"] == "provider-http"
    receipt = next(row["receipt"] for row in json.loads(tool["content"])["events"]
                   if row["kind"] == "receipt")
    assert receipt["call_id"] != "provider-http" and "Quartz Portal" in receipt["stdout"]
    assert client._api_key not in (tmp_path / "native_tools.jsonl").read_text(encoding="utf-8")
    assert NativeSession(FakeNative([]), lean_run(tmp_path)).pending is None


def test_multiple_calls_return_paired_refusals_without_dispatch(tmp_path, monkeypatch):
    executor, calls = native_client(monkeypatch)
    multiple = message("http", {"method": "GET", "path": "/"}, "provider-a")
    multiple["tool_calls"] += message(
        "http", {"method": "GET", "path": "/"}, "provider-b")["tool_calls"]
    client = FakeNative([multiple, message("finish", {
        "claim": "no request sent", "verdict": "unsatisfied", "citations": []})])
    result = drive(card(), task(), SCOPE, executor, client=client,
                   run_dir=tmp_path, max_steps=4)
    assert result["status"] == "model_reported"
    assert not [row for row in calls if row[0] == "request"]
    tools = [row for row in client.requests[1]["messages"] if row["role"] == "tool"]
    assert {row["tool_call_id"] for row in tools} == {"provider-a", "provider-b"}
    assert all("LEAN_ONE_ACTION_PER_ANSWER" in row["content"] for row in tools)


def test_unknown_native_exchange_cannot_be_resent(tmp_path):
    client = FakeNative([TimeoutError("unconfirmed transport")])
    session = NativeSession(client, lean_run(tmp_path))
    with pytest.raises(TimeoutError):
        session.complete(task="lean_action", system="rules", user="inputs", timeout=1)
    resumed = FakeNative([])
    with pytest.raises(ValueError, match="MODEL_CALL_UNKNOWN"):
        NativeSession(resumed, lean_run(tmp_path))
    assert len(client.requests) == 1 and not resumed.requests


def test_received_native_answer_replays_without_api(tmp_path):
    client = FakeNative([message("finish", {
        "claim": "not established", "verdict": "uncertain", "citations": []},
        "provider-stable")])
    session = NativeSession(client, lean_run(tmp_path))
    assert session.complete(task="lean_action", system="rules", user="inputs",
                            timeout=1).native_message["tool_calls"][0]["id"] == "provider-stable"
    resumed_client = FakeNative([])
    resumed = NativeSession(resumed_client, lean_run(tmp_path))
    replayed = resumed.complete(task="lean_action", system="rules", user="inputs", timeout=1)
    assert replayed.native_message["tool_calls"][0]["id"] == "provider-stable"
    assert not resumed_client.requests
    assert resumed.native_action(replayed)["kind"] == "finish"


def test_native_evidence_allowance_is_eight_and_separate_from_actions(tmp_path, monkeypatch):
    executor, calls = native_client(monkeypatch)
    class Reader(FakeNative):
        def invoke_tools(self, **request):
            index = len(self.requests)
            self.requests.append(request)
            if index == 0:
                value = message("http", {"method": "GET", "path": "/"}, "provider-http")
            elif index <= 9:
                current = json.loads(request["messages"][1]["content"])
                value = message("evidence", {
                    "call_id": current["calls"][0]["call_id"],
                    "contains": "Quartz Portal", "limit": 100}, "provider-read-%d" % index)
            else:
                value = message("finish", {
                    "claim": "bounded reads complete", "verdict": "uncertain", "citations": []},
                    "provider-finish")
            return ModelReply(ok=True, text=json.dumps(value), native_message=value,
                              response_confirmed=True)
    client = Reader([])
    result = drive(card(), task(), SCOPE, executor, client=client,
                   run_dir=tmp_path, max_steps=4)
    assert result["status"] == "model_reported"
    rows = [json.loads(line) for line in
            (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert sum(row["kind"] == "receipt_read" for row in rows) == 8
    assert any(row.get("refusal", {}).get("reason_code") == "LEAN_EVIDENCE_READ_LIMIT"
               for row in rows)
    assert len([row for row in calls if row[0] == "request"]) == 1
    assert len(client.requests) == 11


def test_actual_chatopenai_binding_is_offline_and_accepts_declared_tools():
    from langchain_core.messages import AIMessage
    client = ChatModel(name="deepseek-flash", base_url="https://example.invalid/v1",
                       api_key="unused-offline-key", reasoning_effort="none")
    tools = schemas({"allowed_tools": ["cmd", "finish"]})
    binding = client._model(1, "none", 0).bind_tools(
        tools, tool_choice="auto", parallel_tool_calls=False)
    assert binding.kwargs["parallel_tool_calls"] is False
    assert {row["function"]["name"] for row in binding.kwargs["tools"]} == {
        "cmd", "finish", "evidence", "abandon"}
    wire = message("cmd", {"cmd": "fixture"}, "provider-real")
    result = client._response(
        AIMessage(content="", additional_kwargs={"tool_calls": wire["tool_calls"]},
                  response_metadata={"finish_reason": "tool_calls"}),
        True, 1, time.monotonic(), "offline", 0)
    assert result.ok and result.native_message["tool_calls"][0]["id"] == "provider-real"
