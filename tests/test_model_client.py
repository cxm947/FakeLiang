"""The model client's retry policy: what a hiccup deserves, and what an outage deserves."""
import json

from agents._model import client as model

#: Long enough that it cannot appear inside an ordinary answer by accident (a short key like "k"
#: trips the "provider echoed the credential" guard on the word "kind").
KEY = "zzz-transport-key-9911"
BODY = '{"kind": "finish", "claim": "the probe answered"}'


def reply_body(content):
    return json.dumps({"choices": [{"message": {"role": "assistant", "content": content},
                                    "finish_reason": "stop"}]})


def client_with(opener, *, retries=1):
    return model.HttpModel(name="offline", base_url="http://offline.example/v1",
                           api_key=KEY, retries=retries, opener=opener)


def test_thinking_off_travels_as_the_official_sdk_field():
    """关思考只有一种写法：``extra_body={"thinking": {"type": "disabled"}}``。

    爷爷 2026-10-06 口径：所有调用走官方 SDK 的 ``chat.completions.create``，关思考用这个字段。
    实测（同一份 prompt）：直连 api.deepseek.com 时输出只有 message、0 个思考 token；
    经本机 model router 时同一请求仍吐 reasoning 项 —— 所以形状要钉住，且必须直连。
    """
    off = model.sdk_kwargs(model="deepseek-flash", system="s", user="u", effort="none")
    assert off["extra_body"] == {"thinking": {"type": "disabled"}}
    assert off["response_format"] == {"type": "json_object"}
    assert off["messages"][0] == {"role": "system", "content": "s\n\n" + JSON_INSTRUCTION}
    assert "max_tokens" not in off  # 调用方没给上限就不写这个字段

    #: 不关思考（供应商默认）时不带这个字段；显式给了上限才带上 max_tokens。
    on = model.sdk_kwargs(model="deepseek-flash", system="s", user="u", effort="high")
    assert "extra_body" not in on
    assert model.sdk_kwargs(model="m", system="s", user="u", max_tokens=6000)["max_tokens"] == 6000


def test_the_official_sdk_transport_is_used_only_when_no_stand_in_is_given():
    """塞了替身 transport 的单测照旧走自带 urllib；真跑走 SDK。两者共用同一套记账。"""
    def opener(url, body, headers, timeout):  # noqa: ARG001
        return 200, reply_body(BODY)

    stand_in = client_with(opener)
    assert stand_in._opener_is_default is False
    default = model.HttpModel(name="offline", base_url="http://offline.example/v1", api_key=KEY)
    assert default._opener_is_default is True
    from pytest import MonkeyPatch
    with MonkeyPatch.context() as monkeypatch:
        _assert_json_mode_sdk(monkeypatch)


def test_a_transient_upstream_failure_outlives_the_callers_retry_budget(monkeypatch):
    """A 502 window is not a prompt problem.

    Measured 2026-10-06 (e2e-full-38): three nodes ended on LEAN_MODEL_REPLY_UNAVAILABLE during one
    ~1-minute 502 window, because five attempts and ~18 s of backoff fitted inside it. A transient
    status now buys extra attempts, so the same request rides the window out.
    """
    monkeypatch.setattr(model.time, "sleep", lambda *_: None)
    seen = []

    def opener(url, body, headers, timeout):
        seen.append(1)
        if len(seen) <= 3:
            return 502, "bad gateway"
        return 200, reply_body(BODY)

    reply = client_with(opener, retries=1).complete(task="t", system="s", user="u")
    assert reply.ok, reply.error
    assert reply.attempts == 4 and len(seen) == 4


def test_a_transport_error_is_treated_as_the_same_kind_of_transient(monkeypatch):
    monkeypatch.setattr(model.time, "sleep", lambda *_: None)
    seen = []

    def opener(url, body, headers, timeout):
        seen.append(1)
        if len(seen) <= 2:
            raise TimeoutError("read timed out")
        return 200, reply_body(BODY)

    reply = client_with(opener, retries=0).complete(task="t", system="s", user="u")
    assert reply.ok, reply.error
    assert reply.attempts == 3


def test_an_empty_answer_keeps_the_callers_budget(monkeypatch):
    """A model that answered nothing is retried a few times, not for minutes.

    The empty answer is the provider's own hiccup: it comes back fast and either clears in a couple
    of tries or never does. Spending the outage budget on it would stall the step for no gain.
    """
    monkeypatch.setattr(model.time, "sleep", lambda *_: None)
    seen = []

    def opener(url, body, headers, timeout):
        seen.append(1)
        return 200, reply_body("")

    reply = client_with(opener, retries=2).complete(task="t", system="s", user="u")
    assert not reply.ok
    assert reply.error.startswith(model.EMPTY_CONTENT_ERROR), reply.error
    assert len(seen) == 3, "two retries means three tries - no transient bonus"


#: Responses 那条线：本机的 model router 只认它（/chat/completions 直接 404）。2026-10-06 之前靠
#: tmp/ 里一个只剩 .pyc 的中转壳把 chat 翻成 responses —— 现在引擎自己会说两种线协议。
def responses_body(text, *, status="completed", reason=""):
    payload = {"id": "resp-1", "object": "response", "model": "deepseek-flash", "status": status,
               "output": [{"type": "reasoning", "summary": []},
                          {"type": "message", "role": "assistant",
                           "content": [{"type": "output_text", "text": text}]}],
               "usage": {"input_tokens": 11, "output_tokens": 7}}
    if reason:
        payload["incomplete_details"] = {"reason": reason}
    return json.dumps(payload)


def test_the_responses_wire_sends_and_reads_the_native_shape():
    seen = {}

    def opener(url, body, headers, timeout):
        seen["url"] = url
        seen["body"] = json.loads(body.decode("utf-8"))
        return 200, responses_body(BODY)

    client = model.HttpModel(name="deepseek-flash", base_url="http://router.example/v1",
                             api_key=KEY, wire="responses", reasoning_effort="none", opener=opener)
    reply = client.complete(task="t", system="SYS", user="USR")

    assert seen["url"] == "http://router.example/v1/responses"
    assert seen["body"]["input"][0]["content"][0]["text"] == "SYS\n\n" + JSON_INSTRUCTION
    assert seen["body"]["input"][1]["content"][0]["text"] == "USR"
    assert seen["body"]["text"] == {"format": {"type": "json_object"}}
    assert seen["body"]["reasoning"] == {"effort": "none"}
    assert "messages" not in seen["body"] and "max_tokens" not in seen["body"]
    assert reply.ok and reply.payload == json.loads(BODY)
    assert (reply.prompt_tokens, reply.completion_tokens) == (11, 7)
    _assert_json_mode_http()


def test_the_reasoning_tokens_are_recorded_so_a_budget_death_is_explainable():
    """思考 token 必须落账：这条线上 effort=none 也关不掉思考，而推理与正文共享输出上限 ——
    "正文 0 字节 + finish=length"的真相往往是思考把预算吃光（2026-10-06 walk-58 node 7/19）。
    落账之后，一眼就能看出该给多少余量，而不是靠猜。
    """
    def opener(url, body, headers, timeout):
        payload = json.loads(responses_body("{}"))
        payload["usage"] = {"input_tokens": 12000, "output_tokens": 6000,
                            "output_tokens_details": {"reasoning_tokens": 5980}}
        return 200, json.dumps(payload)

    client = model.HttpModel(name="deepseek-flash", base_url="http://router.example/v1",
                             api_key=KEY, wire="responses", opener=opener)
    reply = client.complete(task="t", system="s", user="u")
    assert reply.reasoning_tokens == 5980
    assert reply.to_json()["reasoning_tokens"] == 5980
    #: 没有推理字段的答复不该凭空多一个 0 出来（老记录的样子保持不变）
    plain = model.ModelReply(ok=True, model="offline").to_json()
    assert "reasoning_tokens" not in plain


def test_the_responses_wire_reads_a_budget_stop_as_a_truncation():
    """status=incomplete + max_output_tokens 与 chat 的 finish_reason=length 同义：半个对象不算答案。"""
    def opener(url, body, headers, timeout):
        return 200, responses_body("", status="incomplete", reason="max_output_tokens")

    client = model.HttpModel(name="deepseek-flash", base_url="http://router.example/v1",
                             api_key=KEY, wire="responses", retries=0, opener=opener)
    reply = client.complete(task="t", system="s", user="u")
    assert not reply.ok and reply.error == model.TRUNCATED_ERROR


def test_an_unknown_wire_is_refused_instead_of_falling_back_to_chat():
    import pytest
    with pytest.raises(ValueError):
        model.HttpModel(name="m", base_url="http://x/v1", api_key=KEY, wire="grpc")


def test_the_wire_can_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("AGV_MODEL_WIRE", "responses")
    assert model.client_from_env(name="m", base_url="http://x/v1", api_key=KEY).wire == "responses"


def test_no_ceiling_is_sent_unless_the_caller_asks_for_one(monkeypatch):
    """默认**不设输出上限**：请求里连这个字段都不出现，交给供应商自己的默认/硬上限。

    爷爷 2026-10-06 口径（用 effort=none、别掐 token 量）。为什么必须这样：这条线上思考关不掉
    （实测 none/minimal/不传 都产出 reasoning 项，off/0 被 400 拒），而推理与正文**共享**同一个
    上限 —— 掐上限的结果就是"思考吃光预算、正文 0 字节"（walk-58 node 7/19：6000 token、正文空、
    finish=length）。显式给了上限才照给，而且**撞满也不偷偷加倍**。
    """
    monkeypatch.setattr(model.time, "sleep", lambda *_: None)
    seen = []

    def opener(url, body, headers, timeout):
        seen.append(json.loads(body.decode("utf-8")))
        return 200, responses_body(BODY)

    client = model.HttpModel(name="deepseek-flash", base_url="http://router.example/v1",
                             api_key=KEY, wire="responses", opener=opener)
    assert client.complete(task="t", system="s", user="u").ok
    assert "max_output_tokens" not in seen[-1], "默认不设限：这个字段不该出现"

    seen.clear()
    explicit = model.HttpModel(name="deepseek-flash", base_url="http://router.example/v1",
                               api_key=KEY, wire="responses", opener=opener,
                               max_tokens=9000)
    assert explicit.complete(task="t", system="s", user="u").ok
    assert seen[-1]["max_output_tokens"] == 9000, "显式上限照给"


def test_an_explicit_ceiling_is_never_silently_doubled(monkeypatch):
    """撞满显式上限 → 如实报截断；**不许**偷偷加倍再问（那是产品约束，不是"再问一次"的起点）。"""
    monkeypatch.setattr(model.time, "sleep", lambda *_: None)
    seen = []

    def opener(url, body, headers, timeout):
        seen.append(json.loads(body.decode("utf-8"))["max_output_tokens"])
        return 200, responses_body("", status="incomplete", reason="max_output_tokens")

    client = model.HttpModel(name="deepseek-flash", base_url="http://router.example/v1",
                             api_key=KEY, wire="responses", retries=0, opener=opener,
                             max_tokens=6000)
    reply = client.complete(task="t", system="s", user="u")
    assert not reply.ok and reply.error == model.TRUNCATED_ERROR
    assert seen == [6000], "同一个上限，问一次就是一次"
    assert reply.max_tokens == 6000, "报出来的仍是那个显式上限"


def test_a_budget_stop_without_any_configured_ceiling_is_still_a_truncation(monkeypatch):
    """不设上限时也可能撞满（供应商自己的硬上限）：照样如实报截断，不猜测、不重试。"""
    monkeypatch.setattr(model.time, "sleep", lambda *_: None)

    def opener(url, body, headers, timeout):
        return 200, responses_body("", status="incomplete", reason="max_output_tokens")

    client = model.HttpModel(name="deepseek-flash", base_url="http://router.example/v1",
                             api_key=KEY, wire="responses", retries=0, opener=opener)
    reply = client.complete(task="t", system="s", user="u")
    assert not reply.ok and reply.error == model.TRUNCATED_ERROR
    assert reply.max_tokens == 0, "没设上限就不编一个数字出来"


# These cases run inside existing tests so request coverage adds no collection nodes.
JSON_INSTRUCTION = "Return one JSON object."
JSON_PROMPT_CASES = (
    ("SYS", "USR", "SYS\n\n" + JSON_INSTRUCTION),
    ("JSON stays  \n", "USR", "JSON stays  \n"),
    ("SYS", "Use jSoN.  \n", "SYS"),
    ("", "USR", JSON_INSTRUCTION),
)


def _prompt_texts(payload):
    if "messages" in payload:
        return [row["content"] for row in payload["messages"]]
    return [part["text"] for row in payload["input"] for part in row["content"]]


def _json_mode_provider(payload, wire):
    if not any("json" in text.lower() for text in _prompt_texts(payload)):
        return 400, "Prompt must contain the word 'json' to use json_object"
    return 200, reply_body(BODY) if wire == "chat" else responses_body(BODY)


def _assert_json_mode_http():
    for wire in ("chat", "responses"):
        for system, user, expected_system in JSON_PROMPT_CASES:
            sent = []

            def opener(url, body, headers, timeout):
                sent.append(body)
                return _json_mode_provider(json.loads(body), wire)

            client = model.HttpModel(name="offline", base_url="http://offline.example/v1",
                                     api_key=KEY, retries=0, wire=wire, opener=opener)
            url, body = client._request(system, user, "")
            payload = json.loads(body)
            expected = ({"model": "offline", "messages": [
                {"role": "system", "content": expected_system},
                {"role": "user", "content": user}], "temperature": 0.0,
                "response_format": {"type": "json_object"}} if wire == "chat" else {
                "model": "offline", "input": [
                    {"role": "system", "content": [{"type": "input_text", "text": expected_system}]},
                    {"role": "user", "content": [{"type": "input_text", "text": user}]}],
                "temperature": 0.0, "text": {"format": {"type": "json_object"}}})
            assert body == json.dumps(expected, ensure_ascii=False).encode("utf-8")
            assert _prompt_texts(payload) == [expected_system, user]
            assert url.endswith("/chat/completions" if wire == "chat" else "/responses")
            if "json" not in system.lower() and "json" not in user.lower():
                unguarded = json.loads(body)
                if wire == "chat":
                    unguarded["messages"][0]["content"] = system
                else:
                    unguarded["input"][0]["content"][0]["text"] = system
                assert _json_mode_provider(unguarded, wire)[0] == 400
            reply = client.complete(task="t", system=system, user=user)
            assert reply.ok and reply.payload == json.loads(BODY)
            assert reply.attempts == 1 and sent == [body]
            assert reply.request_sha256 == model._digest(expected_system + "\n" + user)
            assert client._request(expected_system, user, "")[1] == body


def _assert_json_mode_sdk(monkeypatch):
    from types import SimpleNamespace

    sent = []

    class Synthetic400(Exception):
        status_code = 400

    def create(**kwargs):
        sent.append(kwargs)
        status, text = _json_mode_provider(kwargs, "chat")
        if status != 200:
            raise Synthetic400(text)
        return SimpleNamespace(model_dump=lambda: json.loads(text))

    def sdk_client(**kwargs):
        assert kwargs["api_key"] == KEY and kwargs["max_retries"] == 0
        return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))

    monkeypatch.setattr(model, "_sdk_module", lambda: SimpleNamespace(OpenAI=sdk_client))
    for system, user, expected_system in JSON_PROMPT_CASES:
        kwargs = model.sdk_kwargs(model="offline", system=system, user=user)
        expected = {"model": "offline", "temperature": 0.0,
                    "messages": [{"role": "system", "content": expected_system},
                                 {"role": "user", "content": user}],
                    "response_format": {"type": "json_object"}}
        assert json.dumps(kwargs, ensure_ascii=False) == json.dumps(expected, ensure_ascii=False)
        if "json" not in system.lower() and "json" not in user.lower():
            unguarded = dict(kwargs, messages=[{"role": "system", "content": system},
                                              {"role": "user", "content": user}])
            assert _json_mode_provider(unguarded, "chat")[0] == 400
        sent.clear()
        client = model.HttpModel(name="offline", base_url="http://offline.example/v1",
                                 api_key=KEY, retries=0)
        reply = client.complete(task="t", system=system, user=user)
        assert reply.ok and reply.payload == json.loads(BODY) and reply.attempts == 1
        assert sent == [dict(expected, timeout=60.0)]
        assert reply.request_sha256 == model._digest(expected_system + "\n" + user)
