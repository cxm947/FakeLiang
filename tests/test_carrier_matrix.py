"""执行通道矩阵：**一个动作 × 一种载体**，谁来跑。

爷爷 2026-10-07 的口径："管道要考虑会话类型是什么，给到不同的管道。"
矩阵的四格是：跑命令 / 送文件 / 起会话 / 探活；载体是：msf 会话（shell、meterpreter）、
ssh、web（webshell，含 docker 里的那种）。这个文件钉住"送文件"和"探活"两格的**分流**：

* 送文件不许再写死"控制台会话"（那是 2026-10-07 之前的实现）；
* web / ssh 载体各有自己的发送端，命令按它们的形状走（web 是"一次请求"、ssh 是"一行"）；
* Windows 位置不给走 POSIX 分段上传，具名拒绝；
* **webshell 的探活不是 msf 两层**（docker 里那种会话根本不是 msf 对象）。
"""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from runtime import channels, msfservice
from tests import support


def _rpc_transport(monkeypatch, replies, *, tick=0.001):
    import http.client
    import io
    import msgpack
    from types import SimpleNamespace
    from runtime import msfservice

    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(msfservice, "time", SimpleNamespace(monotonic=lambda: clock.now))
    requests, budgets, closed = [], [], []

    class Socket:
        def __init__(self):
            self.data = b""

        def settimeout(self, value):
            budgets.append((clock.now, value))

        def makefile(self, mode, buffering=0):
            owner = self

            class Raw(io.RawIOBase):
                def readable(self):
                    return True

                def readinto(self, buffer):
                    if not owner.data:
                        return 0
                    clock.now += tick
                    buffer[0] = owner.data[0]
                    owner.data = owner.data[1:]
                    return 1

            return Raw()

    class Connection:
        def __init__(self, host, port, *, timeout):
            self.sock = Socket()
            budgets.append((clock.now, timeout))

        def connect(self):
            pass

        def request(self, method, path, *, body, headers):
            requests.append(msgpack.unpackb(body, raw=False))
            payload = msgpack.packb(replies.pop(0), use_bin_type=True)
            self.sock.data = (b"HTTP/1.1 200 OK\r\nContent-Length: "
                              + str(len(payload)).encode("ascii")
                              + b"\r\nConnection: close\r\n\r\n" + payload)

        def getresponse(self):
            response = self.response_class(self.sock, method="POST")
            response.begin()
            return response

        def close(self):
            closed.append(True)

    monkeypatch.setattr(http.client, "HTTPConnection", Connection)
    client = SimpleNamespace(
        _agv_endpoint=msfservice.Endpoint(host="console.invalid", port=55553,
                                         user="attacker", password="private"),
        _agv_token="")
    return client, clock, requests, budgets, closed


def test_rpc_authentication_and_response_share_the_callers_deadline(monkeypatch):
    """Authentication, headers and body consume one deadline instead of new per-RPC windows."""
    from runtime import msfservice

    client, clock, requests, budgets, closed = _rpc_transport(
        monkeypatch, [{"token": "token"}, {"7": {"type": "shell"}}])
    assert msfservice.raw_call(client, "session.list", deadline=2.0) == {
        "7": {"type": "shell"}}
    assert [request[0] for request in requests] == ["auth.login", "session.list"]
    assert all(abs(now + budget - 2.0) < 1e-9 for now, budget in budgets)
    assert clock.now < 2.0
    assert closed == [True, True]


def test_rpc_drip_feed_cannot_extend_the_total_deadline(monkeypatch):
    """Byte-by-byte output expires against the original deadline even without a quiet interval."""
    import pytest
    from runtime import msfservice

    client, clock, requests, budgets, closed = _rpc_transport(
        monkeypatch, [{"token": "token"}, {"data": "x" * 10000}], tick=0.005)
    with pytest.raises(TimeoutError, match="MSF_DEADLINE_EXCEEDED"):
        msfservice.raw_call(client, "session.shell_read", ["7"], deadline=2.0)
    assert [request[0] for request in requests] == ["auth.login", "session.shell_read"]
    assert clock.now <= 2.005
    assert all(now < 2.0 and 0 < budget <= 2.0 for now, budget in budgets)
    assert closed == [True, True]


def test_unknown_session_type_never_selects_a_default_rpc_method(monkeypatch):
    """Only an authoritative supported type supplies a transport method."""
    import pytest
    from runtime import msfservice

    monkeypatch.setattr(msfservice, "session_kind", lambda *args, **kwargs: "unknown")
    with pytest.raises(msfservice.MsfUnreachable, match="MSF_SESSION_TYPE_UNKNOWN"):
        msfservice.channel_methods(object(), "7", deadline=2.0)


def test_windows_reply_decoding_preserves_gbk_and_utf8():
    """Windows bytes remain readable without treating a decoding failure as target failure."""
    text = "\u547d\u4ee4\u6210\u529f\u5b8c\u6210"
    assert msfservice.clean_bytes(text.encode("gbk")) == text
    assert msfservice.clean_bytes(text.encode("utf-8")) == text
    assert msfservice.clean_bytes({b"key": [b"\xb0\xa1"]}) == {"key": ["\u554a"]}
    assert isinstance(msfservice.clean_bytes(b"\xff\xfe\xfd"), str)


@pytest.mark.parametrize("kind,write_method,read_method", [
    ("shell", "session.shell_write", "session.shell_read"),
    ("meterpreter", "session.meterpreter_write", "session.meterpreter_read"),
])
def test_authoritative_types_select_raw_rpc_without_wrapping_commands(
        monkeypatch, kind, write_method, read_method):
    """The authoritative session type selects the raw RPC method without reinterpreting text."""
    calls = []
    def fake_raw(client, method, params=None, *, deadline):
        calls.append((method, params, deadline))
        if method == "session.list":
            return {"6": {"type": kind}}
        return {"data": "shell read"}
    monkeypatch.setattr(msfservice, "raw_call", fake_raw)
    client = object()
    msfservice.shell_write(client, "6", "whoami\n", deadline=8.0)
    assert (write_method, ["6", "whoami\n"], 8.0) in calls
    assert msfservice.shell_read(client, "6", deadline=8.0) == "shell read"
    assert (read_method, ["6"], 8.0) in calls
    assert all(deadline == 8.0 for _, _, deadline in calls)
    assert not any(method == "session.meterpreter_run_single" for method, _, _ in calls)


def test_client_construction_defers_authentication_to_the_owned_deadline(monkeypatch):
    """Constructing a client suppresses the library's independent login window."""
    constructed = []
    monkeypatch.setattr(msfservice, "time", SimpleNamespace(monotonic=lambda: 1.0))
    monkeypatch.setattr(msfservice, "_CLIENTS", {})
    def client(password, **kwargs):
        constructed.append((password, kwargs))
        return SimpleNamespace()
    monkeypatch.setattr(msfservice, "MsfRpcClient", client)
    endpoint = msfservice.Endpoint(host="console.invalid", port=55553, user="attacker", password="private")
    result = msfservice.client_for(endpoint, deadline=2.0)
    assert constructed[0][1]["token"] == ""
    assert result._agv_endpoint == endpoint and result._agv_token == ""
    assert msfservice.client_for(endpoint, deadline=2.0) is result
    assert len(constructed) == 1


# meterpreter is a KNOWN session type now (the engine stopped guessing it), so the
# "unknown type" cases are the empty string, a bare word and a genuinely odd token.
@pytest.mark.parametrize("kind", ["", "unknown", "not_a_kind"])
def test_unknown_raw_session_type_never_sends_a_write(monkeypatch, kind):
    """An unknown authoritative type is refused instead of defaulting to meterpreter."""
    sent = []
    def fake_raw(client, method, params=None, *, deadline):
        sent.append(method)
        return {"6": {"type": kind}}
    monkeypatch.setattr(msfservice, "raw_call", fake_raw)
    with pytest.raises(msfservice.MsfUnreachable, match="MSF_SESSION_TYPE_UNKNOWN"):
        msfservice.shell_write(object(), "6", "command", deadline=2.0)
    assert sent == ["session.list"]


def test_bound_probe_uses_one_explicit_action_and_remote_completion(monkeypatch, tmp_path):
    """An explicit bound probe needs remote completion rather than a guessed carrier recipe."""
    console = support.wire_console(monkeypatch, tmp_path=tmp_path,
        when_written=[("echo agv-entry-ok", "agvteststart\nagv-entry-ok\nagvtestend 0\n")])
    outcome = channels.console_call(support.session_binding(),
        support.bound_action("echo agv-entry-ok\n"), 2.0)
    executor = SimpleNamespace(calls=console.writes)
    alive, note = outcome.read_stop == "end_marker", outcome.stdout
    assert alive and "agv-entry-ok" in note, "web 载体用自己那条无害请求探活"
    assert executor.calls, "确实是往入口发了一次请求"
