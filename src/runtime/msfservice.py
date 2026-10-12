"""msf 控制台：**引擎本机用库直连**的唯一入口（爷爷 2026-10-07 定）。

为什么会有这个模块
------------------
爷爷 2026-10-07 的三句话决定了它的形状：

* "我的这套代码是在本地运行的，MCP 连的 kali —— 能不能本地用 pymetasploit3 去调用 VM 里的 kali？"
* "-a 就好了。"（`msfrpcd` 默认本来就听 0.0.0.0，靶场快照里那个实例是被显式起成回环的）
* "能用已有工具的就用。" / "不用做双保险了。"

在这之前，引擎驱动会话的方式是"把一个客户端脚本推到控制端去跑"：每发命令一个 ssh 进程、
一个 msgpack POST，还会打嗝 —— 一打嗝就被上层读成"会话没了"（那封假阵亡通知书的病根）。
现在的形态是：**把 msf 当一个服务端点**（常驻的 msfrpcd + 一组方法），引擎在本机用 msf 自己的
python 库直接调；`session.write/read/runsingle/stop`、`sessions.list`、`modules.execute`、
`jobs.list/stop` 都是库自己的方法，这里只做三件事：

1. 一个端点一条连接（谁用谁拿，不各起一份）；
2. **把"没问到"与"确实没有"分开**：连不上/打嗝 = `MsfUnreachable`；框架明说没这条会话 =
   `MsfSessionMissing`。上层据此判活死，绝不把打嗝当死亡证据；
3. 保留 `call(method, *params)` 这个旧形状，让调用点可以逐处迁移到库的 API 上。
"""
from __future__ import annotations

import math
import os
import time
from dataclasses import dataclass

try:
    from pymetasploit3.msfrpc import MsfRpcClient
except ImportError:
    MsfRpcClient = None


class MsfUnreachable(Exception):
    """Failure to observe the console does not establish session death."""


class MsfSessionMissing(Exception):
    """An authoritative listing excludes this session."""


@dataclass(frozen=True)
class Endpoint:
    host: str = "127.0.0.1"
    port: int = 55553
    user: str = "msf"
    password: str = ""
    ssl: bool = False


_CLIENTS = {}
CHANNEL_METHODS = {
    "meterpreter": {"write": "session.meterpreter_write", "read": "session.meterpreter_read"},
    "shell": {"write": "session.shell_write", "read": "session.shell_read"},
}


def endpoint_from_env(environ=None) -> Endpoint:
    raw = str((os.environ if environ is None else environ).get("AGV_MSF_RPC", "")).strip()
    if not raw:
        raise ValueError("MSF_ENDPOINT_MISSING: set AGV_MSF_RPC=user:password@host:port")
    head, separator, tail = raw.rpartition("@")
    user, colon, password = head.partition(":")
    host, port_separator, port = tail.rpartition(":")
    if not separator or not colon or not port_separator or not user or not host:
        raise ValueError("MSF_ENDPOINT_INVALID")
    try:
        port_number = int(port)
    except ValueError as error:
        raise ValueError("MSF_ENDPOINT_INVALID") from error
    if not 1 <= port_number <= 65535:
        raise ValueError("MSF_ENDPOINT_INVALID")
    return Endpoint(host=host, port=port_number, user=user, password=password, ssl=False)


def _remaining(deadline):
    if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline)):
        raise ValueError("MSF_DEADLINE_INVALID")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("MSF_DEADLINE_EXCEEDED")
    return remaining


def client_for(endpoint: Endpoint, *, deadline):
    _remaining(deadline)
    if endpoint in _CLIENTS:
        return _CLIENTS[endpoint]
    if MsfRpcClient is None:
        raise MsfUnreachable("pymetasploit3 is not installed on the engine host")
    # A non-None token suppresses the library constructor's unbounded login.
    # Only raw_call authenticates, using the requested RPC's deadline.
    client = MsfRpcClient(endpoint.password, server=endpoint.host, port=int(endpoint.port),
                          username=endpoint.user, ssl=bool(endpoint.ssl), token="")
    client._agv_endpoint = endpoint
    client._agv_token = ""
    _CLIENTS[endpoint] = client
    return client


def clean_bytes(value):
    if isinstance(value, bytes):
        for codec in ("utf-8", "gbk"):
            try:
                return value.decode(codec)
            except UnicodeDecodeError:
                pass
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        return {clean_bytes(key): clean_bytes(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean_bytes(item) for item in value]
    return value


def raw_call(client, method, params=None, *, deadline):
    """Read synchronously with the remaining budget on every socket operation."""
    import http.client
    import io
    import msgpack
    import socket

    endpoint = getattr(client, "_agv_endpoint", None)
    if not isinstance(endpoint, Endpoint):
        raise MsfUnreachable("MSF_CLIENT_ENDPOINT_MISSING")
    _remaining(deadline)

    class DeadlineReader(io.RawIOBase):
        def __init__(self, sock):
            self.sock = sock
            self.source = sock.makefile("rb", buffering=0)

        def close(self):
            try:
                self.source.close()
            finally:
                super().close()

        def readable(self):
            return True

        def readinto(self, buffer):
            self.sock.settimeout(_remaining(deadline))
            return self.source.readinto(buffer)

    class ResponseSocket:
        def __init__(self, sock):
            self.sock = sock

        def makefile(self, mode):
            if mode != "rb":
                raise ValueError("MSF_RESPONSE_MODE_INVALID")
            return io.BufferedReader(DeadlineReader(self.sock))

    def response_for(sock, *args, **kwargs):
        return http.client.HTTPResponse(ResponseSocket(sock), *args, **kwargs)

    def post(payload):
        connection_type = (http.client.HTTPSConnection if endpoint.ssl
                           else http.client.HTTPConnection)
        connection = connection_type(endpoint.host, int(endpoint.port),
                                     timeout=_remaining(deadline))
        connection.response_class = response_for
        response = None
        try:
            connection.connect()
            connection.sock.settimeout(_remaining(deadline))
            connection.request("POST", "/api/",
                               body=msgpack.packb(payload, use_bin_type=True),
                               headers={"Content-Type": "binary/message-pack"})
            _remaining(deadline)
            response = connection.getresponse()
            if response.status != 200:
                raise MsfUnreachable("MSF_HTTP_STATUS: " + str(response.status))
            body = response.read()
            _remaining(deadline)
            decoded = clean_bytes(msgpack.unpackb(body, raw=True, strict_map_key=False))
        except (TimeoutError, socket.timeout) as error:
            raise TimeoutError("MSF_DEADLINE_EXCEEDED") from error
        except (OSError, http.client.HTTPException, ValueError) as error:
            raise MsfUnreachable("MSF_RPC_INVALID: " + type(error).__name__) from error
        finally:
            if response is not None:
                response.close()
            connection.close()
        if not isinstance(decoded, dict) or decoded.get("error"):
            raise MsfUnreachable("MSF_RPC_REJECTED: " + str(method))
        return decoded

    token = str(getattr(client, "_agv_token", "") or "")
    if not token:
        auth = post(["auth.login", endpoint.user, endpoint.password])
        token = str(auth.get("token") or "")
        if not token:
            raise MsfUnreachable("MSF_AUTH_UNCONFIRMED")
        client._agv_token = token
    return post([str(method), token, *list(params or [])])

def sessions(client, *, deadline) -> dict:
    reply = raw_call(client, "session.list", deadline=deadline)
    if any(not isinstance(value, dict) for value in reply.values()):
        raise MsfUnreachable("MSF_SESSION_LIST_INVALID")
    return {str(key): value for key, value in reply.items()}


def session_shape(client, sid, *, deadline):
    sid = str(sid)
    listing = sessions(client, deadline=deadline)
    if sid not in listing:
        raise MsfSessionMissing(sid)
    info = listing[sid]
    return {**info, "sid": sid, "type": str(info.get("type") or "").strip().lower()}


def session_kind(client, sid, *, deadline) -> str:
    return session_shape(client, sid, deadline=deadline)["type"]


def channel_methods(client, sid, *, deadline):
    kind = session_kind(client, sid, deadline=deadline)
    if kind not in CHANNEL_METHODS:
        raise MsfUnreachable("MSF_SESSION_TYPE_UNKNOWN: " + (kind or "unknown"))
    table = CHANNEL_METHODS[kind]
    return table["write"], table["read"]


def shell_write(client, sid, text, *, deadline) -> None:
    method, _ = channel_methods(client, sid, deadline=deadline)
    raw_call(client, method, [str(sid), text], deadline=deadline)


def shell_read(client, sid, *, deadline) -> str:
    _, method = channel_methods(client, sid, deadline=deadline)
    #: `session.*_read` drains a buffer, so a dropped keep-alive can be asked again: the
    #: request either never landed (nothing consumed) or already answered. Measured on the
    #: lab 2026-10-08: a burst of reads let the server close one connection mid-request.
    try:
        reply = raw_call(client, method, [str(sid)], deadline=deadline)
    except MsfUnreachable:
        _remaining(deadline)
        reply = raw_call(client, method, [str(sid)], deadline=deadline)
    data = reply.get("data", "")
    if not isinstance(data, str):
        raise MsfUnreachable("MSF_SESSION_DATA_INVALID")
    return data


def read(client, sid, *, deadline) -> str:
    return shell_read(client, sid, deadline=deadline)


def write(client, sid, text, *, deadline) -> None:
    shell_write(client, sid, text, deadline=deadline)


def runsingle(client, sid, verb, *, deadline) -> str:
    if session_kind(client, sid, deadline=deadline) != "meterpreter":
        raise MsfUnreachable("RUNSINGLE_NOT_A_METERPRETER")
    raw_call(client, "session.meterpreter_run_single", [str(sid), verb], deadline=deadline)
    return ""


def stop_session(client, sid, *, deadline) -> bool:
    try:
        session_shape(client, sid, deadline=deadline)
    except MsfSessionMissing:
        return False
    raw_call(client, "session.stop", [str(sid)], deadline=deadline)
    return True


def jobs(client, *, deadline) -> dict:
    return raw_call(client, "job.list", deadline=deadline)


def call(client, method, *params, deadline):
    if method == "session.list":
        return sessions(client, deadline=deadline)
    if method in {"session.shell_read", "session.meterpreter_read"}:
        return {"data": read(client, params[0], deadline=deadline)}
    if method in {"session.shell_write", "session.meterpreter_write"}:
        write(client, params[0], params[1], deadline=deadline)
        return {}
    if method == "session.meterpreter_run_single":
        return {"data": runsingle(client, params[0], params[1], deadline=deadline)}
    if method == "session.stop":
        stop_session(client, params[0], deadline=deadline)
        return {}
    return raw_call(client, method, list(params), deadline=deadline)
