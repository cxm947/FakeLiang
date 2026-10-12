"""Tunnel records, coverage and port reservations."""
from __future__ import annotations

from copy import deepcopy
import time
from uuid import uuid4

from runtime import harvest
from .tunnel_proxy import map_path


def record(run_dir, *, session_row, mappings, proxy_port, alive, note) -> dict:
    """Record one tunnel resource with its exact session binding."""
    row = {"channel_id": "tunnel-" + uuid4().hex, "kind": "proxy", "at": time.time(),
           "host": str(session_row.get("host") or ""),
           "logical": str(session_row.get("logical") or ""),
           "parent": str(session_row.get("channel_id") or ""),
           "session_binding": deepcopy(session_row),
           "reach": "socks5://127.0.0.1:%s" % proxy_port,
           "alive": bool(alive), "note": str(note),
           "tunnel_ports": [{"target": host, "port": port, "listen": str(listen)}
                            for (host, port), listen in sorted(mappings.items())],
           "tunnel_proxy_port": proxy_port, "tunnel_map": map_path()}
    return harvest.record(run_dir, "tunnel", row)


def rows(run_dir) -> list:
    """隧道行，按建立顺序；close 过的不再返回（回收表一走就干净）。"""
    all_rows = harvest.read(run_dir, row_type="tunnel")
    closed = {str(row.get("parent")) for row in all_rows if str(row.get("kind")) == "closed"}
    kept = {}
    for row in all_rows:
        if str(row.get("kind")) == "closed":
            continue
        key = str(row.get("channel_id") or "")
        if key and key not in closed:
            kept[key] = row
    return list(kept.values())


def covers(row, host) -> bool:
    """这条隧道覆盖不覆盖这个地址（按端口映射的目标地址比 /24：实验网段够用，不需第三方库）。"""
    address = str(host or "").strip()
    if not address:
        return False
    prefix = ".".join(address.split(".")[:3])
    for item in row.get("tunnel_ports") or []:
        if ".".join(str(item.get("target") or "").split(".")[:3]) == prefix:
            return True
    return False


def local_listeners(executor, *, timeout=30.0) -> set:
    """Ports already listening on the box `executor` runs on (ss or netstat, best effort)."""
    done = executor(["/bin/sh", "-c",
                     "ss -ltn 2>/dev/null || netstat -lnt 2>/dev/null"], timeout)
    found = set()
    for line in str(getattr(done, "stdout", "") or "").splitlines():
        if "LISTEN" not in line.upper():
            continue
        cells = line.split()
        address = cells[3] if len(cells) >= 4 else ""
        tail = address.rsplit(":", 1)[-1]
        if tail.isdigit():
            found.add(int(tail))
    return found


def free_ports(executor, run_dir, *, owner, host, band, count, local=False, timeout=30.0) -> list:
    """Reserve `count` ports of `band` for `owner` without handing out a claimed one.

    The ledger is the authority for "already reserved"; a port already listening on the box the
    executor runs on is skipped when `local` says that band lives there. Both checks are
    advisory: the atomic claim decides, and a real bind failure at start time is the caller's
    signal to advance on the band rather than a reason to retry here.
    """
    from runtime import session_registry

    if type(count) is not int or count <= 0:
        raise ValueError("TUNNEL_PORT_COUNT_UNDECLARED")
    ports = sorted(set(band))
    if not ports or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("TUNNEL_PORT_BAND_UNDECLARED")
    taken = {port for _host, port in session_registry.held_resources(run_dir, host=host)}
    if local:
        taken |= local_listeners(executor, timeout=timeout)
    chosen = [port for port in ports if port not in taken][:count]
    if len(chosen) < count:
        raise ValueError("TUNNEL_PORT_RANGE_EXHAUSTED")
    session_registry.reserve_resources(
        run_dir, owner=owner,
        resources=[{"host": host, "port": port, "protocol": "tcp"} for port in chosen])
    return chosen


def live(run_dir, host) -> dict:
    """覆盖这个地址的、还活着的隧道；没有就返回 {}（调用方据此如实说"没有隧道"）。"""
    for row in rows(run_dir):
        if row.get("alive") and covers(row, host):
            return row
    return {}
