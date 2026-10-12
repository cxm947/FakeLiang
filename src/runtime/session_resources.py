"""Session resources: pick a port on a pivot, and read the ones the control box already holds."""
from __future__ import annotations


#: 跨网段交付：跳板侧的监听端口带（与控制端的交付带分开，方便认账与回收）。
RELAY_PIVOT_BAND = (2090, 2099)


def free_pivot_port(carrier, *, band=RELAY_PIVOT_BAND, timeout=30.0, taken=()):
    """Pick a port on the pivot that nothing is using *and* no plan already holds.

    Free on the pivot is not enough: walk-145 node 48 picked a port that node 44's plan still
    leased and the reservation refused with a bare SESSION_RESOURCE_BUSY. `taken` carries the
    leases of this run so the choice skips them.
    """
    from runtime import session_io, session_registry, sessions
    held = {int(port) for port in taken}
    for port in range(int(band[0]), int(band[1]) + 1):
        if port in held:
            continue
        result = session_io.call_bound(
            carrier, {"tool": "cmd", "cmd": "netstat -an | findstr :%d" % port}, timeout)
        text = str(getattr(result.get("outcome"), "stdout", "") or "").upper()
        if "LISTENING" in text or "ESTABLISHED" in text:
            continue
        return port
    return 0


def _handler_ports_with_sessions(call) -> set:
    """控制台里**已有会话挂靠**的端口。这些 handler 不许碰：停掉它们是给活会话找麻烦。"""
    listing = call("session.list") or {}
    ports = set()
    #: 回复有两种形状（实测都出现过）：`{sid: info}` 与 `{"sessions": {sid: info}}`。
    #: 只认一种的后果很严重 —— 认不出就以为"没有会话挂靠"，接着把正在用的 handler 停掉。
    rows = listing
    if isinstance(listing, dict) and isinstance(listing.get("sessions"), dict):
        rows = listing["sessions"]
    if isinstance(rows, dict):
        for info in rows.values():
            for key in ("tunnel_local", "tunnel_peer"):
                tail = str((info or {}).get(key) or "").rsplit(":", 1)[-1]
                if tail.isdigit():
                    ports.add(int(tail))
    return ports


#: Delivery resources live in one band so a stale one is always recognisable and reapable.
DELIVERY_PORT_BAND = tuple(range(1080, 1150))


def free_delivery_ports(executor, *, band=DELIVERY_PORT_BAND, timeout=30.0):
    """Read the ports this control box already listens on; never guess or scan."""
    outcome = executor(["/bin/sh", "-c",
                        "ss -lnt 2>/dev/null | awk '{print $4}' | sed 's/.*://'"], timeout)
    tokens = str(getattr(outcome, "stdout", "") or "").replace("\r", "").split()
    busy = {int(token) for token in tokens if token.isdigit()}
    return [port for port in band if port not in busy]
