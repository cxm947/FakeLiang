"""Observed interface prefixes and graph-declared tunnel targets."""
from __future__ import annotations

import json
from ipaddress import ip_address, ip_network


def _windows_prefixes(text) -> set:
    """Prefixes from WMI's list format: `IPAddress=…` / `IPSubnet=…`, one pair per adapter group."""
    found, addresses, masks = set(), [], []

    def flush():
        for address, mask in zip(addresses, masks):
            try:
                net = ip_network("%s/%s" % (address, _prefix_from_mask(mask)), strict=False)
                if net.version == 4 and not ip_address(address).is_loopback:
                    found.add(str(net))
            except (TypeError, ValueError):
                continue
        addresses.clear()
        masks.clear()

    for line in str(text or "").splitlines():
        key, separator, value = line.strip().partition("=")
        if not separator:
            continue
        #: WMI prints a multi-valued property as WQL set syntax: {"192.0.2.30","fe80::1"}
        parts = [item.strip().strip('"')
                 for item in value.strip().strip("{}").split(",") if item.strip()]
        if key.strip().lower() == "ipaddress":
            #: one adapter per group, and WMI separates the two properties with a blank line --
            #: the group ends when the next address arrives, never on a blank line
            if addresses:
                flush()
            addresses.extend(parts)
        elif key.strip().lower() == "ipsubnet":
            masks.extend(parts)
    flush()
    return found


def _as_list(value):
    """WMI answers a single adapter as a scalar and several as a list; both mean "a list"."""
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _prefix_from_mask(mask) -> int:
    """A dotted IPv4 netmask as its prefix length; anything else refuses."""
    binary = bin(int(ip_address(str(mask))))[2:]
    bits = binary.count("1")
    #: a netmask is contiguous: once the zeros start, a one means it is not a netmask at all
    if bits and "1" in binary.lstrip("1"):
        raise ValueError("TUNNEL_MASK_NOT_CONTIGUOUS")
    return bits


def _json_documents(text, *, marker="", first=None):
    """Every JSON document an answer carries: the framed body, or one object per line."""
    from runtime import session_io

    text = str(text or "")
    for candidate in ([session_io._frame_body(text, marker)] if marker else []) + [text]:
        if not candidate:
            continue
        try:
            yield json.loads(candidate)
            return
        except ValueError:
            continue
    for line in text.splitlines():
        try:
            yield json.loads(line)
        except ValueError:
            continue


def local_subnets(executor, channel, *, timeout=45.0) -> list:
    """Read actual interface prefixes; never invent a /24 network."""
    from runtime import session_io
    platform = str(channel.get("platform") or "").lower()
    if platform.startswith("windows"):
        #: `Get-NetIPAddress` needs Windows 8+ and `ConvertTo-Json` needs PowerShell 3+ (Windows 7
        #: ships 2.0), so both miss on the machines we actually meet (measured 2026-10-09). WMI's
        #: list format exists everywhere and its field names are English on every locale.
        request = {"tool": "cmd", "cmd": (
            "wmic nicconfig where IPEnabled=true get IPAddress,IPSubnet /format:list")}
    elif platform.startswith("linux"):
        request = {"tool": "tool", "name": "ip", "args": ["-j", "-4", "addr", "show"]}
    else:
        raise ValueError("TUNNEL_PLATFORM_UNDECLARED")
    result = session_io.call_bound(channel, request, timeout)
    if not result["confirmed"] or result["command_rc"] != 0:
        return []
    found = set()
    if platform.startswith("windows"):
        return sorted(_windows_prefixes(str(result["outcome"].stdout or "")))
    for parsed in _json_documents(str(result["outcome"].stdout or ""),
                                  marker=result.get("marker") or ""):
        entries = parsed if isinstance(parsed, list) else [parsed]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if platform.startswith("windows"):
                #: WMI answers one entry per adapter with parallel IPv4/IPv6 lists.
                addresses = list(zip(_as_list(entry.get("IPAddress")),
                                     _as_list(entry.get("IPSubnet"))))
            else:
                addresses = [(item.get("local"), item.get("prefixlen"))
                             for item in entry.get("addr_info") or [] if isinstance(item, dict)]
            for address, prefix in addresses:
                try:
                    address = ip_address(str(address))
                    if platform.startswith("windows") and str(prefix).count(".") == 3:
                        prefix = _prefix_from_mask(prefix)
                    if type(prefix) is not int or not 0 <= prefix <= address.max_prefixlen:
                        continue
                    if address.version != 4 or address.is_loopback or address.is_link_local:
                        continue
                    found.add(str(ip_network("%s/%s" % (address, prefix), strict=False)))
                except (KeyError, TypeError, ValueError):
                    continue
    return sorted(found)


def covering_subnets(host_map, *, exclude_prefix="192.168.52.") -> list:
    """主机-地址映射里**控制端自己到不了**的那些 /24（排除控制端自己的网段）。"""
    found = []
    for address in (host_map or {}).values():
        text = str(address or "").strip()
        #: 只认"像主机地址"的值：主机-地址表里可能混着**掩码**（255.255.255.0）、广播或空值，
        #: 拿它们去加转发只会白装一条永远不通的路（2026-10-07 实测：掩码被当成主机，
        #: 给 DC 加了一条指向 255.255.255.0 的转发，整条隧道因此判失败，node 48 拿不到隧道）。
        octets = text.split(".")
        if (text.count(".") != 3 or text.startswith(exclude_prefix)
                or not all(part.isdigit() and 0 <= int(part) <= 255 for part in octets)
                or octets[0] == "255" or octets[0] == "0" or text.endswith(".0")
                or text.endswith(".255") or text.startswith("127.")):
            continue
        prefix = ".".join(text.split(".")[:3]) + ".0/24"
        if prefix not in found:
            found.append(prefix)
    return sorted(found)


def probes_from_facts(document, host_map, *, subnets) -> list:
    """从攻击图的 OR 事实里取 [(地址, 端口), …]：**图自己说的端口**比猜的可靠。

    本图用 `hacl(从,到,协议,端口)` 与 `networkServiceInfo(主机,服务,协议,端口,权限)`；
    别的图可能写 `netAccess(主机,tcp,端口)`，三种都认。`execCode(主机,权限)` 按 445 试。
    """
    import re
    patterns = (r"hacl\([^,]+,\s*([A-Za-z0-9_.\-]+)\s*,[^,]*,\s*(\d+)\s*\)",
                r"networkServiceInfo\(([A-Za-z0-9_.\-]+)\s*,[^,]*,[^,]*,\s*(\d+)\s*,",
                r"netAccess\(([A-Za-z0-9_.\-]+)\s*,\s*[A-Za-z0-9_]+\s*,\s*(\d+)\s*\)")
    wanted, seen = [], set()

    def add(logical, port):
        address = str((host_map or {}).get(str(logical).strip()) or "")
        if address and (address, str(port)) not in seen:
            seen.add((address, str(port)))
            wanted.append((address, str(port)))

    for node in (document or {}).get("nodes") or []:
        for dep in node.get("dependencies") or []:
            text = str(dep.get("description") or dep.get("ref") or "")
            for pattern in patterns:
                for logical, port in re.findall(pattern, text):
                    add(logical, port)
            for logical in re.findall(r"execCode\(([A-Za-z0-9_.\-]+)\s*,[^)]+\)", text):
                add(logical, "445")
    return [item for item in wanted
            if any(item[0].startswith(str(subnet).split("/")[0].rsplit(".", 1)[0] + ".")
                   for subnet in subnets)]


def targets_for(document, host_map) -> list:
    """The (address, port) pairs this run's graph says live behind a pivot.

    Off-control-box /24s come from the host map, the ports from the graph's own facts -- guessing
    a service port is what makes a forward look installed while nothing flows through it.
    """
    subnets = covering_subnets(host_map)
    if not subnets:
        return []
    return sorted({(str(address), str(port))
                   for address, port in probes_from_facts(document, host_map, subnets=subnets)})
