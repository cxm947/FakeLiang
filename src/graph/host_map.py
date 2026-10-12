"""Host map rows and the deployment profile -> the document's hosts[] block.

The map (``host,ip`` rows, '#' comments, header optional) is the only place a logical host
name gets an address; several rows for one host are its interfaces. A container entity takes
its address from the profile's observed local IP and keeps its parent host. Local data only.
"""

from __future__ import annotations

import csv
import json
from ipaddress import ip_address
from pathlib import Path


def _ip_key(value: str):
    parsed = ip_address(value)
    if parsed.version == 4:
        return (4, tuple(int(part) for part in str(parsed).split(".")))
    return (6, parsed.packed)


def read_rows(path) -> list[tuple[str, str]]:
    """``host,ip`` rows: '#' comments, optional header, one row per interface."""
    rows: list[tuple[str, str]] = []
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.reader(stream, strict=True):
            cells = [cell.strip() for cell in row]
            if not cells or cells[0].startswith("#"):
                continue
            if len(cells) < 2:
                raise ValueError("host map rows must have at least two fields")
            host, address = cells[0], cells[1]
            if host == "host" and address == "ip":
                continue
            try:
                ip_address(address)
            except ValueError as error:
                raise ValueError("host map row " + repr(host) + ": " + repr(address)
                                 + " is not an IP address") from error
            rows.append((host, address))
    return rows


def load_profile(path) -> dict:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("deployment profile must decode to a JSON object")
    return payload


def build_hosts(rows, profile: dict | None = None) -> list[dict]:
    entities: dict[str, dict] = {}

    def entity(host: str) -> dict:
        return entities.setdefault(host, {"host": host, "aliases": [], "kind": "host",
                                          "parent": None, "ips": []})

    for host, address in rows:
        entry = entity(host)
        if address not in entry["ips"]:
            entry["ips"].append(address)
    for host, meta in ((profile or {}).get("hosts") or {}).items():
        if not isinstance(meta, dict):
            continue
        entry = entity(str(host))
        if meta.get("kind") == "container":
            entry["kind"] = "container"
            entry["parent"] = meta.get("parent")
        addresses = list(meta.get("ips") or [])
        observed = (meta.get("observed_local") or {}).get("ip")
        if observed:
            addresses.append(observed)
        for address in addresses:
            if address and address not in entry["ips"]:
                entry["ips"].append(address)
    for entry in entities.values():
        entry["ips"].sort(key=_ip_key)
    return [entities[host] for host in sorted(entities)]


class HostIndex:
    """Term -> host references (E9): names resolve to themselves, addresses to their owners."""

    def __init__(self, hosts: list[dict] | None = None):
        self.by_name = {entry["host"]: entry for entry in hosts or []}
        self.by_ip: dict[str, list[str]] = {}
        for entry in hosts or []:
            for address in entry["ips"]:
                self.by_ip.setdefault(address, []).append(entry["host"])

    def refs(self, term: str) -> list[str]:
        if term in self.by_name:
            return [term]
        return list(self.by_ip.get(term, []))

    def entry(self, term: str) -> dict:
        """E9: omit host_refs when the term resolves to itself; keep on composite/one-to-many/none."""
        refs = self.refs(term)
        if refs == [term]:
            return {"term": term}
        return {"term": term, "host_refs": refs}