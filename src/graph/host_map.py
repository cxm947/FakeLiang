"""Combine graph host names and host,ip CSV rows into {host, ips} entries."""

import csv
from ipaddress import ip_address
from pathlib import Path


def read_host_map(path, *, hosts=()) -> tuple[list[dict], int]:
    """Return the inventory and data-row count, including duplicate records."""
    addresses = {host: set() for host in hosts}
    records = 0
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream, skipinitialspace=True, strict=True)
        try:
            for row in reader:
                cells = [cell.strip() for cell in row]
                if not cells or not any(cells) or cells[0].startswith("#"):
                    continue
                if cells[:2] == ["host", "ip"]:
                    continue
                if len(cells) < 2 or not cells[0]:
                    raise ValueError("expected host,ip")
                host, address = cells[:2]
                addresses.setdefault(host, set()).add(ip_address(address))
                records += 1
        except (csv.Error, ValueError) as error:
            raise ValueError(f"host map line {reader.line_num}: {error}") from error
    return [
        {"host": host, "ips": [str(address) for address in sorted(
            addresses[host], key=lambda address: (address.version, int(address)))]}
        for host in sorted(addresses)
    ], records


def read_hosts(path, *, hosts=()) -> list[dict]:
    """Keep logical names distinct, even when they share an IP address."""
    return read_host_map(path, hosts=hosts)[0]
