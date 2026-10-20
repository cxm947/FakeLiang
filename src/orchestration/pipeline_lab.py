"""Serial lifecycle using the existing six-VM reset and VMware wrapper."""

from pathlib import Path
from socket import create_connection
from time import monotonic, sleep

from run_action import rollback_lab, save
from src.session.planner_store import now


def validate_console(spec):
    """The controller endpoint is deployment-declared, never inferred."""
    if not isinstance(spec, dict) or not {"vm", "command", "address", "port"} <= set(spec):
        raise ValueError("Console spec needs vm, command, address and port")
    if any(not isinstance(spec[key], str) or not spec[key].strip()
           for key in ("vm", "command", "address")):
        raise ValueError("Console spec needs nonempty vm, command and address")
    if type(spec["port"]) is not int or not 1 <= spec["port"] <= 65535:
        raise ValueError("Console port is invalid")


def _tcp_open(address, port, timeout=2.0):
    try:
        with create_connection((str(address), int(port)), timeout):
            return True
    except OSError:
        return False


def console_up(guest, spec, directory, *, probe=None):
    """Start the controller's session endpoint after a rollback and wait until it listens.

    A rolled-back controller carries nothing a run can rely on, so the deployment supplies
    one start command; readiness is observed on the real port rather than assumed.
    """
    validate_console(spec)
    probe = probe or _tcp_open
    path = Path(directory) / "console.json"
    progress = {"vm": spec["vm"], "address": spec["address"], "port": spec["port"],
                "started_at": now(), "status": "starting"}
    save(path, progress)
    try:
        result = guest.execute(spec["vm"], spec["command"], root=True)
        progress["transport_error"] = bool(result.get("transport_error"))
    except Exception as exc:
        progress.update(status="failed", category="会话没接上", error_type=type(exc).__name__)
        save(path, progress)
        raise
    deadline = monotonic() + float(spec.get("ready_timeout", 60))
    while True:
        if probe(spec["address"], spec["port"]):
            progress.update(status="ready", ready=True, finished_at=now())
            save(path, progress)
            return progress
        if monotonic() >= deadline:
            progress.update(status="failed", ready=False, category="会话没接上", finished_at=now())
            save(path, progress)
            raise ValueError("Console endpoint did not become ready")


def validate_lab(guest, snapshots):
    """Every declared VM must be unique and configured; the count is deployment data."""
    names = [item["vm"] for item in snapshots]
    if not names or len(set(names)) != len(names) or not set(names) <= set(guest.config.guests):
        raise ValueError("Every lab VM must be unique and configured")
    for item in snapshots:
        if not item["snapshot"] or not Path(guest.config.guests[item["vm"]].vmx).is_file():
            raise ValueError("Invalid VM or clean snapshot binding")


def apply_network(guest, entries, directory):
    """Apply the deployment's declared network prerequisites after a rollback.

    A clean snapshot does not contain the lab's attack path: the controller reaches the
    second segment through the dual-homed web host, and Docker's default FORWARD policy
    drops that traffic. These are topology facts of this deployment, so they are declared
    beside the snapshots instead of being typed by hand before every run.
    """
    path = Path(directory) / "network.json"
    progress = {"status": "applying", "records": []}
    save(path, progress)
    for entry in entries:
        record = {"vm": entry["vm"], "started_at": now()}
        try:
            result = guest.execute(entry["vm"], entry["command"],
                                   root=bool(entry.get("root", True)))
            record.update(status="applied" if result.get("return_code") == 0 else "failed",
                          return_code=result.get("return_code"),
                          stdout=str(result.get("stdout") or "")[-400:])
        except Exception as exc:
            record.update(status="failed", error_type=type(exc).__name__)
        progress["records"].append({**record, "finished_at": now()})
        save(path, progress)
    progress["status"] = ("failed" if any(row["status"] == "failed" for row in progress["records"])
                          else "applied")
    save(path, progress)
    return progress


def prepare_lab(guest, snapshots, directory, *, console=None, probe=None, network=()):
    """Roll back serially, apply network prerequisites, then bring the endpoint up."""
    validate_lab(guest, snapshots)
    progress = rollback_lab(guest, snapshots, directory)
    if network:
        progress["network"] = apply_network(guest, network, directory)
    if console is not None:
        console_up(guest, console, directory, probe=probe)
    return progress


def direct_services(request, controller_address):
    """Endpoints the controller itself can probe, derived from the graph and its hosts."""
    document = request.get("document") or request
    subnet = ".".join(str(controller_address).split(".")[:3]) + "."
    addresses = {row.get("host"): (row.get("ips") or [])
                 for row in document.get("hosts", [])}
    found = set()
    for node in document.get("nodes", []):
        host = str(node.get("target_host") or "")
        port = str(node.get("port") or "")
        if not host or not port.isdigit():
            continue
        for address in addresses.get(host, []):
            if str(address).startswith(subnet):
                found.add((str(address), int(port)))
    return sorted(found)


def wait_services(entries, directory, *, probe=None, timeout=900.0, interval=5.0):
    """Wait until every declared direct service accepts a TCP connection.

    A rolled-back lab starts its guests and their services on their own schedule. "The VM is
    powered on" is not "the service is ready": a node that ran while the application was
    still starting saw Connection refused and failed a step the target could have served
    moments later (live 2026-10-18, node 7). Only endpoints the controller can reach
    directly are waited on; the second segment stays behind the pivot.
    """
    probe = probe or _tcp_open
    path = Path(directory) / "services.json"
    pending = {(str(address), int(port)) for address, port in entries}
    progress = {"status": "waiting", "started_at": now(), "targets": len(pending),
                "records": []}
    save(path, progress)
    deadline = monotonic() + float(timeout)
    while pending and monotonic() < deadline:
        for address, port in sorted(pending):
            if probe(address, port):
                pending.discard((address, port))
                progress["records"].append({"address": address, "port": port,
                                            "ready_at": now()})
        if pending:
            save(path, progress)
            sleep(interval)
    progress["pending"] = [{"address": a, "port": p} for a, p in sorted(pending)]
    progress["status"] = "ready" if not pending else "timeout"
    progress["finished_at"] = now()
    save(path, progress)
    return progress


def cleanup_lab(guest, snapshots, directory):
    """Stop each VM once, in order; continue collecting receipts after failures."""
    validate_lab(guest, snapshots)
    progress = {"serial": True, "status": "stopping", "records": []}
    path = Path(directory) / "cleanup.json"
    for item in snapshots:
        progress["current"] = item["vm"]
        save(path, progress)
        record = {"vm": item["vm"], "started_at": now()}
        try:
            # Already powered-off VMs need no stop command.
            if guest.config.guests[item["vm"]].vmx in guest.running():
                guest.call(item["vm"], "stop", "soft", timeout=90)
            if guest.config.guests[item["vm"]].vmx in guest.running():
                raise RuntimeError("VM stop was not confirmed")
            record["status"] = "stopped"
        except Exception as exc:
            record.update(status="failed", category="会话没接上", error_type=type(exc).__name__)
        progress["records"].append({**record, "finished_at": now()})
        save(path, progress)
    progress.update(current=None, status="failed" if any(r["status"] == "failed"
                    for r in progress["records"]) else "completed")
    save(path, progress)
    return progress
