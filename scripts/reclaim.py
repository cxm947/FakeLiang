#!/usr/bin/env python3
"""Reclaim: undo what a run did, generically.

Everything this script touches comes from the ledger of the run it is given: the hosts are the
hosts the run recorded handles for, the sessions are the session ids it recorded, and the files it
removes are the ones our own tools name with one prefix. Nothing here lists "our lab": that is the
point - a new deployment is reclaimed with the same command.

Order matters and is deliberate:

1. **Stop the remote payload first.** A payload whose handler is gone keeps dialing forever (the
   fd/thread pile-up in the session-management notes came from exactly that), so it goes before
   the framework side.
2. **Stop the framework session/job.** Sessions we recorded are stopped by id; jobs are stopped
   only when asked for explicitly, because a job id we never recorded cannot be attributed to us
   on a console someone else may share.
3. **Remove our files** on each host we can still reach (the one prefix our tools use).
4. **Close the ledger rows**, so a later carry cannot bring a dead handle forward as if it lived.

Default is a dry run: it prints the plan, changes nothing. --apply performs it. --lab adds the two
leftovers that are specific to the validation lab (redis config pointing at a key file, the planted
authorized_keys line) because those are the deployment, not the tool.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime import session_io, session_registry, sessions   # noqa: E402
from runtime.runner import ExecOutcome             # noqa: E402
from runtime import artifacts as artifact_ledger    # noqa: E402
from runtime import harvest                         # noqa: E402
from runtime.remote import SshExecutor, parse_remote   # noqa: E402

from scripts.reclaim_hosts import (
    ARTIFACT_PREFIX, KILL_SCRIPT, REMOVE_SCRIPT, hosts_of,
    KILL_SCRIPT_WINDOWS, REMOVE_SCRIPT_WINDOWS, clean_host,
    LEFT_OVER_LINUX, LEFT_OVER_WINDOWS, SECTION_RULE,
    _parse_leftover, _leftover_items, leftover_scan, lab_extras,
)

def stop_framework(executor, rows, rpc_conf, *, apply=False, all_jobs=False, run_dir=None):
    """Stop only the authoritative incarnation named by the owned registry binding."""
    import time
    from runtime import channels, msfservice

    if not rpc_conf:
        return ["No console configured: pass --msf-rpc user:password@host:port"]
    endpoint = msfservice.Endpoint(host=rpc_conf["host"], port=rpc_conf["port"],
                                   user=rpc_conf["user"], password=rpc_conf["password"])
    identity = {"host": endpoint.host, "port": endpoint.port, "ssl": endpoint.ssl}
    lines = []
    for row in rows:
        sid = str(row.get("session_id") or "")
        if not sid:
            continue
        if row.get("endpoint") != identity:
            lines.append("session %s: RECLAIM_ENDPOINT_MISMATCH" % sid)
            continue
        if not apply:
            lines.append("Would stop session %s" % sid)
            continue
        if run_dir is None:
            lines.append("session %s: RECLAIM_REGISTRY_UNBOUND" % sid)
            continue
        hold = None
        try:
            hold = channels.begin_use(row)
            deadline = time.monotonic() + 90.0
            client = msfservice.client_for(endpoint, deadline=deadline)
            observed = msfservice.session_shape(client, sid, deadline=deadline)
            declared_uuid, observed_uuid = row.get("uuid"), observed.get("uuid")
            declared_host, observed_host = row.get("host"), observed.get("session_host")
            if (not isinstance(declared_uuid, str) or not declared_uuid.strip()
                    or not isinstance(observed_uuid, str) or not observed_uuid.strip()
                    or not isinstance(declared_host, str) or not declared_host.strip()
                    or not isinstance(observed_host, str) or not observed_host.strip()
                    or row.get("session_type") not in {"shell", "meterpreter"}
                    or observed.get("type") not in {"shell", "meterpreter"}):
                lines.append("session %s: RECLAIM_IDENTITY_UNCONFIRMED" % sid)
                continue
            if (declared_uuid != observed_uuid or declared_host != observed_host
                    or row["session_type"] != observed["type"]):
                lines.append("session %s: RECLAIM_IDENTITY_CHANGED" % sid)
                continue
            stopped = msfservice.stop_session(client, sid, deadline=deadline)
            if stopped:
                sessions.revoke_session(
                    run_dir, row, receipt={"session_id": sid, "state": "stopped"},
                    timeout=max(0.0, deadline - time.monotonic()))
                lines.append("session %s stopped and registration revoked" % sid)
            else:
                lines.append("session %s: RECLAIM_STOP_UNCONFIRMED" % sid)
        except msfservice.MsfSessionMissing:
            lines.append("session %s: RECLAIM_SESSION_MISSING" % sid)
        except msfservice.MsfUnreachable as error:
            lines.append("session %s: RECLAIM_RPC_UNCONFIRMED %s" % (sid, str(error)[:120]))
        except (ValueError, OSError) as error:
            lines.append("session %s: RECLAIM_STOP_UNCONFIRMED %s" % (sid, str(error)[:120]))
        finally:
            if hold is not None:
                channels.end_use(hold)
    if all_jobs:
        deadline = time.monotonic() + 90.0
        client = msfservice.client_for(endpoint, deadline=deadline)
        jobs = msfservice.raw_call(client, "job.list", deadline=deadline) or {}
        for job_id in jobs if isinstance(jobs, dict) else ():
            if apply:
                msfservice.raw_call(client, "job.stop", [str(job_id)], deadline=deadline)
            lines.append("%s job %s" % ("Stop requested for" if apply else "Would stop", job_id))
    return lines or ["Nothing to stop on the console side"]
def executor_spellings(executor, rows, remote) -> dict:
    """Resolve only unique recorded bindings; ambiguous host aliases stay unbound."""
    from runtime import dispatch

    candidates = {}

    def add(name, identity, call):
        candidates.setdefault(name, {})[identity] = call

    def for_binding(binding):
        def command(argv, timeout):
            request = dispatch.command_request(argv, platform=binding.get("platform"))
            result = session_io.call_bound(binding, request, timeout)
            outcome = result["outcome"]
            return ExecOutcome(
                returncode=result["command_rc"] if result["confirmed"] else None,
                stdout=outcome.stdout, stderr=outcome.stderr,
                timed_out=outcome.timed_out, tool_error=outcome.tool_error,
                read_stop=outcome.read_stop)
        return command

    if remote:
        target = parse_remote(remote)
        for key in (target.label(), target.host, ""):
            add(key, "base:" + target.label(), executor)
    else:
        add("", "base", executor)
    for row in rows or ():
        if not isinstance(row.get("endpoint"), dict) or not row.get("session_id"):
            continue
        identity = json.dumps({"endpoint": row["endpoint"], "session_id": row["session_id"]},
                              sort_keys=True, separators=(",", ":"))
        call = for_binding(row)
        names = {str(row.get("logical") or ""), str(row.get("host") or "")}
        for name in names - {""}:
            add(name, identity, call)
    return {name: next(iter(items.values())) for name, items in candidates.items()
            if len(items) == 1}


def reclaim_delivery_plans(root, *, executor, rpc_conf=None, apply=False):
    """Recover explicit delivery cleanup before any carrier or framework session is stopped."""
    from runtime import session_delivery
    out = []
    for path in sorted((Path(root) / "delivery").glob("*/plan.json")):
        try:
            plan = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(plan, dict) or plan.get("owner") != path.parent.name:
                raise ValueError("SESSION_DELIVERY_PLAN_MISMATCH")
            if plan.get("state") in ("cleaned", "not_started"):
                continue
            if not apply:
                out.append({"owner": plan["owner"], "state": "planned",
                            "reason": "DECLARED_DELIVERY_CLEANUP"})
                continue
            configuration = rpc_conf or {}
            result = session_delivery.cancel_session_delivery(
                executor=executor, plan=plan, root=root,
                rpc_conf={"rpc_password": configuration.get("password") or ""})
            out.append(dict(result, owner=plan["owner"]))
        except (ValueError, OSError, RuntimeError) as error:
            out.append({"owner": path.parent.name, "state": "unknown", "reason": str(error)})
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(prog="reclaim.py", description=__doc__)
    parser.add_argument("--ledger", required=True, help="run directory holding channels.jsonl")
    parser.add_argument("--remote", default="", help="control box to run from (kali@host)")
    parser.add_argument("--password", default=None)
    parser.add_argument("--msf-rpc", default="", help="user:password@host:port of the console")
    parser.add_argument("--apply", action="store_true", help="actually do it (default: dry run)")
    parser.add_argument("--all-jobs", action="store_true",
                        help="also stop every job on the console (dedicated consoles only)")
    parser.add_argument("--lab", action="store_true", help="also undo the lab-specific leftovers")
    args = parser.parse_args(argv)

    root = Path(args.ledger)
    rows = session_registry.snapshot(root)
    hosts, carriers = hosts_of(rows)
    rpc_conf = {}
    if args.msf_rpc:
        head, _, tail = args.msf_rpc.partition("@")
        user, _, password = head.partition(":")
        host, _, port = tail.partition(":")
        rpc_conf = {"user": user, "password": password, "host": host or "127.0.0.1",
                    "port": int(port or 55553)}

    print("ledger: %s" % root)
    print("handles: %d | hosts: %s" % (len(rows), ", ".join(hosts) or "-"))
    print("mode: %s" % ("APPLY" if args.apply else "dry run"))
    owner = None
    try:
        if args.remote:
            owner = SshExecutor(parse_remote(args.remote), password=args.password)
        executor = owner or (lambda argv, timeout: None)
        if args.msf_rpc:
            import os
            os.environ["AGV_MSF_RPC"] = args.msf_rpc
        delivery_cleanup = reclaim_delivery_plans(
            root, executor=executor, rpc_conf=rpc_conf, apply=args.apply)
        for row in delivery_cleanup:
            print("delivery cleanup: " + json.dumps(row, ensure_ascii=False))
        if args.apply and any(row.get("state") != "completed" for row in delivery_cleanup):
            print("SESSION_DELIVERY_CLEANUP_UNCONFIRMED: carriers and resource ownership retained")
            return 2
        print("")
        print("-- 1) resources while their sessions are available --")
        print("")
        #: 产物表要**趁入口还活着**倒着撤：等下一步把控制台会话停了再撤，跳板上的转发/防火墙规则
        #: 就没人能去删了（2026-10-06 实测：PC1 的 portproxy 就是这么留在那儿的）。
        print("-- 2) 产物表（我们改过什么，倒着撤）--")
        produced = artifact_ledger.read(root)
        if not produced:
            print("  产物表为空（这一轮没记下任何改动，或它是旧验证轮次）")
        else:
            executors = executor_spellings(executor, rows, args.remote)
            for line in artifact_ledger.revert(root, produced, executors=executors,
                                               apply=args.apply):
                print("  " + line)
            needs_a_human = artifact_ledger.manual(produced)
            if needs_a_human:
                print("  %d artifact(s) require manual cleanup" % len(needs_a_human))
                for row in needs_a_human:
                    print("    %s %s @%s" % (row.get("kind"), row.get("target"), row.get("host")))
        print("-- 2) remote payload cleanup --")
        for carrier in carriers:
            print("  " + clean_host(executor, carrier, apply=args.apply))
        print("-- 2.5) cleanup observations --")
        for line in leftover_scan(executor, rows, apply=args.apply):
            print("  " + line)
        print("")
        print("-- 3) console sessions/jobs --")
        for line in stop_framework(executor, rows, rpc_conf, apply=args.apply,
                                   all_jobs=args.all_jobs, run_dir=root):
            print("  " + line)
        print("")
        print("-- 4) session registry --")
        print("  %d registered session(s) remain" % len(session_registry.snapshot(root)))
        if args.lab:
            print("")
            print("-- 5) lab-specific leftovers --")
            control = parse_remote(args.remote).host if args.remote else ""
            for line in lab_extras(executor, rows, apply=args.apply,
                                   skip_hosts=[control] if control else []):
                print("  " + line)
    finally:
        if owner:
            owner.close()
    print("")
    print("done%s" % ("" if args.apply else " (nothing was changed - pass --apply)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
