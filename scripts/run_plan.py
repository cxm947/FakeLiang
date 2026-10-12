#!/usr/bin/env python3
"""Light planner: walk the graph in dependency order, one node at a time, through the executor.

What the engine owns is *readiness*: a node is ready when every OR fact it consumes was produced
by a node this walk already proved (the graph's own ``produced_by`` rows). A node whose report is
not a pass is recorded, and its consumers stay blocked - nothing advances on a claim.

What the model owns is everything inside a node: the executor asks it for one action at a time.

Credential supply uses proved getAccount facts and private material references.
Consumers receive derived material first, then the declared external account;
ambiguous or unavailable material is refused.
Channel selection, probing and migration retain their existing behavior.

Usage:
  python scripts/run_plan.py --graph <graph.json> --host-map <map.csv> --run-root <dir>
      --remote kali@<host> --password <pw> --model <name>
      [--model-base-url <url>] [--model-api-key-env VAR] [--max-nodes N] [--max-steps N]
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import json
import time
from pathlib import Path
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import json
import os
import sys

from agents._model import client as model_mod  # noqa: E402
from graph.paths import resolve_path  # noqa: E402
from runtime import session_io, sessions  # noqa: E402
from runtime.lean import mask_secrets  # noqa: E402
from runtime.remote import SshExecutor, parse_remote  # noqa: E402

from orchestration import bootstrap, cli, positions, reporting  # noqa: E402
from orchestration.contracts import StepLimits  # noqa: E402
from orchestration.walk import run_walk  # noqa: E402

from agents.executor import driver as run_lean_task  # noqa: E402
import run_node  # noqa: E402


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    args = cli.parse_args(argv, description=__doc__)
    root = resolve_path(args.run_root)
    graph_label, document = bootstrap.load_graph_document(
        args.graph, host_map=args.host_map,
        assets=args.graph_assets, run_root=root,
    )
    host_map = (
        run_node.host_map_of(resolve_path(args.host_map))
        if args.host_map else {}
    )
    host_environments = (
        positions.host_contexts(resolve_path(args.host_map))
        if args.host_map else {}
    )
    control = str(args.control or host_map.get("control") or "")
    rpc_secret = (
        args.msf_rpc or os.environ.get("AGV_MSF_RPC", "")
    ).partition("@")[0].partition(":")[2]
    secrets = [
        value for value in (
            args.password, os.environ.get(args.model_api_key_env), rpc_secret
        ) if value
    ]
    try:
        credentials = bootstrap.load_credentials(
            root=root, repository=ROOT, document=document,
            host_map=host_map,
            carry_from=resolve_path(args.carry_from) if args.carry_from else None,
            source_path=resolve_path(args.credentials) if args.credentials else None,
            materials_dir=resolve_path(args.materials_dir) if args.materials_dir else None,
            secrets=secrets,
        )
    except (ValueError, OSError) as error:
        print(json.dumps(
            mask_secrets({"status": "blocked", "reason": str(error)}, secrets),
            ensure_ascii=False,
        ))
        return 2

    #: Freeze the model backend only after every refusal path has passed: this call may create
    #: the run root, and a refused run must leave no directory behind.
    from agents._model.backend import freeze_backend
    try:
        backend = freeze_backend(root)
    except ValueError as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}))
        return 2

    root.mkdir(parents=True, exist_ok=True)
    remote = parse_remote(args.remote)
    executor = SshExecutor(
        remote, password=args.password, key_filename=args.key
    )
    try:
        client = model_mod.client_from_env(
            name=args.model, base_url=args.model_base_url,
            api_key_env=args.model_api_key_env,
            timeout=args.model_timeout, wire=args.model_wire, backend=backend,
        )
        rpc_conf = bootstrap.rpc_config(args.msf_rpc, control=control)
        secrets.extend(
            value for value in (rpc_conf.get("rpc_password"),) if value
        )
        if args.msf_rpc:
            os.environ["AGV_MSF_RPC"] = str(args.msf_rpc)
        if rpc_conf:
            ensured = session_io.ensure_console(
                host=str(rpc_conf.get("rpc_host") or control),
                port=int(rpc_conf.get("rpc_port") or 55553),
                user=str(rpc_conf.get("rpc_user") or "msf"),
                password=str(rpc_conf.get("rpc_password") or ""),
            )
            print("控制台：" + json.dumps(ensured, ensure_ascii=False), flush=True)
        if args.carry_from and not args.resume:
            carried, closed, _superseded = sessions.carry_handles(
                resolve_path(args.carry_from), root, executor=executor
            )
            print("carried:", carried, "| closed:", closed)
        walk = run_walk(
            document=document, graph_label=str(graph_label),
            root=root, repository=ROOT, host_map=host_map,
            host_environments=host_environments,
            executor=executor, executor_host=remote.host, client=client,
            control=control, rpc_conf=rpc_conf, credentials=credentials,
            limits=StepLimits(
                python=args.python, timeout=args.timeout,
                max_steps=args.max_steps, model_timeout=args.model_timeout,
            ),
            max_nodes=args.max_nodes, secrets=secrets, resume=args.resume,
            prepare_task=run_node.prepare, drive=run_lean_task.drive,
        )
    finally:
        executor.close()

    if walk.planner_error is not None:
        return 2

    def render_journal(run_root, *, graph_path):
        import journal
        return journal.render(run_root, graph_path=graph_path)

    def write_transcripts(run_name):
        import node_transcript
        return node_transcript.write_all(run_name)

    return reporting.settle_walk(
        root=root, document=document, graph_label=str(graph_label),
        host_map=host_map, state=walk.state, order=walk.order,
        planner_notes=walk.planner_notes, planner_trace=walk.planner_trace,
        secrets=secrets, render_journal=render_journal,
        write_transcripts=write_transcripts,
    )


if __name__ == "__main__":
    raise SystemExit(main())
