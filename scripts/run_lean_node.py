#!/usr/bin/env python
"""Drive one graph node through the executor (opt-in; no graph fact or session is registered).

What it does: read the compiled graph, take the node's own fixed fields (target host, port,
transport), pick the card named on the command line, build the lean task and its single endpoint
scope, and hand both to the same loop `run_lean_task` uses. Nothing else is derived: the
graph -> card binding is the selector's job in the old path and is not replaced here.

What it does not do (and says so in the result): no session delivery, no graph fact registration,
no cross-run reuse. The result is a model report whose citations were checked against this run's
own raw output - not a machine fact.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from graph import rehydrate          # noqa: E402
from skills.lean import load_card    # noqa: E402
import run_lean_task                 # noqa: E402


def host_map_of(path):
    rows = {}
    if not path:
        return rows
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        cells = [cell.strip() for cell in text.split(",")]
        if len(cells) >= 2 and cells[0] != "host":
            rows.setdefault(cells[0], cells[1])
    return rows


def node_of(graph_path, node_id):
    document = rehydrate.load_file(graph_path)
    for item in document["nodes"]:
        if str(item.get("id")) == str(node_id):
            return item
    raise SystemExit("LEAN_NODE_NOT_FOUND: " + str(node_id))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--card", required=True)
    parser.add_argument("--host-map", default="")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--goal", default="")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--actions")
    source.add_argument("--model")
    remote = parser.add_mutually_exclusive_group()
    remote.add_argument("--remote")
    remote.add_argument("--chain")
    parser.add_argument("--password")
    parser.add_argument("--key")
    parser.add_argument("--python", default="python3")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--max-steps", type=int, default=8)
    parser.add_argument("--model-base-url", default="")
    parser.add_argument("--model-api-key-env", default="AGV_MODEL_API_KEY")
    parser.add_argument("--model-timeout", type=float, default=60)
    args = parser.parse_args(argv)

    node = node_of(args.graph, args.node)
    mapping = host_map_of(args.host_map)
    logical = str(node.get("target_host") or "")
    host = mapping.get(logical, logical)
    port = node.get("port")
    card = load_card(args.card, ROOT)
    if card.get("runs_at") == "base" and not mapping.get(logical, logical):
        raise SystemExit("LEAN_NODE_NO_ENDPOINT: " + logical)
    if not host or port in (None, ""):
        raise SystemExit("LEAN_NODE_NO_ENDPOINT: %s:%s" % (logical, port))

    scope = {"host": host, "port": int(port), "protocol": "tcp",
             "vantage": "base", "resources": "whole_endpoint"}
    inputs = {"target_host": host, "port": str(port),
              "protocol": str(node.get("protocol") or "tcp")}
    task = {"node_id": str(node.get("id")),
            "goal": args.goal or str(node.get("description") or ""),
            "inputs": inputs, "scope": scope}
    delegated = ["--card", args.card, "--task", json.dumps(task, ensure_ascii=False),
                 "--run-dir", args.run_dir]
    if args.actions is not None:
        delegated += ["--actions", args.actions]
    else:
        delegated += ["--model", args.model]
    if args.remote:
        delegated += ["--remote", args.remote]
    if args.chain:
        delegated += ["--chain", args.chain]
    for flag, value in (("--password", args.password), ("--key", args.key)):
        if value:
            delegated += [flag, value]
    delegated += ["--python", args.python, "--timeout", str(args.timeout),
                  "--max-steps", str(args.max_steps),
                  "--model-base-url", args.model_base_url,
                  "--model-api-key-env", args.model_api_key_env,
                  "--model-timeout", str(args.model_timeout)]
    print(json.dumps({"node": task["node_id"], "card": card["id"], "endpoint": scope,
                      "registers_graph_facts": False, "registers_sessions": False},
                     ensure_ascii=False))
    return run_lean_task.main(delegated)


if __name__ == "__main__":
    raise SystemExit(main())
