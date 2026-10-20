"""Create, inspect or manually resume a Pre task. Does not execute Action."""

import argparse
import json
from pathlib import Path

import yaml

from src.agents.pre_verifier.mcp_client import KaliMCP, load_mcp_config
from src.graph.files import atomic_write
from src.session.planner_store import PlannerStore
from src.session.pre_service import PreService


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["create", "resume", "inspect", "list"])
    parser.add_argument("--graph", type=Path)
    parser.add_argument("--node")
    parser.add_argument("--environment", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--confirm-environment", action="store_true")
    parser.add_argument("--mcp", type=Path, default=Path("configs/pre-mcp.local.yaml"))
    parser.add_argument("--storage", type=Path, default=Path("configs/storage.local.yaml"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    storage = yaml.safe_load(args.storage.read_text(encoding="utf-8"))
    store = PlannerStore(storage["database_url"])
    store.setup()
    service = PreService(store, gateway_factory=lambda state: KaliMCP(load_mcp_config(args.mcp)))
    if args.operation == "create":
        if not args.graph or not args.node:
            parser.error("create needs --graph and --node")
        environment = json.loads(args.environment.read_text(encoding="utf-8")) if args.environment else None
        result = service.create(json.loads(args.graph.read_text(encoding="utf-8")), args.node,
                                environment=environment, run_id=args.run_id)
    elif args.operation == "list":
        result = service.list()
    else:
        if not args.run_id:
            parser.error("resume/inspect needs --run-id")
        result = (service.resume(args.run_id, confirm_environment=args.confirm_environment)
                  if args.operation == "resume" else service.inspect(args.run_id))
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        atomic_write(args.output, (text + "\n").encode("utf-8"))
        print(args.output)
    else:
        print(text)


if __name__ == "__main__":
    main()
