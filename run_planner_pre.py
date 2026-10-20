"""Single-round Planner/Pre inspection; run_pipeline.py runs the complete chain."""

import argparse
import json
from pathlib import Path

import yaml

from src.agents.pre_verifier.mcp_client import KaliMCP, load_mcp_config
from src.graph.cli import compile_document, DEFAULT_INPUT, DEFAULT_HOST_MAP
from src.graph.files import atomic_write
from src.session.planner_service import PlannerService
from src.session.pre_service import PreService
from src.session.planner_pre_service import PlannerPreService
from src.session.planner_store import PlannerStore


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["create", "run", "resume", "inspect"])
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--host-map", type=Path, default=DEFAULT_HOST_MAP)
    parser.add_argument("--environment", type=Path)
    parser.add_argument("--vmware-config", type=Path, help="local experiment carrier configuration")
    parser.add_argument("--run-id")
    parser.add_argument("--confirm-environment", action="store_true")
    parser.add_argument("--mcp", type=Path, default=Path("configs/pre-mcp.local.yaml"))
    parser.add_argument("--storage", type=Path, default=Path("configs/storage.local.yaml"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error("output already exists; use a new report path")
    if args.operation in {"inspect", "resume"} and not args.run_id:
        parser.error("inspect/resume needs --run-id")
    store = PlannerStore(yaml.safe_load(args.storage.read_text(encoding="utf-8"))["database_url"])
    store.setup()
    planner = PlannerService(store)
    gateway_factory = lambda state: KaliMCP(load_mcp_config(args.mcp))
    vm_config = None
    if args.vmware_config:
        from src.agents.pre_verifier.vmware_guest import VMwareGuest, GuestCheckGateway
        vm_config = json.loads(args.vmware_config.read_text(encoding="utf-8"))
        gateway_factory = lambda state: GuestCheckGateway(KaliMCP(load_mcp_config(args.mcp)),
            VMwareGuest(vm_config["guest_config"]), vm_config["bindings"], vm_config.get("source_aliases"))
    pre = PreService(store, gateway_factory=gateway_factory, model_config=planner.model_config)
    service = PlannerPreService(planner, pre)
    error = None
    if args.operation in {"create", "run"}:
        document = compile_document(args.input, host_map=args.host_map)
        env = json.loads(args.environment.read_text(encoding="utf-8")) if args.environment else None
        if vm_config:
            env = {**(env or {}), **{name: {"platform": b["platform"], "access": "VMware Tools local experiment carrier",
                "identity": b.get("identity"), "container_map": b.get("container_map", {})}
                for name, b in vm_config["bindings"].items()}}
        result = service.create(document, environment=env, run_id=args.run_id)
        run_id = result["id"]
        print(json.dumps({"id": run_id, "status": "created"}), flush=True)
    else:
        run_id = args.run_id
    try:
        result = service.resume(run_id, confirm_environment=args.confirm_environment) if args.operation in {"run", "resume"} else service.inspect(run_id)
    except Exception as exc:
        error = type(exc).__name__
        result = service.inspect(run_id)
    # Export the two actual child records.
    details = {"handoff": result, "error": error}
    for key, child in (("planner", planner), ("pre", pre)):
        try:
            details[key] = child.inspect(result["state"]["run"][key + "_id"])
        except KeyError:
            details[key] = None
    atomic_write(args.output, (json.dumps(details, ensure_ascii=False, indent=2) + "\n").encode())
    print(json.dumps({"status": result["status"], "result": result["state"].get("result"),
                      "error": error, "report": str(args.output)}, ensure_ascii=False))
    return 1 if error or result["status"] == "planner_exhausted" else 0


if __name__ == "__main__":
    raise SystemExit(main())
