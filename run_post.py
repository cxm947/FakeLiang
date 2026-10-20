"""Persist an Action handoff, observe one Post node, and export its checkpoint."""

import argparse
from datetime import datetime
from importlib import import_module
import json
from pathlib import Path
import sys
from uuid import uuid4
from zoneinfo import ZoneInfo

import yaml

from run_action import RecordedModel, save
from src.agents._model.client import create_chat_model, load_model_config
from src.orchestration.lab_settings import lock_name
from src.session.planner_store import PlannerStore, now
from src.session.post_service import PostService


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8")) if path else None


def load_factory(reference):
    module, separator, name = reference.partition(":")
    if not separator or not module or not name:
        raise ValueError("Executor must be a module:factory reference")
    factory = getattr(import_module(module), name)
    if not callable(factory):
        raise ValueError("Executor factory is not callable")
    return factory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["run", "create", "resume", "inspect", "list"])
    parser.add_argument("--graph", type=Path, default=Path("output/Hongri7_v2.action_graph.json"))
    parser.add_argument("--node")
    parser.add_argument("--action-state", type=Path)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--current-carrier-ref")
    parser.add_argument("--no-carrier-reason")
    parser.add_argument("--proposition", choices=["target_state", "channel_liveness", "目标状态", "原通道持续可用"])
    parser.add_argument("--environment", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--attempt-id")
    parser.add_argument("--thread-id")
    parser.add_argument("--lab", type=Path, default=Path("configs/action-lab.local.json"))
    parser.add_argument("--bindings", type=Path, default=Path("configs/vmware-lab.local.json"))
    parser.add_argument("--executor", default="src.orchestration.post_dispatch:vmware_gateway_factory")
    parser.add_argument("--storage", type=Path, default=Path("configs/storage.local.yaml"))
    parser.add_argument("--model", type=Path)
    parser.add_argument("--observation", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--output", type=Path, help="Additional checkpoint export path")
    args = parser.parse_args(argv)
    new = args.operation in {"run", "create"}
    if new and not args.node:
        parser.error("run/create requires --node")
    if args.operation in {"resume", "inspect"} and (not args.thread_id or not args.output_dir):
        parser.error("resume/inspect requires --thread-id and --output-dir")
    if args.observation and args.operation != "resume":
        parser.error("--observation is accepted only for resume")
    storage = yaml.safe_load(args.storage.read_text(encoding="utf-8"))
    store = PlannerStore(storage["database_url"])
    store.setup()
    config = load_model_config(args.model)
    if args.operation == "list":
        view = PostService(store, model_config=config).list()
        if args.output:
            save(args.output, view)
        else:
            print(json.dumps(view, ensure_ascii=False, indent=2))
        return 0
    thread_id = args.thread_id or str(uuid4())
    stamp = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y%m%dT%H%M%S")
    directory = args.output_dir or Path("output/post") / f"{stamp}-{thread_id[:8]}"
    if new and directory.exists():
        parser.error("A new Post run requires a new output directory")
    owner = None
    if not new:
        try:
            owner = read_json(directory / "progress.json")
        except (OSError, ValueError):
            parser.error("resume/inspect requires an existing Post progress file")
        if owner.get("thread_id") != thread_id:
            parser.error("Output directory belongs to a different Post thread")
    directory.mkdir(parents=True, exist_ok=True)
    for name in ("model_judgments", "raw_evidence", "review"):
        (directory / name).mkdir(exist_ok=True)
    # Import and invoke the executor only when an unfinished run resumes.
    # Inspect and completed resume can therefore work without its owner.
    service = PostService(store, model_config=config,
        model_factory=lambda: RecordedModel(create_chat_model(config), directory / "model_judgments"),
        gateway_factory=lambda state: load_factory(args.executor)(state))
    progress = dict(owner) if owner else {"thread_id": thread_id, "started_at": now()}
    progress.update(status="starting")
    save(directory / "progress.json", progress)
    try:
        if new:
            action = read_json(args.action_state)
            if isinstance(action, dict) and isinstance(action.get("state"), dict):
                action = action["state"]
            inventory = read_json(args.inventory)
            if inventory is None and action:
                inventory = action.get("carrier_inventory")
            reference = args.current_carrier_ref
            if reference is None and action:
                reference = action.get("current_carrier_ref")
            environment = read_json(args.environment) or {}
            environment["post_execution"] = {"lab_path": str(args.lab.resolve()),
                                               "bindings_path": str(args.bindings.resolve())}
            view = service.create(read_json(args.graph), args.node, action_state=action,
                carrier_inventory=inventory, current_carrier_ref=reference,
                no_carrier_reason=args.no_carrier_reason, proposition={"目标状态": "target_state",
                    "原通道持续可用": "channel_liveness"}.get(args.proposition, args.proposition),
                environment=environment, run_id=args.run_id, attempt_id=args.attempt_id,
                thread_id=thread_id, require_new=True, post_output_directory=str(directory.resolve()))
            # This export precedes resume and demonstrates the durable handoff.
            save(directory / "handoff-state.json", view)
            save(directory / "state.json", view)
        if args.operation in {"run", "resume"}:
            with store.lock(lock_name(read_json(args.lab))):
                view = service.resume(thread_id, observation=read_json(args.observation))
        elif args.operation == "inspect":
            view = service.inspect(thread_id)
        state_path = save(directory / "state.json", view)
        if args.output:
            save(args.output, view)
        result = view["state"].get("result")
        progress.update(status=view["status"], result=result, finished_at=now())
        save(directory / "progress.json", progress)
        print(json.dumps({"thread_id": thread_id, "status": view["status"],
            "conclusion": result.get("result") if result else None,
            "run_directory": str(directory.resolve()), "state_file": str(state_path.resolve())},
            ensure_ascii=False))
        # A completed negative/unknown verdict is still a successful Post run.
        return 0 if args.operation in {"create", "inspect"} or result is not None else 1
    except Exception as exc:
        try:
            save(directory / "state.json", service.inspect(thread_id))
        except KeyError:
            pass
        progress.update(status="interrupted", error_type=type(exc).__name__, finished_at=now())
        save(directory / "progress.json", progress)
        print(json.dumps({"error_type": type(exc).__name__,
            "run_directory": str(directory.resolve())}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
