"""Validate individual live nodes with manually prepared prerequisites; never plan or reset."""

import argparse
import json
from pathlib import Path
from uuid import UUID, uuid4

from src.orchestration.live_pipeline import LiveConfig, LiveRuntime, read_json
from src.orchestration.node_live import (NodeLiveDriver, check_nodes, exception_record, executable_nodes,
                                         registrations, write)


def json_input(value):
    if value.lstrip().startswith(("[", "{")):
        return json.loads(value)
    return read_json(value)


def selected_nodes(request, node_id):
    nodes = executable_nodes(request)
    if node_id is not None:
        if node_id not in nodes:
            raise ValueError("--node must identify an executable node, not a final goal")
        return [node_id]
    return nodes


def report(summary, directory):
    print(json.dumps({"run_id": summary["run_id"], "status": summary["status"],
                      "summary": str(directory / "summary.json")}, ensure_ascii=False))
    return 0 if summary["status"] in {"succeeded", "validated"} else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="Live config; paths relative to cwd")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--node", help="One executable graph node id")
    selection.add_argument("--all", action="store_true", help="Every executable node in document order")
    parser.add_argument("--sessions", help="JSON file or inline list of SessionRegistration without run_id; overrides config seeds")
    parser.add_argument("--bindings", help="JSON file or inline object: node id -> frozen ExecutionBinding; missing keys fail closed")
    parser.add_argument("--output", type=Path, required=True, help="New evidence directory")
    parser.add_argument("--run-id", help="Existing run UUID for manually registered prerequisites")
    parser.add_argument("--check", action="store_true", help="Local input/context audit only; no runtime connection or live execution")
    parser.add_argument("--cleanup", choices=("keep", "stop"), default="keep",
                        help="keep the lab by default; stop explicitly powers off configured VMs, never reverts")
    args = parser.parse_args(argv)
    if args.check and args.cleanup != "keep":
        parser.error("--check cannot stop the lab")
    directory = args.output
    try:
        run_id = str(UUID(args.run_id)) if args.run_id else str(uuid4())
    except ValueError:
        parser.error("--run-id must be a UUID")
    if directory.exists():
        parser.error("--output must be a new directory; existing evidence is never overwritten")
    directory.mkdir(parents=True)
    (directory / "run-id.txt").write_text(run_id + "\n", encoding="utf-8")
    summary = {"run_id": run_id, "status": "failed", "nodes": []}
    stage = "configuration"
    try:
        manual = registrations(json_input(args.sessions), run_id) if args.sessions else []
        bindings = json_input(args.bindings) if args.bindings else None
        if bindings is not None and not isinstance(bindings, dict):
            raise ValueError("--bindings must contain an object keyed by node id")
        if args.check:
            config = LiveConfig.model_validate(read_json(args.config))
            request = read_json(config.request)
            sessions = manual if args.sessions else registrations(read_json(config.initial_sessions), run_id)
            summary = check_nodes(request, selected_nodes(request, args.node), directory,
                                  run_id, sessions, bindings=bindings)
            return report(summary, directory)
        runtime = LiveRuntime(args.config, directory, initial_sessions=[] if args.sessions else None)
        nodes = selected_nodes(runtime.request, args.node)
        stage = "connect"
        with runtime.connect(run_id):
            try:
                stage = "seed"
                runtime.seed(run_id)
                stage = "sessions"
                write(directory / "sessions" / "manual-input.json",
                      [row.model_dump(mode="json", exclude={"run_id"}) for row in manual])
                for row in manual:
                    runtime.sessions.register(row)
                runtime.sessions.commit()
                write(directory / "sessions" / "registered.json", [row.model_dump(mode="json")
                      for row in runtime.sessions.list_for_run(run_id)])
                # The deployment's declared files travel with the run: a card that calls a
                # supplied PoC must find it at the declared execution-point path, exactly as
                # the full pipeline arranges (live 2026-10-18, node 28: single-node runs had
                # no materials and the card correctly reported the missing path). The entry
                # comes from the manual registrations when the run seeds none of its own.
                if manual and not runtime.initial_sessions:
                    runtime.initial_sessions = [row.model_dump(mode="json")
                                                for row in manual
                                                if row.binding_kind == "controller_entry"]
                    if not runtime.initial_sessions:
                        # A node can be driven from a target-side session alone; the run still
                        # reaches the execution point through the deployment's declared entry.
                        seed = read_json(runtime.config.initial_sessions)
                        runtime.initial_sessions = [row for row in seed
                                                    if row.get("binding_kind") == "controller_entry"]
                stage = "materials"
                runtime.push_materials(directory / "materials")
                stage = "nodes"
                summary = NodeLiveDriver(runtime, run_id, directory, bindings=bindings).run(nodes)
            finally:
                if args.cleanup == "stop":
                    from src.orchestration.pipeline_lab import cleanup_lab
                    stage = "cleanup"
                    try:
                        runtime.release_deliveries()
                    except Exception as exc:
                        summary["cleanup_exception"] = exception_record(exc)
                        summary["status"] = "failed"
                    cleanup = cleanup_lab(runtime.guest, runtime.lab["snapshots"], directory / "lab")
                    summary["cleanup"] = cleanup
                    if cleanup["status"] != "completed":
                        summary["status"] = "failed"
        write(directory / "summary.json", summary)
    except Exception as exc:
        summary.update(status="failed", failure_stage=stage, exception=exception_record(exc))
        write(directory / "summary.json", summary)
    return report(summary, directory)


if __name__ == "__main__":
    raise SystemExit(main())
