"""Run the same durable pipeline with offline doubles or live collaborators."""

import argparse
import json
from pathlib import Path
from uuid import uuid4

from run_action import save
from src.orchestration.pipeline_evidence import PipelineEvidence
from src.session.pipeline_service import PipelineFailure


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--offline", action="store_true")
    modes.add_argument("--live", action="store_true")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--config", type=Path, help="Live deployment configuration (paths relative to cwd)")
    parser.add_argument("--check", action="store_true", help="Validate local live inputs; no DB, model or VM calls")
    parser.add_argument("--reset-lab", action="store_true", help="Serial clean rollback of all six VMs (new run only)")
    parser.add_argument("--cleanup", choices=["keep", "stop"], default="keep")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--confirm-environment", action="store_true")
    args = parser.parse_args(argv)
    if args.live:
        if not args.config:
            parser.error("参数没给到: --live requires --config")
        if args.resume and args.reset_lab:
            parser.error("参数没给到: a resumed run cannot reset the lab")
        return run_live(args)
    if args.config or args.check or args.reset_lab or args.cleanup != "keep" or args.resume:
        parser.error("参数没给到: deployment/lab options require --live")
    # The offline doubles are imported only on the offline path. Importing them at module
    # scope made every --live process load simulation code it must never assemble.
    from src.orchestration.offline_pipeline import OfflineRuntime, demo_request
    runtime = OfflineRuntime(args.output_dir, channel_kinds={"b": "remote_command", "c": "authorized_connection"})
    runtime.service.evidence = PipelineEvidence(args.output_dir, runtime.service)
    marker = args.output_dir / "run-id.txt"
    run_id = marker.read_text(encoding="utf-8").strip() if marker.exists() else str(uuid4())
    marker.write_text(run_id, encoding="utf-8")
    runtime.seed(run_id)
    runtime.service.create(demo_request(), run_id=run_id)
    result = runtime.service.resume(run_id, confirm_environment=args.confirm_environment)
    runtime.service.evidence(result["state"])
    report = args.output_dir / "pipeline.json"
    report.write_text(json.dumps({**result, "offline": True, "events": runtime.events},
                                ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"status": result["status"], "rounds": len(result["state"]["rounds"]),
        "failure": result["state"]["failure"], "report": str(report)}, ensure_ascii=False))
    return 0 if result["status"] == "completed" else 1


def run_live(args):
    from src.orchestration.live_pipeline import LiveRuntime
    from src.orchestration.lab_settings import lock_name
    from src.orchestration.pipeline_lab import (cleanup_lab, direct_services,
                                                prepare_lab, wait_services)
    directory = args.output_dir
    report = directory / "pipeline.json"
    result, runtime, run_id = None, None, None
    stage = "configuration"
    # A new run never overwrites earlier evidence, including partial rollback.
    if not args.check and not args.resume and directory.exists():
        print(json.dumps({"failure": {"stage": stage, "category": "参数没给到",
            "detail": "A new live run requires a new output directory"}}, ensure_ascii=False))
        return 1
    try:
        runtime = LiveRuntime(args.config, directory)
        if args.check:
            print(json.dumps({"status": "validated", "remote_operations": 0}, ensure_ascii=False))
            return 0
        marker = directory / "run-id.txt"
        if args.resume:
            run_id = marker.read_text(encoding="utf-8").strip()
        else:
            directory.mkdir(parents=True)
            run_id = str(uuid4())
            marker.write_text(run_id, encoding="utf-8")
        runtime_run = {"id": run_id, "offline": False, "status": "starting"}
        save(report, runtime_run)
        stage = "storage"
        # Share the existing lab lock with the Action and Post CLI entry points.
        with runtime.store.lock(lock_name(runtime.lab)):
            cleanup_needed = False
            try:
                if args.reset_lab:
                    stage = "rollback"
                    cleanup_needed = True
                    prepare_lab(runtime.guest, runtime.lab["snapshots"], directory / "lab",
                                console=runtime.config.console,
                                network=runtime.lab.get("network") or ())
                    # A powered-on guest is not a ready service. Wait for the endpoints the
                    # controller can reach directly before the graph starts using them.
                    controller = ((runtime.config.console or {}).get("address")
                                  or runtime.config.migration.callback_host)
                    wait_services(
                        direct_services(runtime.request, controller),
                        directory / "lab", timeout=1200.0)
                if not args.resume:
                    # Deployment files live with the deployment; a run pushes the
                    # declared ones to the execution point and records the receipt.
                    stage = "materials"
                    runtime.push_materials(directory / "lab")
                stage = "connect"
                cleanup_needed = True
                with runtime.connect(run_id):
                    stage = "initial_sessions"
                    if not args.resume:
                        runtime.seed(run_id)
                    stage = "pipeline"
                    runtime.service.create(runtime.request, run_id=run_id)
                    try:
                        result = runtime.service.resume(run_id, confirm_environment=args.confirm_environment)
                    finally:
                        view = runtime.service.inspect(run_id)
                        result = view
                        runtime.evidence(view["state"])
                        runtime.release_deliveries()
                        save(report, {**view, "offline": False})
            finally:
                if args.cleanup == "stop" and cleanup_needed:
                    cleanup = cleanup_lab(runtime.guest, runtime.lab["snapshots"], directory / "lab")
                    if cleanup["status"] != "completed" and result and result["status"] == "completed":
                        stage = "cleanup"
                        raise PipelineFailure("会话没接上", "Lab cleanup was not confirmed")
        print(json.dumps({"status": result["status"], "rounds": len(result["state"]["rounds"]),
            "failure": result["state"]["failure"], "report": str(report)}, ensure_ascii=False))
        return 0 if result["status"] == "completed" else 1
    except Exception as exc:
        failure = {"stage": stage, "category": getattr(exc, "category",
            "参数没给到" if stage == "configuration" or isinstance(exc, (ValueError, KeyError, TypeError, FileNotFoundError))
            else "会话没接上"),
            "detail": exc.detail if isinstance(exc, PipelineFailure) else type(exc).__name__}
        # Never print config validation inputs or credential-bearing exception text.
        if not args.check and (directory.exists() or not args.resume):
            save(report, {"id": run_id, "offline": False, "status": "failed", "failure": failure,
                          "pipeline": result})
        print(json.dumps({"failure": failure, "report": str(report)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
