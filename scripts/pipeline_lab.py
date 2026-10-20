"""Explicit serial lab prepare/stop; importing this script performs no VM IO."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.orchestration.live_pipeline import read_json
from src.orchestration.pipeline_lab import prepare_lab, cleanup_lab
from src.agents.pre_verifier.vmware_guest import VMwareGuest
from src.session.planner_store import PlannerStore
from run_action import save
import yaml


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["prepare", "stop"])
    parser.add_argument("--lab", type=Path, default=Path("configs/action-lab.local.json"))
    parser.add_argument("--storage", type=Path, default=Path("configs/storage.local.yaml"))
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        lab = read_json(args.lab)
        guest = VMwareGuest(lab["guest_config"])
        store = PlannerStore(yaml.safe_load(args.storage.read_text(encoding="utf-8"))["database_url"])
        with store.lock("action:vmware-lab"):
            result = (prepare_lab if args.operation == "prepare" else cleanup_lab)(
                guest, lab["snapshots"], args.output_dir)
        return 0 if result["status"] == "completed" else 1
    except Exception as exc:
        failure = {"stage": args.operation, "category": "参数没给到"
            if isinstance(exc, (ValueError, KeyError, TypeError, FileNotFoundError)) else "会话没接上",
            "detail": type(exc).__name__}
        save(args.output_dir / "failure.json", failure)
        print(json.dumps({"failure": failure}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
