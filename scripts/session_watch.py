"""Run exactly one registered-channel liveness sweep and save its JSON summary."""

import argparse
import json
from pathlib import Path
import sys

import psycopg
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.session.session_backend import SessionBackend
from src.session.session_registry import SessionRegistry
from src.session.session_watch import SessionWatch


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--storage", type=Path, required=True,
                        help="YAML containing database_url")
    parser.add_argument("--backend", type=Path, required=True,
                        help="SessionBackend YAML configuration")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args(argv)
    try:
        backend = SessionBackend.from_config(args.backend)
        # Validate inputs before connecting, including on an empty registry.
        SessionWatch(None, backend, args.run_id, timeout=args.timeout)
        storage = yaml.safe_load(args.storage.read_text(encoding="utf-8"))
        dsn = storage["database_url"].replace("postgresql+psycopg://", "postgresql://", 1)
        # Each registry operation commits separately; no transaction spans RPC IO.
        with psycopg.connect(dsn, autocommit=True) as connection:
            registry = SessionRegistry(connection)
            registry.setup_watch()
            with backend:
                summary = SessionWatch(registry, backend, args.run_id,
                                       timeout=args.timeout).sweep()
            report = {"status": "completed", **summary.to_dict()}
        code = 0
    except Exception as exc:
        report = {"status": "failed", "run_id": args.run_id,
                  "reason": "session_watch_failed:" + type(exc).__name__}
        code = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
