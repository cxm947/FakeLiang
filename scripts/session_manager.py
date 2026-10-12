#!/usr/bin/env python3
"""List explicitly bound console sessions and carry their handles."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="session_manager.py",
        description=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    show = sub.add_parser("list")
    show.add_argument("--ledger", required=True)

    move = sub.add_parser("carry")
    move.add_argument("--from", dest="source", required=True)
    move.add_argument("--to", dest="target", required=True)
    move.add_argument("--remote", default="")
    move.add_argument("--password", default=None)
    move.add_argument("--key", default=None)

    args = parser.parse_args(argv)

    src = str(Path(__file__).resolve().parents[1] / "src")
    if src not in sys.path:
        sys.path.insert(0, src)

    if args.command == "list":
        from runtime import session_registry

        print(
            json.dumps(
                session_registry.snapshot(args.ledger),
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    from runtime import sessions

    carried, unavailable, superseded = sessions.carry_handles(
        args.source,
        args.target,
        executor=None,
    )
    print(
        json.dumps(
            {
                "carried": carried,
                "unavailable": unavailable,
                "superseded": superseded,
            }
        )
    )
    return 0 if carried else 2


if __name__ == "__main__":
    raise SystemExit(main())
