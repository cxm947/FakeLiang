#!/usr/bin/env python3
"""Install local hooks. pre-commit reads git config ci.python.

Use .venv312/Scripts/python.exe for acceptance; ci.py binds all gates to it.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=str(ROOT / ".venv312" / "Scripts" / "python.exe"))
    args = parser.parse_args(argv)
    interpreter = Path(args.python).resolve()
    if not interpreter.is_file():
        parser.error("interpreter is missing: " + str(interpreter))
    for key, value in (("ci.python", str(interpreter)), ("core.hooksPath", "scripts/hooks")):
        subprocess.run(["git", "-C", str(ROOT), "config", "--local", key, value], check=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    print("pre-commit -> ci.python=" + str(interpreter))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
