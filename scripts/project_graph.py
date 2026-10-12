"""Run from a source checkout without pip installing the project."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from graph.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
