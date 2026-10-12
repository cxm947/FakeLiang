"""Print a compatibility request; never obtain a key or call a model."""
import argparse
import json
from importlib.resources import files
from pathlib import Path

from .render import assemble


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--backend", choices=("legacy", "native"), default="legacy")
    args = parser.parse_args()
    raw = (args.request.read_text(encoding="utf-8") if args.request
           else files(__package__).joinpath("example.json").read_text(encoding="utf-8"))
    assembler = assemble
    if args.backend == "native":
        from .native_preview import assemble_native
        assembler = assemble_native
    print(json.dumps(assembler(json.loads(raw)), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
