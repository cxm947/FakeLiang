"""Parse a predicate graph and write its JSON document and Graphviz PDF."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .files import atomic_write, check_targets, publish_bundle
from .host_map import read_host_map
from .parser import read_txt
from .visualize import render_document_pdf

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = REPO_ROOT / "data/inputs/Hongri7_v2.txt"
DEFAULT_HOST_MAP = REPO_ROOT / "data/inputs/host_ip_map.csv"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "output"


def compile_document(input_path, *, host_map=None, original=False) -> dict:
    document = read_txt(input_path, original=original)
    if host_map:
        document["hosts"], records = read_host_map(
            host_map, hosts=(entry["host"] for entry in document["hosts"]),
        )
        document["inputs"]["host_map"] = {"source": str(host_map), "records": records}
    document["summary"]["hosts"] = len(document["hosts"])
    document["summary"]["addresses"] = len({ip for host in document["hosts"] for ip in host["ips"]})
    return document


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, default=DEFAULT_INPUT,
                        help="graph TXT (default: bundled Hongri7_v2 graph)")
    parser.add_argument("--host-map", type=Path, default=DEFAULT_HOST_MAP,
                        help="host,ip CSV (default: bundled Hongri7 host map)")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help="artifact directory (default: repository output)")
    args = parser.parse_args(argv)
    try:
        stem = args.input.stem + ".action_graph"
        paths = {"json": args.output_dir / (stem + ".json"),
                 "pdf": args.output_dir / (stem + ".pdf"),
                 "original_json": args.output_dir / (args.input.stem + ".original_graph.json"),
                 "original_pdf": args.output_dir / (args.input.stem + ".original_graph.pdf")}
        check_targets(paths.values(), inputs=[args.input, args.host_map], force=True)
        original = compile_document(args.input, host_map=args.host_map, original=True)
        document = compile_document(args.input, host_map=args.host_map)
        # Rendering must succeed before either existing artifact is replaced.
        pdf, renderer = render_document_pdf(document, title=args.input.stem)
        original_pdf, _ = render_document_pdf(original, title=args.input.stem + " original")
        contents = {
            "json": (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
            "pdf": pdf,
            "original_json": (json.dumps(original, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
            "original_pdf": original_pdf,
        }
        publish_bundle(paths, contents, writer=atomic_write)
        print(f"PDF renderer: {renderer}")
        for kind, path in paths.items():
            print(f"{kind.upper()}: {path.resolve()}")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Graph compilation failed ({type(error).__name__}): {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
