"""The V1 entry point: one TXT (+ host map) -> loss-preserving JSON + DOT + PDF."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from .files import atomic_write, check_targets
from .host_map import HostIndex, build_hosts, load_profile, read_rows
from .parser import read_txt
from .paths import resolve_path
from .projector import project, source_snapshot
from .visualize import build_dot, render_pdf

REPO_ROOT = Path(__file__).resolve().parents[2]


def _snapshot(path, fmt: str) -> dict:
    resolved = Path(path).resolve()
    try:
        name = resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        name = resolved.as_posix()
    return {"file": name, "format": fmt, "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest()}


def compile_document(input_path, *, host_map="", assets="", edge_order="target-source",
                     encoding="utf-8-sig") -> dict:
    """TXT（+ 主机映射表 + 可选部署画像）-> 一份 1.2.0 文档对象。

    命令行与验证流程共用这一条链：验证流程要能直接吃 ``--graph <攻击图.txt>``，就不能让"怎么从 TXT 编译"
    只活在命令行里（2026-10-06：这条链曾被整批删掉而没人发现，因为验证流程当时只用编译好的 JSON）。
    """
    graph = read_txt(resolve_path(input_path), edge_order=edge_order, encoding=encoding)
    rows, profile = [], None
    inputs = {"graph_source": _snapshot(input_path, "mulval_txt")}
    if host_map:
        resolved = resolve_path(host_map)
        rows = read_rows(resolved)
        inputs["host_map"] = {"source": _snapshot(resolved, "csv"), "records": len(rows)}
    if assets:
        resolved = resolve_path(assets)
        profile = load_profile(resolved)
        inputs["asset_profile"] = {**_snapshot(resolved, "json"),
                                   "usage": "optional deployment profile merged into hosts[] "
                                            "(multi-NIC / container IPs)"}
    hosts = build_hosts(rows, profile)
    return project(graph, hosts=hosts, host_index=HostIndex(hosts), inputs=inputs)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--host-map", type=Path, help="host,ip rows: the only place a host name gets an address")
    parser.add_argument("--assets", type=Path, help="optional deployment profile (multi-NIC / container addresses)")
    parser.add_argument("--edge-order", choices=("target-source", "source-target"), default="target-source")
    parser.add_argument("--encoding", default="utf-8-sig")
    parser.add_argument("--no-simplify", action="store_true",
                        help="accepted for compatibility; 1.2.0 always carries the direct parents")
    parser.add_argument("--strict", action="store_true", help="fail before writing if a case is unknown/ambiguous")
    parser.add_argument("--json-only", action="store_true", help="skip Graphviz and PDF; still save DOT")
    parser.add_argument("--dot-executable")
    parser.add_argument("--rankdir", choices=("TB", "BT", "LR", "RL"), default="TB")
    parser.add_argument("--labels", choices=("detail", "compact"), default="detail")
    parser.add_argument("--force", action="store_true", help="explicitly replace existing output files")
    args = parser.parse_args(argv)
    try:
        args.input = resolve_path(args.input)
        args.output_dir = resolve_path(args.output_dir)
        stem = args.input.stem + ".action_graph"
        paths = {"json": args.output_dir / "json" / (stem + ".json"), "dot": args.output_dir / "dot" / (stem + ".dot")}
        if not args.json_only:
            paths["pdf"] = args.output_dir / "pdf" / (stem + ".pdf")
        check_targets(paths.values(), inputs=[args.input], force=args.force)
        document = compile_document(args.input, host_map=args.host_map, assets=args.assets,
                                    edge_order=args.edge_order, encoding=args.encoding)
        if args.strict and any(item["code"].startswith("case_") for item in document["diagnostics"]):
            print("Unknown rule case(s): " + ", ".join(item["node_ref"] for item in document["diagnostics"]
                                                       if item["code"].startswith("case_")), file=sys.stderr)
            return 3
        dot = build_dot(document, title=args.input.stem, rankdir=args.rankdir, labels=args.labels)
        # Render before publishing artifacts; a missing Graphviz leaves no new files.
        contents = {"json": (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8"), "dot": dot.encode("utf-8")}
        if not args.json_only:
            contents["pdf"] = render_pdf(dot, executable=args.dot_executable)
        for kind, path in paths.items():
            atomic_write(path, contents[kind], force=args.force)
        print(json.dumps({"artifacts": {k: str(v.resolve()) for k, v in paths.items()}, "summary": document["summary"]}, ensure_ascii=False, indent=2))
        print("JSON preserves original facts (including any credentials). Keep it local and redact before sharing.")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"V1 failed ({type(error).__name__}): {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())