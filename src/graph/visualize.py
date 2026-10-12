"""JSON -> DOT -> vector PDF. Adapted from the user's plotss/topology scripts.

No topology is recomputed here. Display exactly the JSON nodes and edges.
Original script references and adaptation decisions: docs/v1/visualization.md.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

from .files import atomic_write, check_targets
from .paths import resolve_path
from .rehydrate import ensure_view, load_file


def quote_dot(value: str) -> str:
    # Escape backslashes FIRST. Never interpolate raw labels into DOT syntax.
    text = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", "\\n")
    return '"' + text + '"'


def _dependency_label(node):
    rows = node["dependencies"]
    if not rows:
        return "deps [INPUT]: LEAF facts"
    terms = []
    for row in rows:
        ref = row["ref"]
        if row["type"] == "OR":
            producers = " OR ".join(row.get("produced_by") or []) or "FALSE"
            terms.append(ref + " <- (" + producers + ")")
        elif row["type"] == "LEAF":
            terms.append(ref + "*")
        else:
            terms.append(ref)
    kind = "AND" if len(rows) > 1 else "SINGLE"
    return "deps [" + kind + "]: " + " AND ".join(terms)


def validate_view(document: dict):
    ids = {node["id"] for node in document["nodes"]}
    if len(ids) != len(document["nodes"]):
        raise ValueError("duplicate projected node IDs")
    if any(node["type"] not in {"AND", "OR"} for node in document["nodes"]):
        raise ValueError("renderer expects AND and terminal OR nodes only")


def build_dot(document: dict, *, title="Action graph", rankdir="TB", labels="detail") -> str:
    document = ensure_view(document)
    validate_view(document)
    if rankdir not in {"TB", "BT", "LR", "RL"} or labels not in {"detail", "compact"}:
        raise ValueError("unsupported layout or label mode")
    short_ids = {node["id"]: node["semantics"]["original_id"] for node in document["nodes"]}
    edges = sorted({(row["ref"], node["id"]) for node in document["nodes"] for row in node["dependencies"]
                    if row["ref"] in short_ids})
    legend = (
        f"{title} | {len(document['nodes'])} nodes | {len(edges)} edges\n"
        "Ellipse: AND rule instance    Diamond: terminal OR    Amber: unmatched case\n"
        "deps: every direct parent (E1); '*' = LEAF fixed true; OR rows carry produced_by.\n"
        "Runtime prerequisites are derived on load, not stored in this document.\n"
        f"Logical projection, not execution evidence | graph {document['source_graph']['graph_hash'][:12]}"
    )
    lines = ["digraph ActionGraph {", f"  rankdir={rankdir};",
             '  graph [bgcolor="white", pad="0.35", nodesep="0.4", ranksep="0.8", splines=true, concentrate=false, labelloc="t", fontname="Arial", fontsize=13];',
             '  node [fontname="Arial", fontsize=11, style=filled, color="#34465D", penwidth=1.1, margin="0.16,0.10"];',
             '  edge [color="#65758B", arrowsize=0.65, penwidth=1.1];',
             f"  label={quote_dot(legend)};"]
    for node in document["nodes"]:
        sem = node["semantics"]
        kind = node["type"]
        label_lines = [f"{kind} {sem['original_id']} | {'rule' if kind == 'AND' else 'goal'}" + (f" | {node['attack_id']}" if node["attack_id"] else "")]
        if labels == "detail":
            if kind == "AND":
                text = sem["case_id"] or "UNMATCHED: " + str(node["rule_desc"])
                label_lines += textwrap.wrap(text.replace("_", " "), width=36)
            else:
                goal = sem["details"].get("goal", {})
                # Never place account passwords or raw getAccount args in PDFs.
                label_lines.append("GOAL: " + goal.get("predicate", "unparsed"))
        if node.get("target_host"):
            host = node["target_host"]
            if node.get("source_host") and node["source_host"] != host:
                host = node["source_host"] + " -> " + host
            label_lines += textwrap.wrap(host, width=40)
        elif node.get("source_host"):
            label_lines += textwrap.wrap("source: " + node["source_host"], width=40)
        if labels == "detail":
            if node.get("service") or node.get("port"):
                parts = [str(node[key]) for key in ("service", "protocol", "port") if node.get(key) is not None]
                label_lines += textwrap.wrap(" / ".join(parts), width=40)
        label_lines += textwrap.wrap(_dependency_label(node), width=48)
        fill = "#E8F3EC" if kind == "OR" else "#EAF1FB" if sem["case_status"] == "matched" else "#FFF0D5"
        shape = "diamond" if kind == "OR" else "ellipse"
        label = quote_dot("\n".join(label_lines))
        lines.append(f"  {quote_dot(node['id'])} [shape={shape}, fillcolor={quote_dot(fill)}, label={label}];")
    for source, target in edges:
        lines.append(f"  {quote_dot(source)} -> {quote_dot(target)};")
    return "\n".join([*lines, "}", ""])


def find_dot(executable=None) -> str:
    requested = executable or os.environ.get("AGV_GRAPHVIZ_DOT") or "dot"
    if "/" in str(requested) or "\\" in str(requested):
        requested = resolve_path(requested)
    resolved = shutil.which(str(requested))
    if not resolved:
        raise FileNotFoundError("Graphviz dot not found. Set --dot-executable or AGV_GRAPHVIZ_DOT; alternatively use --json-only.")
    return resolved


def render_pdf(dot_source: str, *, executable=None, timeout=30) -> bytes:
    program = find_dot(executable)
    result = subprocess.run([program, "-Tpdf"], input=dot_source.encode("utf-8"), capture_output=True,
                            timeout=timeout, check=True,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if not result.stdout.startswith(b"%PDF-"):
        raise ValueError("Graphviz did not return a PDF")
    return result.stdout


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Render an existing V1 action_graph.json to a vector PDF; no recompression.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dot-output", type=Path)
    parser.add_argument("--dot-executable")
    parser.add_argument("--rankdir", choices=("TB", "BT", "LR", "RL"), default="TB")
    parser.add_argument("--labels", choices=("detail", "compact"), default="detail")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    try:
        args.input = resolve_path(args.input)
        args.output = resolve_path(args.output)
        if args.dot_output is not None:
            args.dot_output = resolve_path(args.dot_output)
        targets = [args.output] + ([args.dot_output] if args.dot_output else [])
        check_targets(targets, inputs=[args.input], force=args.force)
        document = load_file(args.input)
        dot = build_dot(document, title=args.input.stem, rankdir=args.rankdir, labels=args.labels)
        pdf = render_pdf(dot, executable=args.dot_executable)
        atomic_write(args.output, pdf, force=args.force)
        if args.dot_output:
            atomic_write(args.dot_output, dot.encode("utf-8"), force=args.force)
        print(f"PDF: {args.output.resolve()}")
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Do not echo Graphviz stderr or input labels (may contain sensitive facts).
        print(f"Rendering failed ({type(error).__name__}). Check input schema, output paths and Graphviz.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
