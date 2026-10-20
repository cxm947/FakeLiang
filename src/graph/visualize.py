"""Render the document's nodes and prerequisite-to-dependent edges with Graphviz."""

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path


def quote_dot(value: str) -> str:
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return '"' + text.replace("\r", "").replace("\n", "\\n") + '"'


def build_dot(document: dict, *, title="Action graph") -> str:
    legend = (f"{title} | {len(document['nodes'])} nodes | {len(document['edges'])} edges\n"
              "Ellipse: AND | Diamond: OR | Box: LEAF\n"
              "Arrows: prerequisite -> dependent")
    lines = ["digraph ActionGraph {", "  rankdir=TB;",
             '  graph [bgcolor="white", pad="0.35", nodesep="0.4", ranksep="0.8", labelloc="t", fontname="Arial"];',
             '  node [fontname="Arial", fontsize=10, style=filled, color="#34465D"];',
             '  edge [color="#65758B", arrowsize=0.65];',
             f"  label={quote_dot(legend)};"]
    styles = {"AND": ("ellipse", "#EAF1FB"), "OR": ("diamond", "#E8F3EC"),
              "LEAF": ("box", "#F5F0E8")}
    for node in document["nodes"]:
        shape, color = styles[node["type"]]
        label = f"{node['type']} {node['id']}\n" + "\n".join(
            textwrap.wrap(node["description"], width=55, break_long_words=False))
        lines.append(f"  {quote_dot(node['id'])} [shape={shape}, "
                     f"fillcolor={quote_dot(color)}, label={quote_dot(label)}];")
    for edge in document["edges"]:
        lines.append(f"  {quote_dot(edge['src'])} -> {quote_dot(edge['dst'])};")
    return "\n".join([*lines, "}", ""])


def find_dot(executable=None) -> str:
    tried = []
    requested = executable or os.environ.get("AGV_GRAPHVIZ_DOT")
    if requested:
        requested = str(requested)
        source = "executable" if executable else "AGV_GRAPHVIZ_DOT"
        tried.append(f"{source}={requested}")
        if not executable and Path(requested).is_file():
            return requested
        resolved = shutil.which(requested)
        if resolved:
            return resolved

    if not executable:
        tried.append(f"dot on PATH={os.environ.get('PATH', os.defpath)}")
        resolved = shutil.which("dot")
        if resolved:
            return resolved

        candidates = []
        prefix = os.environ.get("CONDA_PREFIX")
        if prefix:
            prefix = Path(prefix)
            for directory in (prefix, prefix.parent.parent):
                candidates.extend((directory / "Graphviz/bin/dot.exe",
                                   directory / "Library/bin/dot.exe"))
        else:
            tried.append("CONDA_PREFIX is not set")
        # Search the interpreter directory and prefix, plus three parents.
        for location in (Path(sys.executable).parent, Path(sys.prefix)):
            for directory in (location, *location.parents[:3]):
                candidates.extend((directory / "Graphviz/bin/dot.exe",
                                   directory / "Library/bin/dot.exe"))
        for variable, default in (("ProgramFiles", r"C:\Program Files"),
                                  ("ProgramFiles(x86)", r"C:\Program Files (x86)")):
            candidates.append(Path(os.environ.get(variable, default)) / "Graphviz/bin/dot.exe")
        for candidate in dict.fromkeys(candidates):
            tried.append(str(candidate))
            if candidate.is_file():
                return str(candidate)

    raise FileNotFoundError("Graphviz dot not found; add its bin directory to PATH "
                            "or set AGV_GRAPHVIZ_DOT.\nTried:\n  " + "\n  ".join(tried))


def render_pdf(dot_source: str, *, executable=None, timeout=30) -> bytes:
    result = subprocess.run(
        [find_dot(executable), "-Tpdf"], input=dot_source.encode("utf-8"),
        capture_output=True, timeout=timeout, check=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if not result.stdout.startswith(b"%PDF-"):
        raise ValueError("Graphviz did not return a PDF")
    return result.stdout


def render_document_pdf(document: dict, *, title="Action graph", executable=None) -> tuple[bytes, str]:
    return render_pdf(build_dot(document, title=title), executable=executable), "Graphviz"
