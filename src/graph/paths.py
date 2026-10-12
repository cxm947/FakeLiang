"""One path convention for all V1 command-line entry points.

In a source checkout, relative data/output paths are relative to the project
root, not the terminal's current directory. Absolute paths remain absolute.
For a wheel installed outside a checkout, the caller's cwd is the workspace.
No chdir or global environment mutation is needed.
"""

from pathlib import Path

_SOURCE_ROOT = Path(__file__).resolve().parents[2]


def workspace_root() -> Path:
    if (_SOURCE_ROOT / "pyproject.toml").is_file() and (_SOURCE_ROOT / "src/graph/paths.py").is_file():
        return _SOURCE_ROOT
    return Path.cwd().resolve()


def resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else workspace_root() / path).resolve()
