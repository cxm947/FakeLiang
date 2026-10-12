#!/usr/bin/env python3
"""Check built package bytes; no model call or target access."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    "src/agents/_model/chat.py",
    "src/agents/_model/backend.py",
    "src/agents/executor/native_tools.py",
    "src/agents/prompting/native_preview.py",
    "src/agents/executor/templates/native.txt",
    "src/agents/executor/templates/native.yaml",
    "src/agents/executor/templates/system.yaml",
    "src/agents/prompting/example.json",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("wheel", "sdist", "rebuilt", "isolated"), required=True)
    parser.add_argument("--file", type=Path)
    args = parser.parse_args()
    if args.kind == "isolated":
        import agents._model.chat as chat
        import agents.executor.native_tools as native
        import agents.prompting.native_preview as preview
        from importlib.resources import files
        for module in (chat, native, preview):
            location = Path(module.__file__).resolve()
            if location.is_relative_to(ROOT / "src"):
                raise SystemExit("source checkout leaked into isolated import")
        request = json.loads(files("agents.prompting").joinpath("example.json").read_text(
            encoding="utf-8"))
        result = preview.assemble_native(request)
        assert result["protocol"] == "native-tools-v1" and result["tools"]
        assert {row["function"]["name"] for row in result["tools"]} == {
            "cmd", "finish", "evidence", "abandon"}
    elif args.kind == "sdist":
        with tarfile.open(args.file, "r:gz") as archive:
            members = {member.name.split("/", 1)[-1]: member for member in archive.getmembers()
                       if member.isfile() and "/" in member.name}
            for name in FILES:
                assert name in members, name
                assert archive.extractfile(members[name]).read() == (ROOT / name).read_bytes(), name
    else:
        with zipfile.ZipFile(args.file) as archive:
            for name in FILES:
                assert archive.read(name.removeprefix("src/")) == (ROOT / name).read_bytes(), name
            metadata_name = next(name for name in archive.namelist()
                                 if name.endswith(".dist-info/METADATA"))
            metadata = archive.read(metadata_name).decode("utf-8")
            assert "langchain-openai==" in metadata and 'extra == "native"' in metadata
    print("PACKAGING_CHECK_PASSED", args.kind)


if __name__ == "__main__":
    main()
