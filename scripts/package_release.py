#!/usr/bin/env python3
"""Create the audited source release without changing its source repository."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import posixpath
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

PROFILE = "agv-source-release-v1"
#: Audited for the tree rules below; moved forward so the release carries the tracked
#: Hongri7 fixtures the offline tests need, plus the batch-2 model layer.
BASE = "fbf9de4"
MANIFEST = "RELEASE-MANIFEST.json"
ROOT_FILES = {
    ".gitattributes", ".gitignore", "AGENTS.md", "CONTRIBUTING.md",
    "README.md", "pyproject.toml", "requirements.txt",
}
TREES = {
    "src", "skills", "catalog", "schemas", "scripts", "tests", "requirements",
}
DOC_SEEDS = {
    "docs/product/README.md", "docs/product/glossary.md", "docs/decisions.md",
    "docs/orchestration_batch2.md", "docs/orchestration_batch3.md",
}
IO_DIR = "IO\u534f\u8bae"
FENCE = chr(96) * 3
NOTES = (
    "\n"
    "## \u53d1\u5e03\u5305\uff1a\u4ece\u5e72\u51c0\u673a\u5668\u5f00\u59cb\n"
    "\n"
    "\u6e90\u63d0\u4ea4\uff1aCOMMIT\u3002\u53d1\u5e03\u9a8c\u6536\u4f7f\u7528 Python 3.12 (Windows x64)\uff1bpyproject \u7684 >=3.10 \u662f\u5143\u6570\u636e\u4e0b\u9650\u3002Git \u7528\u4e8e tree \u95f8\u3002\n"
    "\n"
    "\u672c\u5305\u5b89\u88c5\uff08\u9501\u6587\u4ef6\u4ec5\u9002\u7528 Windows AMD64 / CPython 3.12\uff0c\u4e0d\u662f\u5b8c\u6574\u79bb\u7ebf\u8f6e\u5b50\u5e93\uff09\uff1a\n"
    "\n"
    "FENCEpowershell\n"
    "py -3.12 -m venv .venv312\n"
    ".\\.venv312\\Scripts\\python.exe -m pip install --require-hashes --find-links requirements/wheels -r requirements/runtime-win-py312.lock\n"
    ".\\.venv312\\Scripts\\python.exe -m pip install --find-links requirements/wheels \".[test,lab,rpc,native]\"\n"
    "FENCE\n"
    "\n"
    "\u9010\u6b65\u9a8c\u6536\u547d\u4ee4\u89c1\u4e0a\u9762\u7684\u300c\u79bb\u7ebf\u68c0\u67e5\u300d\u3002\n"
    "\n"
    "\u79bb\u7ebf\u9a8c\u6536\u6240\u9700\u7684 Hongri7 \u5939\u5177\u968f\u672c\u5305\u63d0\u4f9b\uff1adata/inputs/hongri7/ \u7684\u4e09\u4efd\u8f93\u5165\uff0c\u4ee5\u53ca tests/fixtures/hongri7/reference.action_graph.json \u57fa\u51c6\u56fe\uff1b\u5b57\u8282\u54c8\u5e0c\u8bb0\u5f55\u5728 tests/fixtures/hongri7/manifest.json\uff0c\u65e0\u9700\u53e6\u884c\u7d22\u53d6\u3002\u672c\u5305\u4e0d\u542b run \u5386\u53f2\uff0c\u56e0\u6b64\u6838\u5bf9\u5f15\u7528\u4ea7\u7269\u7684\u7528\u4f8b\u4f1a\u5408\u7406\u8df3\u8fc7\uff0c\u5176\u4f59\u7528\u4f8b\u5e94\u5168\u7eff\u3002\n"
    "\n"
    "\u672a\u5305\u542b\uff1a\u8fd0\u884c\u65e5\u5fd7\u4e0e\u5386\u53f2\u4ea7\u7269\u3001output/\u3001tmp/\u3001build/\u3001\u865a\u62df\u73af\u5883\u4e0e\u7f13\u5b58\u3001\u5bc6\u94a5\u4e0e\u79c1\u6709\u914d\u7f6e\u3001\u9776\u573a\u955c\u50cf\u3001specs/\u3001IO \u5386\u53f2\u534f\u8bae\u3001\u65e7\u5b9e\u9a8c\u4e0e\u8fc1\u79fb\u6570\u636e\u3002tests/\u3001AGENTS.md \u548c\u5c11\u91cf\u5386\u53f2\u6587\u6863\u4e3a\u539f\u9a8c\u6536\u4fdd\u7559\u3002\u9010\u6587\u4ef6\u53bb\u7559\u4e0e\u6458\u8981\u89c1 RELEASE-MANIFEST.json\u3002\n"
)


def git(repo, *args, env=None):
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, env=env, check=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return result.stdout


def safe_name(name):
    path = PurePosixPath(name)
    return (
        name == path.as_posix() and not path.is_absolute()
        and all(part not in ("", ".", "..") for part in path.parts)
        and ":" not in name and "\\" not in name
    )


def read_commit(repo, commit):
    sha = git(repo, "rev-parse", "--verify", commit + "^{commit}").decode().strip()
    if not sha.startswith(BASE):
        raise ValueError("This profile was audited only for " + BASE)
    blobs, modes = {}, {}
    raw = git(repo, "archive", "--format=tar", sha)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            if member.isdir() or member.name == "pax_global_header":
                continue
            if not member.isfile() or not safe_name(member.name):
                raise ValueError("Unsupported archive entry: " + member.name)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("Unreadable archive entry: " + member.name)
            blobs[member.name] = stream.read()
            modes[member.name] = "100755" if member.mode & 0o111 else "100644"
    return sha, blobs, modes


def inventory(names):
    return (
        "\n<!-- agv:file-list:start -->\n" + FENCE + "json\n"
        + json.dumps(sorted(names), ensure_ascii=True, indent=2)
        + "\n" + FENCE + "\n<!-- agv:file-list:end -->\n"
    )


def direct_links(name, raw):
    for href in re.findall(r"\[[^\]\n]*\]\(([^)\n]+)\)", raw.decode("utf-8")):
        href = href.strip().strip("<>").split("#", 1)[0]
        if not href or re.match(r"(?:[a-zA-Z][a-zA-Z0-9+.-]*:|/)", href):
            continue
        yield posixpath.normpath(posixpath.join(posixpath.dirname(name), href))


def select(blobs):
    needed = set(DOC_SEEDS) | {"archive/README.md"}
    needed.update(direct_links(
        "docs/product/README.md", blobs["docs/product/README.md"]
    ))
    for name in blobs:
        if name.startswith("docs/product/reference/") and (
            name.endswith("/README.md") or name.endswith("skill_matcher_prd.md")
        ):
            needed.add(name)
    missing = needed - set(blobs)
    if missing:
        raise ValueError("Missing required documents: " + repr(sorted(missing)))
    #: Offline acceptance fixtures declare themselves in the manifest, so the release ships
    #: exactly what the tests need and nothing else from data/inputs/.
    fixtures = set()
    manifest = "tests/fixtures/hongri7/manifest.json"
    if manifest in blobs:
        declared = json.loads(blobs[manifest].decode("utf-8"))
        fixtures = {str(entry["path"]) for entry in declared.get("files") or ()}
        absent = fixtures - set(blobs)
        if absent:
            raise ValueError("Fixture manifest names untracked files: " + repr(sorted(absent)))
    selected = {}
    for name in sorted(blobs):
        root = name.split("/", 1)[0]
        if name in ROOT_FILES:
            reason = "project metadata, setup, navigation or unchanged test dependency"
        elif root in TREES:
            reason = "runtime code/assets, existing entry points, dependencies or original acceptance"
        elif name in needed:
            reason = "unchanged test dependency or protected product index link"
        elif name in fixtures:
            reason = "tracked offline acceptance fixture declared by tests/fixtures/hongri7/manifest.json"
        elif name == "data/README.md" or name == "data/inputs/.gitkeep":
            reason = "input conventions and placeholder"
        elif name.startswith(("data/attack/", "data/samples/")):
            reason = "tracked reference inputs and runnable examples"
        else:
            continue
        selected[name] = reason
    return selected


def dropped_reason(name):
    reasons = {
        "specs": "development specifications; comments/mock paths only, no runtime loader",
        IO_DIR: "historical protocol examples; no runtime or test loader",
        "archive": "old implementation/experiment backup; no current reader requires this file",
        "docs": "development/history page outside acceptance dependencies and product index links",
        "data": "retired migration/retrieval fixtures; no current runtime or test reader",
    }
    root = name.split("/", 1)[0]
    if root not in reasons:
        raise ValueError("Unreviewed exclusion: " + name)
    return reasons[root]


def render(sha, blobs, modes, script):
    reasons = select(blobs)
    out = {name: blobs[name] for name in reasons}
    original = out["README.md"].decode("utf-8")
    original = re.sub(
        r"\[([^\]\n]*)\]\(specs/README\.md\)", r"\1 (not included)", original
    )
    out["README.md"] = (
        original.rstrip() + "\n"
        + NOTES.replace("COMMIT", sha).replace("FENCE", FENCE)
    ).encode("utf-8")
    out[".gitignore"] += b"\n# Release-local environments.\n.venv*/\n"
    out["scripts/package_release.py"] = script
    out["docs/README.md"] = (
        "# \u53d1\u5e03\u6587\u6863\n\n"
        "[\u5b89\u88c5\u4e0e\u8fd0\u884c](../README.md)\n\n"
        "[\u4ea7\u54c1\u5bfc\u822a](product/README.md)\n\n"
        "[\u6587\u4ef6\u6e05\u5355](file_tree.md)\n"
    ).encode("utf-8")
    out["archive/README.md"] = (
        "# \u5386\u53f2\u9a8c\u6536\u4f9d\u8d56\n\n"
        "\u672c\u76ee\u5f55\u4ec5\u4fdd\u7559\u539f\u6d4b\u8bd5\u548c\u4ea7\u54c1\u5bfc\u822a"
        "\u9700\u8981\u7684\u5386\u53f2\u53c2\u8003\uff0c"
        "\u4e0d\u662f\u5f53\u524d\u8fd0\u884c\u5165\u53e3\u3002\n"
    ).encode("utf-8")
    script_intro = blobs["scripts/README.md"].decode("utf-8").split(
        "## Tracked file inventory", 1
    )[0]
    out["scripts/README.md"] = (
        script_intro.rstrip()
        + "\n\npackage_release.py: deterministic source release / --verify.\n"
        + inventory(name for name in out if name.startswith("scripts/"))
    ).encode("utf-8")
    names = set(out) | {MANIFEST, "docs/file_tree.md"}
    out["docs/file_tree.md"] = (
        "# \u53d1\u5e03\u6587\u4ef6\u5730\u56fe\n\n"
        "\u672c\u6e05\u5355\u662f\u53d1\u5e03\u76ee\u5f55\u7684\u5b8c\u6574\u8ddf\u8e2a\u6587\u4ef6"
        "\u6e05\u5355\uff0c\u7531\u6e90\u63d0\u4ea4\u548c\u56fa\u5b9a\u53d1\u5e03\u89c4\u5219\u751f\u6210\u3002"
        "\u53bb\u7559\u539f\u56e0\u548c\u539f\u59cb/\u53d1\u5e03 SHA-256 \u89c1 RELEASE-MANIFEST.json\u3002"
        "\u4ee3\u7801\u3001\u5361\u3001\u539f\u6d4b\u8bd5\u4fdd\u7559\u6e90\u5b57\u8282\uff1b"
        "\u6587\u6863\u6e05\u5355\u5bf9\u5e94\u672c\u53d1\u5e03\u4ed3\u5e93\uff0c"
        "\u4e0d\u662f\u6e90\u4ed3\u5e93\u7684\u4ea7\u7269\u76ee\u5f55\u3002\n"
        + inventory(names)
    ).encode("utf-8")
    rows = []
    for name in sorted(set(blobs) | set(out) | {MANIFEST}):
        old, new = blobs.get(name), out.get(name)
        action = "dropped" if name not in names else (
            "generated" if old is None else "copied" if old == new else "derived"
        )
        reason = dropped_reason(name) if action == "dropped" else reasons.get(
            name, "generated release metadata/tool"
        )
        if action == "derived":
            reason += "; release-only navigation/ignore overlay"
        rows.append({
            "path": name, "action": action, "reason": reason,
            "source_sha256": hashlib.sha256(old).hexdigest() if old is not None else None,
            "sha256": hashlib.sha256(new).hexdigest() if new is not None else None,
            "mode": modes.get(name, "100644") if action != "dropped" else None,
        })
    audit = []
    terms = (
        "specs", "archive", IO_DIR, "AGENTS.md",
        "docs", "migration", "retrieval_suite",
    )
    for name, raw in sorted(blobs.items()):
        if name.split("/", 1)[0] not in {"src", "scripts", "tests"}:
            continue
        if not name.endswith((".py", ".md", ".txt", ".json", ".ps1")):
            continue
        lines = raw.decode("utf-8-sig", "replace").splitlines()
        for line_no, line in enumerate(lines, 1):
            if any(term in line for term in terms):
                audit.append({"path": name, "line": line_no, "text": line[:240]})
    manifest = {
        "profile": PROFILE,
        "source_commit": sha,
        "rules": {
            "whole_trees": sorted(TREES),
            "root_files": sorted(ROOT_FILES),
            "data": [
                "data/README.md", "data/inputs/.gitkeep",
                "data/attack/**", "data/samples/**",
            ],
            "documents": (
                "test seeds, historical README/matcher fixtures "
                "and direct protected-product-index links"
            ),
            "absent": [
                "output", "tmp", "build", ".venv*", ".pytest_cache", ".idea",
            ],
        },
        "reference_audit": audit,
        #: These used to be "external" inputs the caller had to supply. They are tracked in the
        #: tree now, so the release ships them and names the manifest that records their bytes.
        "acceptance_fixtures": [
            "data/inputs/hongri7/Hongri7_v2.txt",
            "data/inputs/hongri7/host_ip_map.csv",
            "data/inputs/hongri7/assets.json",
            "tests/fixtures/hongri7/reference.action_graph.json",
        ],
        "acceptance_fixtures_note": (
            "shipped inside this release; tests/fixtures/hongri7/manifest.json records their "
            "byte hashes, so the caller does not have to supply them"
        ),
        "files": rows,
        "self_hash": "omitted to avoid circular hashing; Git commits the manifest bytes",
    }
    out[MANIFEST] = (
        json.dumps(manifest, ensure_ascii=True, indent=2) + "\n"
    ).encode("utf-8")
    if out["docs/product/README.md"] != blobs["docs/product/README.md"]:
        raise ValueError("Protected product README changed")
    return out, rows


def verify(dest):
    body = json.loads((dest / MANIFEST).read_text(encoding="utf-8"))
    wanted = set()
    for row in body["files"]:
        if row["action"] == "dropped":
            continue
        name = row["path"]
        if not safe_name(name):
            raise ValueError("Invalid manifest path")
        wanted.add(name)
        path = dest / name
        if not path.is_file():
            raise ValueError("Missing release file: " + name)
        if row["sha256"]:
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_hash != row["sha256"]:
                raise ValueError("Release hash changed: " + name)
    if (dest / ".git").exists():
        actual = set(
            git(dest, "ls-files", "-z").decode("utf-8").split("\0")
        ) - {""}
        if actual != wanted:
            raise ValueError("Release index differs from manifest")
    print("Verified", len(wanted), "release files from", body["source_commit"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--commit", default=BASE)
    parser.add_argument("--dest", type=Path)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify is not None:
        verify(args.verify.resolve())
        return
    if args.dest is None:
        parser.error("--dest is required unless --verify is used")
    repo, dest = args.repo.resolve(), args.dest.resolve()
    if dest.exists() or dest.is_relative_to(repo) or repo.is_relative_to(dest):
        parser.error("--dest must be a new directory outside the source repository")
    script = Path(__file__).read_bytes().replace(b"\r\n", b"\n")
    if not script.isascii():
        raise ValueError("Save this generator as ASCII")
    sha, blobs, modes = read_commit(repo, args.commit)
    out, rows = render(sha, blobs, modes, script)
    dest.mkdir(parents=True)
    for name, raw in sorted(out.items()):
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    verify(dest)
    subprocess.run(["git", "init", "-b", "main", str(dest)], check=True)
    git(dest, "config", "core.autocrlf", "false")
    git(dest, "config", "core.hooksPath", ".git/hooks")
    git(dest, "add", "-f", "--", ".")
    for row in rows:
        if row["mode"] == "100755":
            git(dest, "update-index", "--chmod=+x", "--", row["path"])
    stamp = git(repo, "show", "-s", "--format=%cI", sha).decode().strip()
    env = dict(
        os.environ,
        GIT_AUTHOR_DATE=stamp, GIT_COMMITTER_DATE=stamp,
        GIT_AUTHOR_NAME="AGV Release Builder",
        GIT_COMMITTER_NAME="AGV Release Builder",
        GIT_AUTHOR_EMAIL="release-builder@example.invalid",
        GIT_COMMITTER_EMAIL="release-builder@example.invalid",
    )
    git(
        dest, "-c", "commit.gpgsign=false", "commit",
        "-m", "Release source " + sha, env=env,
    )
    verify(dest)
    if git(dest, "status", "--porcelain").strip():
        raise ValueError("Release working tree is not clean")
    print(
        "Ready:", dest, "main",
        git(dest, "rev-parse", "--short", "HEAD").decode().strip(),
    )


if __name__ == "__main__":
    main()
