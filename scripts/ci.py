#!/usr/bin/env python
"""Local CI: the offline checks, each bound to the revision it ran on.

Roster (nothing here touches a target or a model):

  1. ``pytest tests/ -q``   the offline suite
  2. ``--check cards``      every card folder carries a readable lean face (the eight required
                            fields, a non-empty body, unique ids, a well-formed ``when``)
  3. ``--check tree``       the index documents name every source file they map
                            (``docs/file_tree.md``, ``scripts/README.md``)

Every run writes ``output/reports/ci/<commit>[-dirty].json`` plus ``latest.json`` with the
revision, the dirty flag, per-check exit code, seconds and the output tail, so a result can be
pointed at a revision later.

Exit codes: 0 all green / 1 a check failed / 2 usage error (argparse).
"""
from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD_DIR = ROOT / "output" / "reports" / "ci"
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))


def git(*args):
    try:
        done = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError:
        return None
    if done.returncode != 0:
        return None
    return done.stdout


def repo_files():
    """Files that travel with the repo: tracked plus not-yet-tracked, minus ignored ones."""
    listed = git("ls-files", "--cached", "--others", "--exclude-standard")
    if listed is None:
        return []
    names = {line.strip().replace("\\", "/") for line in listed.splitlines() if line.strip()}
    #: A staged deletion is still in the index but has no working copy; it maps nothing.
    return sorted(name for name in names if (ROOT / name).is_file())


def check_cards():
    """Every card folder must carry one readable lean face."""
    from skills import layout
    from skills.lean import load_card

    problems: list = []
    rows: list = []
    seen: dict = {}
    base = ROOT / "skills"
    for folder in sorted(base.iterdir()):
        if not folder.is_dir() or folder.name.startswith("_"):
            continue
        if not (folder / "skill.json").is_file():
            continue  # not a card folder (the machine contract is the marker)
        if not (folder / "SKILL.md").is_file():
            problems.append("%s: no SKILL.md" % folder.name)
            continue
        card_id = layout.business_id(folder.name, base)
        try:
            card = load_card(card_id, ROOT)
        except (ValueError, OSError) as error:
            problems.append("%s: %s" % (folder.name, error))
            continue
        if card["id"] in seen:
            problems.append("%s and %s both call themselves %s"
                            % (seen[card["id"]], folder.name, card["id"]))
        seen[card["id"]] = folder.name
        rows.append((card["id"], len(card["body"])))
    return problems, ["%d cards, %d bytes of knowledge"
                      % (len(rows), sum(size for _id, size in rows))]


def appended_inventory(lines, base_end, document, problems, marker="append"):
    start = "<!-- agv:file-list:" + marker + ":start -->"
    end = "<!-- agv:file-list:" + marker + ":end -->"
    starts = [i for i, line in enumerate(lines) if line == start]
    ends = [i for i, line in enumerate(lines) if line == end]
    if not starts and not ends:
        return []
    if len(starts) != 1 or len(ends) != 1 or not base_end < starts[0] < ends[0]:
        problems.append(document + ": invalid appended inventory markers")
        return []
    block = "\n".join(lines[starts[0] + 1:ends[0]]).strip().splitlines()
    if len(block) < 3 or block[0] != "```json" or block[-1] != "```":
        problems.append(document + ": appended inventory must be one fenced JSON array")
        return []
    try:
        entries = json.loads("\n".join(block[1:-1]))
    except (ValueError, RecursionError):
        problems.append(document + ": invalid appended inventory JSON")
        return []
    if not isinstance(entries, list):
        problems.append(document + ": appended inventory must be a JSON array")
        return []
    return entries


def check_tree():
    """Compare explicit inventories with complete, tracked repository paths."""
    from collections import Counter
    from pathlib import PureWindowsPath

    start_marker = "<!-- agv:file-list:start -->"
    end_marker = "<!-- agv:file-list:end -->"
    problems = []

    def valid_name(name):
        if not isinstance(name, str) or not name:
            return False
        if "\0" in name or "\\" in name or PureWindowsPath(name).drive:
            return False
        return all(part not in ("", ".", "..") for part in name.split("/"))

    def check_file(name, owner):
        try:
            is_file = (ROOT / name).is_file()
        except OSError as error:
            problems.append("%s: cannot inspect %s: %s" % (owner, name, error))
            return
        if not is_file:
            problems.append("%s: not a file: %s" % (owner, name))

    try:
        listed = git("ls-files", "-z")
    except (OSError, subprocess.SubprocessError) as error:
        return ["git ls-files -z failed: %s" % error], ["tree inventory unavailable"]

    if listed is None:
        return ["git ls-files -z failed"], ["tree inventory unavailable"]
    if not listed:
        return ["git ls-files -z returned an empty index"], ["tree inventory unavailable"]
    if not listed.endswith("\0"):
        return ["git ls-files -z returned non-NUL-terminated output"], [
            "tree inventory unavailable"
        ]

    names = listed[:-1].split("\0")
    invalid = [name for name in names if not valid_name(name)]
    if invalid:
        return [
            "git ls-files -z: invalid path: %r" % name for name in invalid
        ], ["tree inventory unavailable"]

    for name, count in sorted(Counter(names).items()):
        if count > 1:
            problems.append("git ls-files -z: duplicate path: %s" % name)

    tracked = set(names)
    for name in sorted(tracked):
        check_file(name, "tracked")

    cases = (
        ("docs/file_tree.md", tracked),
        ("scripts/README.md", {name for name in tracked if name.startswith("scripts/")}),
    )
    mapped_total = 0
    for document, expected in cases:
        if document not in tracked:
            problems.append("%s: inventory document is not tracked" % document)
        try:
            lines = (ROOT / document).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as error:
            problems.append("%s: cannot read inventory: %s" % (document, error))
            continue

        starts = [i for i, line in enumerate(lines) if line == start_marker]
        ends = [i for i, line in enumerate(lines) if line == end_marker]
        if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
            problems.append("%s: invalid inventory markers" % document)
            continue

        block = "\n".join(lines[starts[0] + 1:ends[0]]).strip().splitlines()
        if len(block) < 3 or block[0] != "```json" or block[-1] != "```":
            problems.append("%s: inventory must be one fenced JSON array" % document)
            continue
        try:
            entries = json.loads("\n".join(block[1:-1]))
        except (ValueError, RecursionError) as error:
            problems.append("%s: invalid inventory JSON: %s" % (document, error))
            continue
        if not isinstance(entries, list):
            problems.append("%s: inventory must be a JSON array" % document)
            continue

        entries += appended_inventory(lines, ends[0], document, problems)
        previous = [i for i, line in enumerate(lines)
                    if line == "<!-- agv:file-list:append:end -->"]
        lower_bound = previous[0] if len(previous) == 1 else ends[0]
        entries += appended_inventory(
            lines, lower_bound, document, problems, marker="batch3")
        newest = [i for i, line in enumerate(lines)
                  if line == "<!-- agv:file-list:batch3:end -->"]
        native_bound = newest[0] if len(newest) == 1 else lower_bound
        entries += appended_inventory(
            lines, native_bound, document, problems, marker="native-tools")
        valid_entries = []
        for name in entries:
            if not valid_name(name):
                problems.append("%s: invalid inventory path: %r" % (document, name))
                continue
            valid_entries.append(name)

        for name, count in sorted(Counter(valid_entries).items()):
            if count > 1:
                problems.append("%s: duplicate path: %s" % (document, name))

        mapped = set(valid_entries)
        mapped_total += len(mapped)
        for name in sorted(expected - mapped):
            problems.append("%s: missing path: %s" % (document, name))
        for name in sorted(mapped - expected):
            problems.append("%s: unexpected path: %s" % (document, name))
        # Tracked paths were checked above; also inspect extra listed paths.
        for name in sorted(mapped - tracked):
            check_file(name, document)

    return problems, [
        "%d tracked files; %d inventory entries checked" % (len(tracked), mapped_total)
    ]


INLINE_CHECKS = {"cards": check_cards, "tree": check_tree}


def build_checks():
    python = [sys.executable, "-B", "-X", "utf8"]
    return [
        ("pytest", python + ["-m", "pytest", "tests/", "-q"]),
        ("cards", python + [str(Path(__file__).resolve()), "--check", "cards"]),
        ("tree", python + [str(Path(__file__).resolve()), "--check", "tree"]),
    ]


def tail(text, lines=14):
    rows = [row for row in (text or "").splitlines() if row.strip()]
    return "\n".join(rows[-lines:])


def run_inline(name):
    problems, summary = INLINE_CHECKS[name]()
    for row in summary:
        print(row)
    for problem in problems:
        print("  ! " + problem)
    print("%s: %s (%d problem%s)" % (name, "pass" if not problems else "FAIL",
                                     len(problems), "" if len(problems) == 1 else "s"))
    return 0 if not problems else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="local CI: the offline checks, bound to the revision")
    parser.add_argument("--label", default="manual", help="who triggered the run (manual / pre-commit)")
    parser.add_argument("--no-record", action="store_true", help="do not write output/reports/ci/*.json")
    parser.add_argument("--check", choices=sorted(INLINE_CHECKS), default=None,
                        help="run one check in this process and print its report")
    args = parser.parse_args(argv)
    if args.check:
        return run_inline(args.check)

    started = datetime.datetime.now().astimezone()
    results = []
    for name, cmd in build_checks():
        begin = time.perf_counter()
        done = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        seconds = time.perf_counter() - begin
        results.append({"name": name, "cmd": " ".join(cmd), "exit": done.returncode,
                        "seconds": round(seconds, 2),
                        "tail": tail((done.stdout or "") + "\n" + (done.stderr or ""))})
        print("ci  %-9s %s %6.2fs" % (name, "pass" if done.returncode == 0 else "FAIL", seconds))
        if done.returncode != 0:
            print("-------- " + name + " output tail --------")
            print(results[-1]["tail"])

    passed = all(row["exit"] == 0 for row in results)
    commit = (git("rev-parse", "--short", "HEAD") or "no-commit").strip()
    dirty = bool((git("status", "--porcelain") or "").strip())
    record = {
        "label": args.label,
        "commit": commit,
        "branch": (git("rev-parse", "--abbrev-ref", "HEAD") or "?").strip(),
        "dirty": dirty,
        "python": sys.executable,
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "result": "pass" if passed else "fail",
        "checks": results,
    }
    location = ""
    if not args.no_record:
        RECORD_DIR.mkdir(parents=True, exist_ok=True)
        body = json.dumps(record, ensure_ascii=False, indent=2) + "\n"
        path = RECORD_DIR / ((commit + ("-dirty" if dirty else "")) + ".json")
        path.write_text(body, encoding="utf-8", newline="\n")
        (RECORD_DIR / "latest.json").write_text(body, encoding="utf-8", newline="\n")
        try:
            shown = str(path.relative_to(ROOT))
        except ValueError:  # a caller-patched record dir (tests) sits outside the checkout
            shown = str(path)
        location = " -> " + shown.replace("\\", "/")

    ok = sum(1 for row in results if row["exit"] == 0)
    print("ci: %s %d/%d @ %s%s%s" % ("PASS" if passed else "FAIL", ok, len(results), commit,
                                     " (dirty)" if dirty else "", location))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
