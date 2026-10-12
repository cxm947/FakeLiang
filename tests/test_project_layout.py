"""Regression checks for entry points, workspace paths, encoding and index documents."""

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from graph.paths import resolve_path, workspace_root
from tests.support import ROOT, entry_point_names


class ProjectLayoutTests(unittest.TestCase):
    def test_relative_paths_use_checkout_root(self):
        with patch("pathlib.Path.cwd", return_value=Path(tempfile.gettempdir())):
            self.assertEqual(workspace_root(), ROOT)
            self.assertEqual(resolve_path("output/reports"), ROOT / "output/reports")

    def test_absolute_paths_are_not_rebased(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "custom.json"
            self.assertEqual(resolve_path(target), target.resolve())

    def test_installed_package_falls_back_to_caller_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_checkout = Path(directory) / "not-a-checkout"
            with patch("graph.paths._SOURCE_ROOT", missing_checkout), \
                    patch("pathlib.Path.cwd", return_value=Path(directory)):
                self.assertEqual(workspace_root(), Path(directory).resolve())
                self.assertEqual(resolve_path("output"), Path(directory).resolve() / "output")

    def test_all_script_help_entry_points_work_from_another_directory(self):
        """The roster comes from the folder (tests/support.py::entry_point_names)."""
        with tempfile.TemporaryDirectory() as directory:
            for name in entry_point_names():
                with self.subTest(script=name):
                    result = subprocess.run(
                        [sys.executable, "-B", str(ROOT / "scripts" / name), "--help"],
                        cwd=directory, capture_output=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                    self.assertIn(b"usage:", result.stdout.lower())

    def test_the_index_documents_are_present_and_substantial(self):
        for document in ("README.md", "docs/file_tree.md", "scripts/README.md"):
            with self.subTest(document=document):
                text = (ROOT / document).read_text(encoding="utf-8")
                self.assertGreater(len(text.strip()), 200)

    def test_local_markdown_links_in_the_index_documents_resolve(self):
        documents = [ROOT / "README.md", ROOT / "docs" / "file_tree.md",
                     ROOT / "scripts" / "README.md", ROOT / "docs" / "product" / "README.md"]
        for document in documents:
            if not document.is_file():
                continue
            text = document.read_text(encoding="utf-8")
            for href in re.findall(r"\[[^\]\n]*\]\(([^)\n]+)\)", text):
                href = href.strip().strip("<>")
                if re.match(r"(?:[a-zA-Z][a-zA-Z0-9+.-]*:|#|/)", href):
                    continue
                target = (document.parent / href.split("#", 1)[0]).resolve()
                if target.is_relative_to(ROOT / "output") or target.is_relative_to(ROOT / "tmp"):
                    continue
                with self.subTest(document=str(document.relative_to(ROOT)), href=href):
                    self.assertTrue(target.exists(), f"Broken local link: {href}")

    def test_no_tracked_content_lives_under_a_tool_private_dot_directory(self):
        """Git keeps the history, so a committed tool-private folder is either redundant or a way
        to smuggle a batch of scratch files past every documentation scan."""
        result = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, timeout=60)
        if result.returncode != 0:
            self.skipTest("not a git checkout")
        allowed = {".github"}
        offenders = []
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            folders = line.split("/")[:-1]
            if any(part.startswith(".") and part not in allowed for part in folders):
                offenders.append(line)
        self.assertEqual([], offenders, "tool-private dot directories must not be committed")

    def test_no_committed_file_is_blank(self):
        result = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, timeout=60)
        if result.returncode != 0:
            self.skipTest("not a git checkout")
        keep = {"data/inputs/.gitkeep"}
        blank = []
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            if line in keep:
                continue
            path = ROOT / line
            if path.is_file() and not path.read_bytes().lstrip(b"\xef\xbb\xbf").strip():
                blank.append(line)
        self.assertEqual([], blank, "blank files belong in .gitkeep-style placeholders only")

    def test_text_sources_keep_one_encoding_discipline(self):
        """Source files are UTF-8 without a BOM; a .ps1 with non-ASCII needs one (PowerShell 5.1
        reads a BOM-less script as ANSI and mangles it)."""
        result = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, timeout=60)
        if result.returncode != 0:
            self.skipTest("not a git checkout")
        bom = b"\xef\xbb\xbf"
        offenders = []
        for name in result.stdout.decode("utf-8", errors="replace").splitlines():
            if not name.endswith((".py", ".md", ".json", ".csv", ".txt", ".ps1")):
                continue
            path = ROOT / name
            if not path.is_file():
                continue
            raw = path.read_bytes()
            has_bom = raw.startswith(bom)
            if name.endswith(".ps1"):
                if not has_bom and not raw.isascii():
                    offenders.append(name + ": non-ASCII PowerShell script without a BOM")
            elif has_bom:
                offenders.append(name + ": byte order mark on a non-PowerShell text file")
        self.assertEqual([], offenders,
                         "one encoding discipline: UTF-8 without BOM (PS1: BOM when non-ASCII)")

    def test_text_files_follow_the_declared_newline_policy(self):
        r"""LF everywhere (`.gitattributes`: `* text=auto eol=lf`); the only exceptions are
        `.cmd` / `.bat` (CRLF on purpose) and `archive/**` (kept as raw bytes). The expectation is
        read off the effective attributes rather than copied a second time into the test."""
        result = subprocess.run(["git", "ls-files", "--eol"], cwd=ROOT, capture_output=True, timeout=60)
        if result.returncode != 0:
            self.skipTest("not a git checkout")
        offenders = []
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            fields = line.split("\t")
            if len(fields) != 2:
                continue
            state, name = fields
            if name.startswith("archive/"):
                continue
            if not (ROOT / name).is_file():  # staged deletion: no working copy
                continue
            columns = state.split()
            attributes = " ".join(columns[2:])
            if "-text" in attributes or "binary" in attributes:
                continue
            expected = "w/crlf" if "eol=crlf" in attributes else "w/lf"
            if columns[0] != "i/lf":
                offenders.append(f"{name}: {columns[0]} in the index (text is stored as LF)")
            if columns[1] != expected:
                offenders.append(f"{name}: {columns[1]} in the working copy (expected {expected})")
        self.assertEqual([], offenders,
                         "one newline rule: LF everywhere, CRLF only for cmd/bat "
                         "(fix a drifted working copy with `git add --renormalize .`)")


if __name__ == "__main__":
    unittest.main()
