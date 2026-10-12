"""Local CI wiring stays honest (scripts/ci.py, scripts/hooks/pre-commit).

The pipeline itself is the roster of offline checks; this file guards the wiring around it: the
check list, the ``--no-record`` escape hatch, green -> green record, red -> red record + exit 1,
and that the pre-commit hook calls the very entry point a human runs. No test here may drive the
whole roster -- pytest-inside-pytest would recurse -- so every recording run is fed a fake check.
The two ``--check`` modes are pure and are exercised for real.
"""

import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_ci():
    spec = importlib.util.spec_from_file_location("agv_ci", ROOT / "scripts" / "ci.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_check(exit_code):
    """A stand-in for a real check: cheap, offline, and free of pytest recursion."""
    code = "print('fake check tail'); raise SystemExit(%d)" % exit_code
    return ("fake", [sys.executable, "-B", "-X", "utf8", "-c", code])


class LocalCiTests(unittest.TestCase):
    def test_roster_is_the_three_offline_checks_and_pytest_stays_on_tests(self):
        ci = load_ci()
        checks = ci.build_checks()
        self.assertEqual(["pytest", "cards", "tree"], [name for name, _ in checks])
        pytest_cmd = checks[0][1]
        self.assertEqual(sys.executable, pytest_cmd[0])
        self.assertIn("tests/", pytest_cmd)
        self.assertNotIn("archive", pytest_cmd)

    def test_the_card_check_reads_every_face_on_this_tree(self):
        ci = load_ci()
        problems, summary = ci.check_cards()
        self.assertEqual([], problems)
        self.assertEqual(1, len(summary))

    def test_the_tree_check_maps_every_source_file_on_this_tree(self):
        ci = load_ci()
        problems, _summary = ci.check_tree()
        self.assertEqual([], problems)

    def test_no_record_leaves_no_trace(self):
        ci = load_ci()
        with tempfile.TemporaryDirectory() as directory:
            record_dir = Path(directory) / "ci"
            with patch.object(ci, "RECORD_DIR", record_dir), \
                    patch.object(ci, "build_checks", return_value=[fake_check(0)]), \
                    redirect_stdout(io.StringIO()):
                code = ci.main(["--no-record"])
            self.assertEqual(0, code)
            self.assertFalse(record_dir.exists())

    def test_green_run_binds_a_record_to_the_revision(self):
        ci = load_ci()
        commit = ci.git("rev-parse", "--short", "HEAD")
        if commit is None:
            self.skipTest("not a git checkout")
        commit = commit.strip()
        with tempfile.TemporaryDirectory() as directory:
            record_dir = Path(directory) / "ci"
            with patch.object(ci, "RECORD_DIR", record_dir), \
                    patch.object(ci, "build_checks", return_value=[fake_check(0)]), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(0, ci.main(["--label", "test"]))
            latest = json.loads((record_dir / "latest.json").read_text(encoding="utf-8"))
            self.assertEqual("pass", latest["result"])
            self.assertEqual("test", latest["label"])
            self.assertEqual(commit, latest["commit"])
            self.assertEqual(0, latest["checks"][0]["exit"])
            self.assertIn("seconds", latest["checks"][0])
            named = record_dir / (commit + ("-dirty" if latest["dirty"] else "") + ".json")
            self.assertTrue(named.is_file(), "the result is also filed under its revision")

    def test_red_check_becomes_a_red_record_and_exit_one(self):
        ci = load_ci()
        with tempfile.TemporaryDirectory() as directory:
            record_dir = Path(directory) / "ci"
            with patch.object(ci, "RECORD_DIR", record_dir), \
                    patch.object(ci, "build_checks", return_value=[fake_check(1)]), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(1, ci.main([]))
            latest = json.loads((record_dir / "latest.json").read_text(encoding="utf-8"))
            self.assertEqual("fail", latest["result"])
            self.assertEqual(1, latest["checks"][0]["exit"])
            self.assertTrue(latest["checks"][0]["tail"], "a red record keeps the output tail")

    def test_pre_commit_hook_calls_the_same_entry_point_a_human_runs(self):
        hook = ROOT / "scripts" / "hooks" / "pre-commit"
        text = hook.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!"), "the hook needs a shebang for the POSIX shell")
        self.assertIn("scripts/ci.py", text)
        self.assertIn("--label pre-commit", text)
        self.assertIn("--no-verify", text, "the deliberate bypass is documented on the hook itself")
        listed = subprocess.run(["git", "ls-files", "-s", "--", "scripts/hooks/pre-commit"],
                                cwd=ROOT, capture_output=True, text=True, timeout=30)
        if listed.returncode == 0 and listed.stdout.strip():
            self.assertTrue(listed.stdout.startswith("100755"),
                            "hooks carry the executable bit in the index: git add --chmod=+x")


class TreeInventoryTests(unittest.TestCase):
    START = "<!-- agv:file-list:start -->"
    END = "<!-- agv:file-list:end -->"
    DOCUMENTS = ("docs/file_tree.md", "scripts/README.md")

    def block(self, entries):
        return (
            self.START + "\n```json\n"
            + json.dumps(entries, ensure_ascii=False, indent=2)
            + "\n```\n" + self.END + "\n"
        )

    def write_inventory(self, root, document, entries, outside=""):
        (root / document).write_text(
            outside + self.block(entries), encoding="utf-8"
        )

    def entries_for(self, document, names):
        if document == "docs/file_tree.md":
            return list(names)
        return [name for name in names if name.startswith("scripts/")]

    @contextmanager
    def tree(self, *extra_names):
        ci = load_ci()
        names = sorted(set(self.DOCUMENTS).union(extra_names))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n", encoding="utf-8")
            for document in self.DOCUMENTS:
                self.write_inventory(
                    root, document, self.entries_for(document, names)
                )
            with patch.object(ci, "ROOT", root), patch.object(
                ci, "git", return_value="\0".join(names) + "\0"
            ) as git_mock:
                yield ci, root, names, git_mock
                git_mock.assert_called_once_with("ls-files", "-z")

    def assert_problem(self, ci, fragment):
        problems, summary = ci.check_tree()
        self.assertEqual(1, len(summary))
        self.assertTrue(problems, "the malformed inventory must fail")
        self.assertIn(fragment, "\n".join(problems))

    def test_complete_inventories_accept_full_paths_and_filename_characters(self):
        with self.tree(
            ".gitattributes",
            "src/a/common.py",
            "src/b/common.py",
            "scripts/a/tool.py",
            "scripts/b/tool.py",
            "scripts/setup.ps1",
            "scripts/hooks/pre-commit",
            "skills/demo/SKILL.md",
            "skills/demo/skill.json",
            "skills/demo/tools/check.py",
            "skills/demo/assets/中文 file [draft].txt",
            "specs/001/check.py",
        ) as (ci, _root, _names, _git):
            problems, summary = ci.check_tree()
            self.assertEqual([], problems)
            self.assertEqual(1, len(summary))

    def test_same_basename_and_text_outside_inventory_do_not_cover_missing_path(self):
        missing = "src/b/common.py"
        with self.tree("src/a/common.py", missing) as (ci, root, names, _git):
            self.write_inventory(
                root,
                "docs/file_tree.md",
                [name for name in names if name != missing],
                outside="The prose also names `%s`.\n" % missing,
            )
            self.assert_problem(
                ci, "docs/file_tree.md: missing path: " + missing
            )

    def test_file_inventory_requires_cards_assets_specs_scripts_and_hidden_files(self):
        required = (
            "skills/demo/SKILL.md",
            "skills/demo/skill.json",
            "skills/demo/tools/check.py",
            "skills/demo/assets/payload.bin",
            "specs/001/check.py",
            "scripts/setup.ps1",
            ".gitattributes",
        )
        for missing in required:
            with self.subTest(path=missing):
                with self.tree(missing) as (ci, root, names, _git):
                    self.write_inventory(
                        root, "docs/file_tree.md",
                        [name for name in names if name != missing],
                    )
                    self.assert_problem(
                        ci, "docs/file_tree.md: missing path: " + missing
                    )

    def test_script_inventory_independently_requires_nested_scripts_ps1_and_hook(self):
        scripts = (
            "scripts/a/tool.py",
            "scripts/b/tool.py",
            "scripts/setup.ps1",
            "scripts/hooks/pre-commit",
        )
        for missing in scripts:
            with self.subTest(path=missing):
                with self.tree(*scripts) as (ci, root, names, _git):
                    entries = self.entries_for("scripts/README.md", names)
                    self.write_inventory(
                        root, "scripts/README.md",
                        [name for name in entries if name != missing],
                        outside="The usage table names `%s`.\n" % missing,
                    )
                    self.assert_problem(
                        ci, "scripts/README.md: missing path: " + missing
                    )

    def test_duplicate_entries_fail_in_either_inventory(self):
        for document in self.DOCUMENTS:
            with self.subTest(document=document):
                with self.tree("scripts/tool.py") as (ci, root, names, _git):
                    entries = self.entries_for(document, names)
                    self.write_inventory(root, document, entries + [entries[0]])
                    self.assert_problem(
                        ci, document + ": duplicate path: " + entries[0]
                    )

    def test_missing_tracked_file_is_not_filtered_out(self):
        missing = "specs/001/check.py"
        with self.tree(missing) as (ci, root, _names, _git):
            (root / missing).unlink()
            self.assert_problem(ci, "tracked: not a file: " + missing)

    def test_directory_cannot_replace_a_tracked_file(self):
        name = "scripts/setup.ps1"
        with self.tree(name) as (ci, root, _names, _git):
            (root / name).unlink()
            (root / name).mkdir()
            self.assert_problem(ci, "tracked: not a file: " + name)

    def test_extra_entries_fail_whether_missing_or_present_but_untracked(self):
        for document in self.DOCUMENTS:
            for exists in (False, True):
                with self.subTest(document=document, exists=exists):
                    with self.tree() as (ci, root, names, _git):
                        extra = "scripts/untracked.py"
                        if exists:
                            (root / extra).write_text("fixture\n", encoding="utf-8")
                        entries = self.entries_for(document, names)
                        self.write_inventory(root, document, entries + [extra])
                        self.assert_problem(
                            ci, document + ": unexpected path: " + extra
                        )

    def test_extra_directory_is_not_a_file_entry(self):
        name = "scripts/folder"
        with self.tree() as (ci, root, names, _git):
            (root / name).mkdir()
            self.write_inventory(root, "docs/file_tree.md", names + [name])
            self.assert_problem(ci, "docs/file_tree.md: not a file: " + name)

    def test_script_inventory_rejects_a_tracked_path_outside_scripts(self):
        name = "src/module.py"
        with self.tree(name) as (ci, root, names, _git):
            entries = self.entries_for("scripts/README.md", names)
            self.write_inventory(root, "scripts/README.md", entries + [name])
            self.assert_problem(ci, "scripts/README.md: unexpected path: " + name)

    def test_noncanonical_paths_are_rejected(self):
        invalid = (
            "", "../outside.py", "/absolute.py",
            "C:/absolute.py", "C:relative.py", "src\\module.py",
            "src//module.py", "./src/module.py",
            "src/../module.py", "src/module.py/", "src/\0module.py",
        )
        for name in invalid:
            with self.subTest(path=repr(name)):
                with self.tree() as (ci, root, names, _git):
                    self.write_inventory(root, "docs/file_tree.md", names + [name])
                    self.assert_problem(ci, "invalid inventory path:")

    def test_wildcards_do_not_cover_files(self):
        with self.tree("src/module.py") as (ci, root, names, _git):
            entries = [name for name in names if name != "src/module.py"]
            self.write_inventory(root, "docs/file_tree.md", entries + ["src/*.py"])
            self.assert_problem(ci, "docs/file_tree.md: missing path: src/module.py")

    def test_malformed_inventories_report_problems_instead_of_raising(self):
        good = self.block(list(self.DOCUMENTS))
        malformed = (
            good.replace(self.START, "", 1),
            good.replace(self.END, "", 1),
            good + good,
            self.END + "\n" + self.START + "\n",
            good.replace("```json", "```text", 1),
            good.replace("[", "[,", 1),
            self.block({"path": "docs/file_tree.md"}),
            self.block(None),
            self.block([None]),
            self.block([True]),
            self.block([12]),
            self.block([{}]),
            self.block([[]]),
        )
        for text in malformed:
            with self.subTest(text=text):
                with self.tree() as (ci, root, _names, _git):
                    (root / "docs/file_tree.md").write_text(
                        text, encoding="utf-8"
                    )
                    self.assert_problem(ci, "docs/file_tree.md:")

    def test_failed_empty_or_truncated_git_output_is_not_a_pass(self):
        for listed in (None, "", "src/module.py"):
            with self.subTest(listed=listed):
                with self.tree() as (ci, _root, _names, git_mock):
                    git_mock.return_value = listed
                    self.assert_problem(ci, "git ls-files -z")

    def test_duplicate_git_paths_are_reported(self):
        with self.tree() as (ci, _root, names, git_mock):
            git_mock.return_value = "\0".join(names + [names[0]]) + "\0"
            self.assert_problem(ci, "git ls-files -z: duplicate path:")


if __name__ == "__main__":
    unittest.main()
