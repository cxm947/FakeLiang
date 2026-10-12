"""Append-only inventory extension must retain the original strict checks."""
import json
import pytest
from tests import test_ci as ci_support


def block(entries):
    fence = chr(96) * 3
    return ("<!-- agv:file-list:append:start -->\n" + fence + "json\n" +
            json.dumps(entries) + "\n" + fence + "\n<!-- agv:file-list:append:end -->\n")


def append(root, text):
    with (root / "docs/file_tree.md").open("a", encoding="utf-8") as stream:
        stream.write(text)


def test_append_maps_new_file_without_rewriting_original():
    fixture = ci_support.TreeInventoryTests()
    added = "tests/test_batch2_inventory.py"
    with fixture.tree(added) as (ci, root, names, _git):
        fixture.write_inventory(root, "docs/file_tree.md", [n for n in names if n != added])
        before = (root / "docs/file_tree.md").read_bytes()
        append(root, block([added]))
        assert (root / "docs/file_tree.md").read_bytes().startswith(before)
        problems, _ = ci.check_tree()
        assert problems == []


def test_append_rejects_duplicates():
    fixture = ci_support.TreeInventoryTests()
    with fixture.tree() as (ci, root, names, _git):
        append(root, block([names[0]]))
        fixture.assert_problem(ci, "duplicate path: " + names[0])


@pytest.mark.parametrize("text", [
    block([]).replace("<!-- agv:file-list:append:end -->", ""),
    block([]) + block([]),
    block({}),
    block(["../escape.py"]),
    block([]).replace(chr(96) * 3 + "json", chr(96) * 3 + "text"),
    block(["tests/untracked.py"]),
])
def test_append_rejects_malformed_or_untracked_paths(text):
    fixture = ci_support.TreeInventoryTests()
    with fixture.tree() as (ci, root, _names, _git):
        append(root, text)
        fixture.assert_problem(ci, "docs/file_tree.md:")


def test_append_must_follow_base_block():
    fixture = ci_support.TreeInventoryTests()
    with fixture.tree() as (ci, root, _names, _git):
        path = root / "docs/file_tree.md"
        path.write_text(block([]) + path.read_text(encoding="utf-8"), encoding="utf-8")
        fixture.assert_problem(ci, "docs/file_tree.md:")
