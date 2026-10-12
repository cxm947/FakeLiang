"""Card-declared assets: the file a card ships is placed on the execution end, once.

爷爷 2026-10-06: a card whose tool only exists because someone copied it there by hand is a
deployment nobody can reproduce. The card declares the path its own recipe names, and the runtime
places the file before the node runs - content decides, so a second run does not rewrite it.
"""
import pathlib

import pytest

from runtime import assets
from skills.lean import load_card


def make_card(tmp_path, *, declared, files):
    # under a fake skills root: a declaration may name another card's file, never the host's
    folder = tmp_path / "skills" / "card"
    (folder / "poc").mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (folder / name).write_text(text, encoding="utf-8", newline="")
    (folder / "SKILL.md").write_text("---\n---\n", encoding="utf-8", newline="")
    return {"id": "exploit.fixture", "path": str(folder / "SKILL.md"), "assets": declared}


class Executor:
    """A tiny execution end: remembers files, answers sha256sum for them."""

    def __init__(self, files=None):
        self.files = dict(files or {})
        self.commands = []
        self.fail = False

    def __call__(self, argv, timeout):
        command = argv[-1]
        self.commands.append(command)
        from hashlib import sha256
        if command.startswith("sha256sum ") and "| cut -d' ' -f1" in command and "mkdir" not in command:
            target = command.split("sha256sum ", 1)[1].split(" 2>/dev/null", 1)[0].strip("'")
            payload = self.files.get(target)
            out = sha256(payload).hexdigest() if payload is not None else ""
            return type("O", (), {"stdout": out, "returncode": 0})()
        if "base64 -d" in command:
            if self.fail:
                return type("O", (), {"stdout": "", "returncode": 1})()
            import base64
            import re
            target = re.search(r">\s*'?([^']+?)'?\s*&&", command).group(1)
            blob = re.search(r"echo\s+(\S+)\s+\|", command).group(1)
            payload = base64.b64decode(blob)
            self.files[target] = payload
            return type("O", (), {"stdout": sha256(payload).hexdigest() + "\n", "returncode": 0})()
        return type("O", (), {"stdout": "", "returncode": 0})()


def test_a_declared_asset_is_pushed_once_and_then_left_alone(tmp_path):
    card = make_card(tmp_path, declared={"/opt/tools/run.py": "poc/run.py"},
                     files={"poc/run.py": "print('hello')\n"})
    executor = Executor()
    first = assets.ensure(card, executor)
    assert first == ["/opt/tools/run.py"]
    assert executor.files["/opt/tools/run.py"] == b"print('hello')\n"
    second = assets.ensure(card, executor)
    assert second == ["/opt/tools/run.py (already there)"]
    assert [c for c in executor.commands if "base64 -d" in c] is not None
    assert len([c for c in executor.commands if "base64 -d" in c]) == 1, "no rewrite on the second call"


def test_a_declared_asset_that_is_missing_or_escapes_the_card_is_refused(tmp_path):
    missing = make_card(tmp_path, declared={"/opt/tools/run.py": "poc/absent.py"}, files={})
    with pytest.raises(ValueError) as error:
        assets.declared(missing, tmp_path)
    assert "LEAN_CARD_ASSET_MISSING" in str(error.value)
    # the loader refuses a destination that is not absolute and a source that is absolute
    from skills import lean
    for declared_assets in ('{"relative": "poc/run.py"}', '{"/opt/tools/run.py": "/etc/passwd"}',
                            '{}'):
        text = ("---\nname: exploit-fixture\ndescription: x\nid: exploit.fixture\n"
                "kind: method\nruns_at: base\ndelivers: [\"evidence\"]\ninputs: {}\n"
                "tools: [\"shell\"]\nassets: " + declared_assets + "\n---\nbody\n")
        with pytest.raises(ValueError) as error:
            lean.parse(text)
        assert "LEAN_CARD_ASSETS_INVALID" in str(error.value), declared_assets
    # and the placement refuses a source that leaves the repository's skills tree
    root = pathlib.Path(__file__).resolve().parents[1]
    escaping = {"id": "exploit.fixture",
                "path": str(root / "skills" / "exploit-laravel-ignition-rce" / "SKILL.md"),
                "assets": {"/tmp/agv-tools/run.py": "../../../etc/passwd"}}
    with pytest.raises(ValueError) as error:
        assets.declared(escaping, root)
    assert "LEAN_CARD_ASSET_OUTSIDE_SKILLS" in str(error.value)


def test_an_unpushed_asset_is_an_error_not_a_silent_pass(tmp_path):
    card = make_card(tmp_path, declared={"/opt/tools/run.py": "poc/run.py"},
                     files={"poc/run.py": "x"})
    executor = Executor()
    executor.fail = True
    with pytest.raises(ValueError) as error:
        assets.ensure(card, executor)
    assert "LEAN_CARD_ASSET_UNPUSHED" in str(error.value)


def test_the_cards_that_ship_a_tool_declare_where_it_goes():
    """The three files a body names are declared, and the declaration matches the recipe."""
    root = pathlib.Path(__file__).resolve().parents[1]
    for card_id in ("exploit.laravel_ignition_rce", "exploit.suid_path_hijack",
                    "exploit.http_post_file"):
        card = load_card(card_id, root)
        pairs = assets.declared(card, root)
        assert pairs, card_id
        for dest, source in pairs:
            assert dest.startswith("/tmp/agv-tools/"), dest
            assert source.is_file(), source
        recipe = " ".join((card.get("channel") or {}).get("recipe") or [])
        for dest, _source in pairs:
            if recipe:
                assert dest in recipe, (card_id, dest)


def test_the_remote_path_stays_posix_when_the_engine_runs_on_windows(tmp_path):
    """A remote path is not a host path.

    Measured 2026-10-06 (e2e-full-40): Path("/tmp/agv-tools/x.py").parent hands back
    a back-slash-prefixed directory on Windows, so the control box created a directory whose name started with a
    literal backslash and the write failed with "Directory nonexistent" - the whole web2 branch was
    refused. The placement must always speak POSIX to the far side.
    """
    card = make_card(tmp_path, declared={"/tmp/agv-tools/deep/x.py": "poc/run.py"},
                     files={"poc/run.py": "x"})
    executor = Executor()
    assets.ensure(card, executor, root=tmp_path)
    push = [c for c in executor.commands if "base64 -d" in c][-1]
    assert "mkdir -p /tmp/agv-tools/deep" in push, push[:120]
    assert chr(92) not in push.split("echo")[0], push[:120]
