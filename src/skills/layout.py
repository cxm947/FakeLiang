"""One place that knows where a skill card lives, and what its business id is.

The Agent Skills format wants a skill's directory to be its ``name`` (lowercase, hyphens). This
repository keeps the *business id* (``exploit.redis_unauth_write``) as the identity the registry,
the graph bindings and history speak in. The two are joined by the release map
(``catalog/skill-release-map.json``), so no reader has to guess:

* :func:`business_id` - a folder name (either spelling) -> the business id;
* :func:`skill_dir`    - a business id -> the folder that actually holds the card;
* :func:`card_folders` - every card folder on disk, with its business id.

Two rules keep this honest: the map is the only translation (nothing derives an id from a
directory name by string surgery), and a folder that is in neither spelling is reported instead
of being silently skipped.
"""
from __future__ import annotations

import json
from pathlib import Path

SKILLS = "skills"
RELEASE_MAP = "catalog/skill-release-map.json"


def _root(root) -> Path:
    return Path(root).resolve() if root is not None else Path(__file__).resolve().parents[2]


def release_rows(root=None) -> list[dict]:
    """The release map rows, which carry both names and the package identity.

    The map is a repository-level artifact, so a caller that passed a *sub*directory (``skills``,
    a scratch root) still gets the real map instead of silently falling back to folder names.
    """
    for base in (_root(root), Path(__file__).resolve().parents[2]):
        path = base / RELEASE_MAP
        if path.is_file():
            return list(json.loads(path.read_text(encoding="utf-8")).get("skills") or [])
    return []


def by_folder(root=None) -> dict[str, dict]:
    """folder name -> release row, for both the standard name and the legacy path."""
    table: dict[str, dict] = {}
    for row in release_rows(root):
        table[row["agent_skill_name"]] = row
        table[row["skill_id"]] = row
        for legacy in row.get("legacy_paths") or []:
            name = str(legacy).rstrip("/").split("/")[-1]
            if name:
                table[name] = row
    return table


def business_id(folder_name: str, root=None) -> str:
    """The business id behind a folder name - the name itself when it is not in the map."""
    row = by_folder(root).get(str(folder_name))
    return row["skill_id"] if row else str(folder_name)


def skill_dir(skill_id: str, root=None) -> Path:
    """The folder that holds one card, whichever naming state the tree is in."""
    base = _root(root) / SKILLS
    row = next((item for item in release_rows(root) if item["skill_id"] == skill_id), None)
    names = [row["agent_skill_name"], skill_id] if row else [skill_id]
    for name in names:
        if name and (base / name / "skill.json").is_file():
            return base / name
    for name in names:
        if name and (base / name).is_dir():
            return base / name
    return base / (names[0] if names else skill_id)


def card_folders(root=None) -> list[tuple[str, Path]]:
    """(business id, folder) for every card folder under ``skills/``, sorted by id."""
    base = _root(root) / SKILLS
    found: list[tuple[str, Path]] = []
    for folder in sorted(base.iterdir()):
        if not folder.is_dir() or not (folder / "skill.json").is_file():
            continue
        found.append((business_id(folder.name, root), folder))
    return found
