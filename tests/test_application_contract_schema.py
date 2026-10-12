"""Application identity declarations cannot expand their own evidence vocabulary."""
from copy import deepcopy
import json
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
PROFILE = {
    "id": "atlas_portal",
    "aliases": ["Atlas Portal", "星图门户"],
    "match_any": [{"source": "path", "literal": "/static/atlas.ico"}],
    "version_pattern": r"Atlas Portal (?P<version>[0-9]+[.][0-9]+)",
}


def validator():
    schema = json.loads((ROOT / "schemas/skill.schema.json").read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator({
        "$ref": "#/$defs/v2ApplicationIdentity", "$defs": schema["$defs"],
    })


def test_identity_profile_accepts_native_markers_and_optional_measured_version():
    assert validator().is_valid(PROFILE)
    minimal = {"id": "atlas_portal", "match_any": [{"source": "title", "literal": "星图门户"}]}
    assert validator().is_valid(minimal)


@pytest.mark.parametrize("patch", [
    {"id": " "},
    {"aliases": [""]},
    {"match_any": []},
    {"match_any": [{"source": "server", "literal": "Atlas"}]},
    {"match_any": [{"source": "path", "literal": ""}]},
    {"match_any": [{"source": "body", "literal": "Atlas", "trust_model": True}]},
    {"version_pattern": r"Atlas (\d+)"},
    {"model_override": True},
])
def test_identity_profile_rejects_empty_markers_server_identity_and_undeclared_controls(patch):
    profile = deepcopy(PROFILE)
    profile.update(patch)
    assert not validator().is_valid(profile)
