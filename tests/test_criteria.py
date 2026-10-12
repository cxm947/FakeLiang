"""验证层的输入：判据来自图自己的依赖，不依赖历史运行产物。"""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from graph import criteria, rehydrate  # noqa: E402


@pytest.fixture(scope="module")
def compiled_graph(tmp_path_factory):
    """Compile the repository inputs once, entirely inside pytest's temp directory."""
    source = ROOT / "data" / "inputs" / "hongri7" / "Hongri7_v2.txt"
    host_map = source.parent / "host_ip_map.csv"
    assets = source.parent / "assets.json"

    for path in (source, host_map, assets):
        assert path.is_file(), "Missing repository input: %s" % path

    output_dir = tmp_path_factory.mktemp("criteria-graph")
    command = [
        sys.executable,
        "-B",
        "-X",
        "utf8",
        str(ROOT / "scripts" / "project_graph.py"),
        str(source),
        "--host-map",
        str(host_map),
        "--assets",
        str(assets),
        "--output-dir",
        str(output_dir),
        "--json-only",
    ]
    done = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert done.returncode == 0, (
        "Graph compilation failed:\n%s\n%s" % (done.stdout, done.stderr)
    )

    compiled = sorted(output_dir.rglob("*.action_graph.json"))
    assert len(compiled) == 1, (
        "Expected one compiled graph under %s, got %r" % (output_dir, compiled)
    )
    assert compiled[0].is_file(), "Compiled graph is not a file: %s" % compiled[0]
    return compiled[0]


@pytest.fixture
def document(compiled_graph):
    """Give each test a fresh document, as the old document() helper did."""
    return rehydrate.load_file(compiled_graph)


def test_a_node_carries_the_criteria_its_dependencies_already_have(document):
    rows = criteria.node_criteria(document, "44")
    by_ref = {row["ref"]: row for row in rows}
    assert by_ref["39"]["validation_kind"] == "network_reachability"
    assert by_ref["39"]["validation_fields"]["port"] == "445"
    assert by_ref["45"]["validation_kind"] == "service_exposure"
    assert by_ref["46"]["validation_kind"] == "capability"
    assert by_ref["3"]["validation_kind"] == "credential"
    # A broad validation class does not imply a machine-checkable declaration.
    assert by_ref["39"]["declaration_kind"] == "assumption"
    assert by_ref["39"]["predicate"] == "hacl"
    # An OR fact carries no machine criterion of its own.
    assert by_ref["6"]["type"] == "OR"
    assert by_ref["6"]["validation_kind"] == "unknown"


def test_the_facts_a_step_must_produce_are_picked_out_of_its_own_dependencies(document):
    produced = criteria.to_produce(document, "44")
    assert [row["fact"] for row in produced] == ["execCode(dc,system)"]
    assert "44" in produced[0]["produced_by"]


def test_an_unknown_node_is_a_named_refusal(document):
    with pytest.raises(ValueError, match="^CRITERIA_NODE_UNKNOWN"):
        criteria.node_criteria(document, "nope")
