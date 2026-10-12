"""攻击图 TXT + 主机映射表 -> 1.2.0 文档：这条入口必须一直在。

2026-10-06：这条链（src/graph/cli.py + projector/host_map/validations）在一次"删旧重建"里被整批删掉，
只剩编译好的 JSON 还在用——于是"从 txt 起手"这件事断了，谁也没发现（因为验证流程直接用旧 JSON）。
这里把入口钉住：编译出来的文档必须能被运行时加载，且与验证流程正在用的那份在**图本身**上一致。
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import project_graph                      # noqa: E402
from graph import rehydrate               # noqa: E402

INPUTS = ROOT / "data" / "inputs" / "hongri7"
SHIPPED = ROOT / "tests/fixtures/hongri7/reference.action_graph.json"

#: 图本身（与部署无关）的字段：主机映射表换了不该动它们。
GRAPH_FIELDS = ("input_nodes", "input_edges", "and_nodes", "terminal_or_nodes", "output_nodes",
                "dependency_entries", "dependency_types", "validation_by_kind",
                "unknown_leaf_validations")


def test_the_txt_plus_host_map_compiles_and_the_runtime_loads_it(tmp_path):
    code = project_graph.main([str(INPUTS / "Hongri7_v2.txt"),
                               "--output-dir", str(tmp_path),
                               "--host-map", str(INPUTS / "host_ip_map.csv"),
                               "--assets", str(INPUTS / "assets.json"),
                               "--json-only", "--force"])
    assert code == 0
    built = tmp_path / "json" / "Hongri7_v2.action_graph.json"
    assert built.is_file()

    document = json.loads(built.read_text(encoding="utf-8"))
    assert document["schema_version"] == "1.2.0"
    assert document["final_goal"] == ["43", "47"]
    hosts = {entry["host"]: entry for entry in document["hosts"]}
    # 主机映射表是逻辑名到地址的唯一来源：控制端、跳板双网卡、容器都要在里面。
    assert hosts["control"]["ips"] == ["192.168.52.128"]
    assert hosts["pc1"]["ips"] == ["192.168.52.30", "192.168.93.20"]
    assert hosts["web2_docker"]["kind"] == "container" and hosts["web2_docker"]["parent"] == "web2"

    view = rehydrate.load_file(built)
    assert len([n for n in view.nodes if n.get("type") == "AND"]) == 12


def test_the_compiled_graph_agrees_with_the_document_the_walk_uses(tmp_path):
    """验证流程读的是 output/ 里那份；它必须与"现在从 txt 编译出来的"在图上一致，否则两边会悄悄漂。"""
    assert project_graph.main([str(INPUTS / "Hongri7_v2.txt"),
                               "--output-dir", str(tmp_path),
                               "--host-map", str(INPUTS / "host_ip_map.csv"),
                               "--assets", str(INPUTS / "assets.json"),
                               "--json-only", "--force"]) == 0
    built = json.loads((tmp_path / "json" / "Hongri7_v2.action_graph.json").read_text(encoding="utf-8"))
    shipped = json.loads(SHIPPED.read_text(encoding="utf-8"))
    for field in GRAPH_FIELDS:
        assert built["summary"][field] == shipped["summary"][field], field
    assert [node["id"] for node in built["nodes"]] == [node["id"] for node in shipped["nodes"]]
    assert built["source_graph"] == shipped["source_graph"]


def test_the_walk_takes_the_txt_directly_and_keeps_the_compiled_graph(tmp_path):
    """正规入口：run_plan 直接吃攻击图 TXT，把它编译到本轮目录里再走。

    "从 txt 起手"必须是产品能力，不是某个临时脚本里的两行；编译产物落在 <run>/graph/ 下，
    这一轮用的是哪张图、哪份映射表、指纹是什么，跟着这一轮走。
    """
    from orchestration.bootstrap import load_graph_document

    path, document = load_graph_document(INPUTS / "Hongri7_v2.txt",
                                         host_map=INPUTS / "host_ip_map.csv",
                                         assets=INPUTS / "assets.json", run_root=tmp_path)
    assert path == tmp_path / "graph" / "Hongri7_v2.action_graph.json"
    assert path.is_file()
    assert document["final_goal"] == ["43", "47"]
    assert len([n for n in document.nodes if n.get("type") == "AND"]) == 12
    # 编译记录跟着这一轮：来源指纹可复核。
    assert document["inputs"]["graph_source"]["file"] == "data/inputs/hongri7/Hongri7_v2.txt"
