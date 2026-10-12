"""走图日志：人读的 txt 必须来自本轮验证自己的证据。

爷爷 2026-10-06: 要有一个专属的记录方式，一个 txt 就能看到每一轮每个攻击步骤 —— planner 给的
下一步、前置过没过、利用段每次调用、验证结果、会话管理结果 —— 这样读文件就能了解进度，不必一直
盯着验证过程。这个测试用一份最小的模拟验证产物，钉住这五段都在，而且数值来自产物本身。
"""
import json
import pathlib

from scripts import journal


def build_run(tmp_path):
    run = tmp_path / "e2e-fixture"
    node = run / "node14"
    (node / "calls" / "call-1").mkdir(parents=True)
    (node / "calls" / "call-1" / "call.json").write_text(json.dumps({
        "call_id": "call-1", "status": "executed",
        "argv": ["nmap", "-sT", "-p", "6379", "10.0.0.5"]}), encoding="utf-8")
    events = [
        {"kind": "intent", "call_id": "call-1", "at": 1000.0,
         "request": {"tool": "shell", "argv": ["nmap"]}},
        {"kind": "receipt", "call_id": "call-1",
         "receipt": {"status": "completed_transport", "returncode": 0}},
        {"kind": "refusal", "refusal": {"reason_code": "LEAN_HTTP_PATH_INVALID",
                                        "detail": "relative request target required"}},
        {"kind": "conclusion", "result": {"claimed_verdict": "pass",
                                          "claim": "port 6379 answered syn-ack"}},
    ]
    (node / "events.jsonl").write_text(
        "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n", encoding="utf-8")
    (run / "channels.jsonl").write_text(json.dumps({
        "kind": "console_session", "host": "10.0.0.5", "privilege": "root", "session_id": "1",
        "source_node": "14", "note": "migrated after the exec fact"}, ensure_ascii=False) + "\n",
        encoding="utf-8")
    (run / "plan_result.json").write_text(json.dumps({
        "order": ["14"], "proved": ["14"], "stopped": [], "blocked": [],
        "blocked_upstream": {},
        "planner": [{"source": "model", "chosen": "14", "note": "", "node": "14"}],
        "nodes": {"14": {"status": "proved", "card": "pre.nmap_tcp_probe",
                         "reason": "MODEL_CLAIM_NOT_MACHINE_VERIFIED",
                         "claimed_verdict": "pass", "run_dir": str(node),
                         "migration": {"state": "completed", "listen_port": 1080,
                                       "sessions": ["1"], "fact_host": "web1"}}},
    }, ensure_ascii=False), encoding="utf-8")
    graph = tmp_path / "graph.json"
    graph.write_text(json.dumps({"nodes": [{"id": "14", "type": "AND", "dependencies": [
        {"ref": "15", "type": "LEAF", "description": "hacl(attacker,web1,tcp,6379)"}]}]},
        ensure_ascii=False), encoding="utf-8")
    return run, graph


def test_the_journal_carries_the_five_things_爷爷_asked_for(tmp_path):
    run, graph = build_run(tmp_path)
    text = journal.render(run, graph_path=str(graph))
    assert "验证轮次：e2e-fixture" in text
    assert "顺序：14" in text and "成立 1 个" in text
    assert "planner 给的下一步：node 14（来源 model）" in text          # ① planner
    assert "调用（1 次）" in text and "nmap" in text and "completed_transport" in text   # ③ 利用段
    assert "拒绝回喂：LEAN_HTTP_PATH_INVALID" in text                   # 回喂也看得见
    assert "验证结果" in text and "通过" in text and "port 6379 answered" in text        # ④ 验证
    assert "登记 console_session host=10.0.0.5 priv=root sess=1" in text               # ⑤ 会话
    assert "迁移：completed" in text and "端口=1080" in text
    assert "前置（OR）" not in text, "图里没有 OR 依赖时不编前置"


def test_the_journal_shows_who_produced_each_前置(tmp_path):
    run, graph = build_run(tmp_path)
    plan = json.loads((run / "plan_result.json").read_text(encoding="utf-8"))
    plan["nodes"]["12"] = {"status": "proved", "card": "exploit.fixture", "run_dir": str(run / "node12")}
    plan["order"] = ["14", "12"]
    plan["proved"] = ["14", "12"]
    (run / "plan_result.json").write_text(json.dumps(plan, ensure_ascii=False), encoding="utf-8")
    (run / "node12").mkdir()
    graph.write_text(json.dumps({"nodes": [
        {"id": "12", "type": "AND", "dependencies": [
            {"ref": "13", "type": "OR", "description": "netAccess(web1,tcp,6379)",
             "produced_by": ["14"]}]}]}, ensure_ascii=False), encoding="utf-8")
    text = journal.render(run, graph_path=str(graph))
    assert "前置（OR）：netAccess(web1,tcp,6379) → 由 node 14 成立" in text


def test_the_cli_writes_the_run_file_and_appends_to_the_rolling_journal(tmp_path):
    run, graph = build_run(tmp_path)
    rolling = tmp_path / "WALK-JOURNAL.txt"
    assert journal.main(["--run", str(run), "--graph", str(graph),
                         "--journal", str(rolling)]) == 0
    assert (run / "walk.txt").is_file()
    first = rolling.read_text(encoding="utf-8")
    journal.main(["--run", str(run), "--graph", str(graph), "--journal", str(rolling)])
    assert rolling.read_text(encoding="utf-8").count("验证轮次：e2e-fixture") == 2
    assert first.startswith("=")


def test_a_run_without_plan_result_is_an_error_not_an_empty_file(tmp_path):
    with_ = tmp_path / "empty"
    with_.mkdir()
    try:
        journal.render(with_)
    except FileNotFoundError:
        return
    raise AssertionError("a run with no result must not silently produce an empty journal")
