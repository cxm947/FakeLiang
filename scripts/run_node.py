#!/usr/bin/env python3
"""Run one graph node through the executor: the model proposes, the run checks the citation.

爷爷 2026-10-04："
  - 卡面只留固定字段 + 给模型读的正文；"when" 说清这张卡回答哪种节点；
  - 引擎只留三条硬约束：不假通过（引用必须在本次原始输出里）、不重放改动类、不越范围；
  - 其余（检索、打分、叶映射、观察派生、变体准入、阶段机、未决对账）都删掉，按新工作流重做。

所以这个入口只有三步：
  1) 读图，取节点的固定字段（目标、端口、传输）与它的 case/service/technique；
  2) 用 `skills.bind` 在图节点与卡面 `when` 之间做匹配（匹配不到就具名缺口，不猜）；
  3) 把任务与**一个端点**的 scope 交给 `run_lean_task.drive`。

它**不登记图事实、不登记会话**：结果是"带核验的模型报告"，不是机器事实。退出码 0 = 这份报告收了。
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from agents._model import client as model_mod          # noqa: E402
from graph import rehydrate                    # noqa: E402
from graph.paths import resolve_path           # noqa: E402
from runtime.remote import SshExecutor, parse_remote   # noqa: E402
from runtime.lean import mask_secrets           # noqa: E402
from skills import bind                        # noqa: E402
from agents.executor import driver as run_lean_task                           # noqa: E402


def find_node(document, node_id):
    for node in document["nodes"]:
        if str(node.get("id")) == str(node_id):
            return node
    raise SystemExit("NODE_NOT_FOUND: " + str(node_id))


def host_map_of(path):
    rows = {}
    if not path:
        return rows
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        cells = [cell.strip() for cell in text.split(",")]
        if len(cells) >= 2 and cells[0] != "host":
            rows.setdefault(cells[0], cells[1])
    return rows


def prepare(node, host_map, card, carrier=None):
    """The node's own fixed fields -> one task with one frozen scope.

    Which scope a node gets is decided by what the node *is*, not by the card: a node with a
    numeric endpoint runs at that endpoint from the base box; a node that only exists on a
    machine an existing handle already reaches (no port of its own - a path inside one sandbox,
    a local identity read) runs *through* the selected handle, and its scope says which handle.
    A node with neither is a named refusal, not a guess. Only the card's own declared inputs are
    filled - everything else is the model's or the runtime's business.
    """
    logical = str(node.get("target_host") or "")
    host = str(host_map.get(logical) or logical)
    port = str(node.get("port") or "").strip()
    if host and port.isdigit():
        scope = {"host": host, "port": int(port), "protocol": "tcp",
                 "vantage": "base", "resources": "whole_endpoint"}
    elif carrier is not None:
        # The step runs through the handle that was selected for it; the scope names that handle, so
        # the runtime can check it really is the handle the executor is bound to. The *address* is the
        # one this step is aimed at - the node's own target - because a position step is not
        # necessarily aimed where its pipe lives: crossing out of an isolated position onto the host
        # behind it is aimed at the host while it still runs through the position's handle. The
        # handle's address is only the fallback for a node whose target has no address of its own.
        address = host if host and host != logical else str(carrier.get("host") or "")
        scope = {"host": address, "vantage": "position",
                 "resources": "execution_position",
                 "carrier": str(carrier.get("channel_id") or ""),
                 "logical": logical}
    else:
        raise ValueError("LEAN_NODE_NO_ENDPOINT: this node has no numeric endpoint (host + port) "
                         "and no channel was selected to run it through")
    inputs = {}
    for name in (card.get("inputs") or {}):
        if name in {"target_host", "host", "target"}:
            inputs[name] = host
        elif name in {"port", "service_port", "target_port"}:
            inputs[name] = str(port)
        elif name == "protocol":
            inputs[name] = str(node.get("protocol") or "tcp")
        elif name == "expected_service":
            inputs[name] = str(node.get("service") or "")
        elif name in {"source_host", "from_host"}:
            logical_source = str(node.get("source_host") or "")
            inputs[name] = str(host_map.get(logical_source) or logical_source)
        elif name == "source_ref":
            inputs[name] = "node:" + str(node.get("id"))
    if str(node.get("service") or ""):
        inputs.setdefault("expected_service", str(node["service"]))
    task = {"node_id": str(node.get("id")),
            "goal": str(node.get("rule_desc") or node.get("description") or node.get("id")),
            "inputs": inputs, "scope": scope}
    return task, scope


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="run_node.py", description=__doc__)
    parser.add_argument("--node", required=True)
    parser.add_argument("--graph", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--host-map", default=None)
    parser.add_argument("--remote", default=None, help="attack box, user@host[:port]")
    parser.add_argument("--chain", default=None,
                        help="LEAN_CHAIN_UNSUPPORTED: 本版本只驱动一个 SSH 跳；"
                             "多跳载体是另一个模块，这里只做具名拒绝")
    parser.add_argument("--password", default=None)
    parser.add_argument("--key", default=None)
    parser.add_argument("--python", default="python3")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--max-steps", type=int, default=8)
    parser.add_argument("--model", default=None, required=True,
                        help="要验证的是模型的输出，所以这个入口必须有模型")
    parser.add_argument("--model-base-url", default="")
    parser.add_argument("--model-api-key-env", default="AGV_MODEL_API_KEY")
    parser.add_argument("--model-timeout", type=float, default=60.0)
    args = parser.parse_args(argv)
    from agents._model.backend import freeze_backend
    try:
        backend = freeze_backend(resolve_path(args.run_dir))
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 3

    if args.chain:
        print("error: LEAN_CHAIN_UNSUPPORTED: this version drives one SSH hop; "
              "a multi-hop carrier is a separate capability", file=sys.stderr)
        return 3
    if not args.remote:
        print("error: give --remote (one hop) or --chain (several hops)", file=sys.stderr)
        return 3
    password = args.password or os.environ.get("AGV_SSH_PASSWORD")
    if not args.chain and not password and not args.key:
        print("error: give --password/AGV_SSH_PASSWORD or --key", file=sys.stderr)
        return 3

    document = rehydrate.load_file(resolve_path(args.graph))
    node = find_node(document, args.node)
    host_map = host_map_of(resolve_path(args.host_map)) if args.host_map else {}
    run_dir = resolve_path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    client = model_mod.client_from_env(name=args.model, base_url=args.model_base_url,
                                       api_key_env=args.model_api_key_env,
                                        timeout=args.model_timeout, backend=backend)
    card, gap, binding_selection = bind.bind(
        node, bind.faces(ROOT), client=client, timeout=args.model_timeout)
    selection = {
        "node_id": str(node.get("id")),
        "status": "selected" if card is not None else "blocked",
        "binding_selection": binding_selection,
        "reason": gap,
    }
    selection = mask_secrets(selection, [value for value in (password,) if value])
    (run_dir / "card_selection.json").write_text(
        json.dumps(selection, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    if card is None:
        print("error: " + selection["reason"], file=sys.stderr)
        return 3

    try:
        task, scope = prepare(node, host_map, card)
    except ValueError as error:
        print("error: " + str(error), file=sys.stderr)
        return 3

    executor = SshExecutor(parse_remote(args.remote), password=password, key_filename=args.key)
    try:
        try:
            result = run_lean_task.drive(card, task, scope, executor, client=client, run_dir=run_dir,
                                         python=args.python, timeout=args.timeout,
                                         max_steps=args.max_steps, model_timeout=args.model_timeout,
                                         secrets=[value for value in (password,) if value])
        except (ValueError, OSError, RuntimeError) as error:
            # A card that needs what this version cannot supply (a session, a credential) is a
            # named refusal, not a crash: the node stays unfinished and says why.
            result = {"status": "uncertain", "reason": str(error)}
    finally:
        executor.close()
    result["node_id"] = str(node.get("id"))
    result["card"] = str(card["id"])
    result["binding_selection"] = selection["binding_selection"]
    result["endpoint"] = scope
    result["lean_lane"] = {"registers_graph_facts": False, "registers_sessions": False,
                           "machine_verified": False}
    (run_dir / "node_result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get("status") == "model_reported":
        return 0
    blocked = ("LEAN_TASK_INPUT_UNBOUND", "LEAN_VANTAGE_BINDING_UNAVAILABLE",
               "LEAN_CHAIN_UNSUPPORTED", "NODE_HAS_NO_CASE", "CARD_GAP")
    return 3 if str(result.get("reason") or "").startswith(blocked) else 2


if __name__ == "__main__":
    raise SystemExit(main())
