"""Run one real graph action through the durable service and VMware Guest Operations."""

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import shlex
import sys
from time import time_ns
from uuid import uuid4
from zoneinfo import ZoneInfo

import yaml

from src.agents._model.client import create_chat_model, load_model_config
from src.agents.executor.schema import ExecutionRequest
from src.agents.pre_verifier.mcp_client import command_for
from src.agents.pre_verifier.vmware_guest import VMwareGuest, ps_quote
from src.session.action_service import ActionService
from src.session.planner_store import PlannerStore, now
from src.orchestration.lab_settings import lock_name


def save(path, value):
    """Keep an immutable revision before updating the readable current file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    revisions = path.parent / ".revisions"
    revisions.mkdir(exist_ok=True)
    token = f"{time_ns():020d}-{uuid4().hex}"
    revision = revisions / f"{path.name}.{token}.json"
    revision.write_text(content, encoding="utf-8", newline="\n")
    pending = path.with_name(f".{path.name}.{token}.tmp")
    try:
        pending.write_text(content, encoding="utf-8", newline="\n")
        pending.replace(path)
    except PermissionError:
        # Windows readers may deny rename while allowing writes. No polling or
        # retries: the immutable revision remains available even if both fail.
        try:
            path.write_text(content, encoding="utf-8", newline="\n")
            if path.read_text(encoding="utf-8") != content:
                return revision
        except PermissionError:
            return revision
        finally:
            try:
                pending.unlink(missing_ok=True)
            except PermissionError:
                pass
    return path


class RecordedModel:
    def __init__(self, model, folder):
        self.model, self.folder = model, Path(folder)
        self.sequence = len(list(self.folder.glob("*.json")))

    def with_structured_output(self, schema, **options):
        bound = self.model.with_structured_output(schema, **options)
        owner = self

        class Recorded:
            def invoke(self, messages):
                owner.sequence += 1
                path = owner.folder / f"{owner.sequence:03d}-{schema['title']}.json"
                record = {"phase": schema["title"], "started_at": now(), "status": "started"}
                save(path, record)
                try:
                    response = bound.invoke(messages)
                except Exception as exc:
                    save(path, {**record, "status": "interrupted", "error_type": type(exc).__name__})
                    raise
                raw = response.get("raw")
                save(path, {**record, "status": "returned", "finished_at": now(),
                    "parsed": response.get("parsed"),
                    "raw_content": raw.content if raw is not None else None,
                    "raw_tool_calls": raw.tool_calls if raw is not None else [],
                    "parse_error": type(response["parsing_error"]).__name__ if response.get("parsing_error") else None})
                return response

        return Recorded()


class ActionDispatch:
    def __init__(self, guest, execution, directory):
        self.guest, self.execution, self.directory = guest, execution, Path(directory)
        self.sequence = len(list(self.directory.glob("dispatch-*.json")))

    def __call__(self, value):
        request = ExecutionRequest.model_validate(value)
        if request.via != "vmware":
            return {"effect_known": True, "response": {"return_code": 1,
                    "error": "This execution context requires via=vmware; request was not dispatched"}}
        if self.execution["platform"] == "windows":
            if request.tool == "tool":
                command = "& " + " ".join(ps_quote(v) for v in [request.name, *request.content])
            elif request.tool == "code" and request.name != "powershell":
                return {"effect_known": True, "response": {"return_code": 1,
                        "error": "Windows code requests require powershell; request was not dispatched"}}
            else:
                command = request.content
        else:
            command = command_for(request.model_dump())
        forbidden = [r"\b(?:Start-Sleep|sleep|usleep|nanosleep)\b"]
        forbidden.extend(re.escape(name) + r"\b" for name in self.execution.get("unavailable_commands", []))
        if any(re.search(pattern, command, re.I) for pattern in forbidden):
            observation = {"effect_known": True, "response": {
                "return_code": 1, "error": "Request rejected before dispatch: wait or unavailable command",
                "dispatched": False}}
            number = len(list(self.directory.glob("rejected-*.json"))) + 1
            save(self.directory / f"rejected-{number:03d}.json", {
                "request": request.model_dump(), "command": command, "at": now(),
                "status": "rejected_before_dispatch", "observation": observation})
            return observation
        self.sequence += 1
        path = self.directory / f"dispatch-{self.sequence:03d}.json"
        record = {"started_at": now(), "request": request.model_dump(),
                  "command": command, "execution_host": self.execution["vm"],
                  "platform": self.execution["platform"], "status": "dispatching"}
        save(path, record)
        try:
            response = self.guest.execute(self.execution["vm"], command)
            observation = {"effect_known": not response["transport_error"], "response": response}
        except RuntimeError as exc:
            observation = {"effect_known": False, "response": {"error": str(exc)}}
        save(path, {**record, "status": "returned", "finished_at": now(), "observation": observation})
        return observation


def rollback_lab(guest, snapshots, directory):
    names = [entry["vm"] for entry in snapshots]
    if not names or len(set(names)) != len(names) or not set(names) <= set(guest.config.guests):
        raise ValueError("Every lab VM must be unique and configured")
    # Validate every binding before reverting the first machine.
    for entry in snapshots:
        if not Path(guest.config.guests[entry["vm"]].vmx).is_file() or not entry["snapshot"]:
            raise ValueError("Invalid VM or snapshot binding")
    progress = {"started_at": now(), "status": "resetting", "serial": True, "records": []}
    path = Path(directory) / "rollback.json"
    for entry in snapshots:
        progress["current"] = entry["vm"]
        save(path, progress)
        started = now()
        try:
            result = guest.revert(entry["vm"], entry["snapshot"])
        except Exception as exc:
            progress.update(status="failed", error_type=type(exc).__name__, finished_at=now())
            save(path, progress)
            raise
        progress["records"].append({**result, "started_at": started, "finished_at": now()})
        save(path, progress)
    progress.update(status="completed", current=None, finished_at=now())
    save(path, progress)
    return progress


def execution_context(document, node_id, lab, guest):
    node = next(n for n in document["nodes"] if n["id"] == node_id)
    hosts = {h["host"]: h["ips"] for h in document["hosts"]}
    target = node.get("target_host", node.get("host"))
    vm = lab["source_vm"]
    return {"via": "vmware", "vm": vm, "platform": guest.platform(vm),
        "source_host": node.get("source_host"), "target_host": target,
        "target_ips": hosts[target], "protocol": node.get("protocol"), "port": node.get("port"),
        "topology": lab.get("topology", {}),
        "instructions": "当前请求由代码在给定 vm 上通过 VMware Guest Operations 执行；via 必须为 vmware。"
            "模型只生成请求和判断，不调用工具、不回滚。使用给定目标地址和端口，禁止等待、轮询、sleep。"
            "连接设有限超时；执行返回本身就是本步证据，按实际返回决定继续或结束。"
            "Direct Network Access 只需建立指定协议连接并输出可核对的远端响应，不执行后续利用。"}


def independent_review(guest, state, directory):
    """One fresh fixed probe for Direct Network Access, independent of model commands."""
    context = state["context"]
    execution = context["execution"]
    review = {"created_at": now(), "kind": "independent_runtime_review",
              "node_id": context["node"]["id"], "action_result": state.get("result"),
              "post_executed": False}
    if context["node"].get("rule_desc") != "Direct Network Access":
        review.update(verdict="unknown", reason="This CLI has no independent probe for this action type")
    else:
        ip, port = execution["target_ips"][0], int(execution["port"])
        script = ("import json,socket\n"
                  f"s=socket.create_connection(({ip!r},{port}),timeout=8)\n"
                  "s.settimeout(8)\nr={'peer':list(s.getpeername()),'connected':True}\n")
        if execution["protocol"] in {"http", "https"}:
            if execution["protocol"] == "https":
                script += f"import ssl\ns=ssl.create_default_context().wrap_socket(s,server_hostname={ip!r})\n"
            script += (f"s.sendall(b'GET / HTTP/1.0\\r\\nHost: {ip}\\r\\nConnection: close\\r\\n\\r\\n')\n"
                       "r['status_line']=s.recv(512).split(b'\\r\\n',1)[0].decode('ascii','replace')\n")
        script += "s.close()\nprint(json.dumps(r))\n"
        command = "python3 -c " + shlex.quote(script)
        try:
            response = guest.execute(execution["vm"], command)
        except Exception as exc:
            response = {"return_code": None, "stdout": "", "stderr": "",
                        "transport_error": True, "error_type": type(exc).__name__}
        evidence_path = save(Path(directory) / "raw_evidence" / "independent-probe.json",
             {"command": command, "response": response, "recorded_at": now()})
        try:
            probe = json.loads(response["stdout"])
            passed = (not response.get("transport_error", True)
                      and response["return_code"] == 0 and probe.get("connected") is True
                      and probe["peer"] == [ip, port]
                      and (execution["protocol"] not in {"http", "https"}
                           or probe.get("status_line", "").startswith("HTTP/")))
        except (ValueError, KeyError, TypeError):
            passed = False
        model_completed = (state.get("result") or {}).get("route") == "post"
        review.update(verdict="passed" if passed and model_completed else "unknown",
                      reason="Fresh connection and response corroborate Action handoff" if passed and model_completed
                      else "Independent probe or Action completion not confirmed",
                      evidence=evidence_path.relative_to(directory).as_posix())
    save(Path(directory) / "review" / "independent-review.json", review)
    return review


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["run", "inspect", "resume"])
    parser.add_argument("--graph", type=Path, default=Path("output/Hongri7_v2.action_graph.json"))
    parser.add_argument("--node", default="30")
    parser.add_argument("--lab", type=Path, default=Path("configs/action-lab.local.json"))
    parser.add_argument("--storage", type=Path, default=Path("configs/storage.local.yaml"))
    parser.add_argument("--model", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--thread-id")
    parser.add_argument("--reset-lab", action="store_true")
    parser.add_argument("--observation", type=Path)
    parser.add_argument("--confirm-environment", action="store_true")
    args = parser.parse_args(argv)
    if args.operation != "run" and (not args.thread_id or not args.output_dir):
        parser.error("inspect/resume requires --thread-id and --output-dir")
    if args.operation != "run" and args.reset_lab:
        parser.error("Only a new run can reset the lab")
    thread_id = args.thread_id or str(uuid4())
    stamp = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y%m%dT%H%M%S")
    directory = args.output_dir or Path("output/action") / f"{stamp}-{thread_id[:8]}"
    if args.operation == "run" and directory.exists():
        parser.error("A new run requires a new output directory")
    if args.operation != "run":
        try:
            owner = json.loads((directory / "progress.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            parser.error("inspect/resume requires an existing run progress file")
        if owner.get("thread_id") != thread_id:
            parser.error("Output directory belongs to a different Action thread")
    directory.mkdir(parents=True, exist_ok=True)
    for name in ("model_judgments", "raw_evidence", "review"):
        (directory / name).mkdir(exist_ok=True)
    storage = yaml.safe_load(args.storage.read_text(encoding="utf-8"))
    store = PlannerStore(storage["database_url"])
    store.setup()
    config = load_model_config(args.model)
    lab = json.loads(args.lab.read_text(encoding="utf-8"))
    guest = VMwareGuest(lab["guest_config"])
    service = ActionService(store, model_config=config,
        model_factory=lambda: RecordedModel(create_chat_model(config), directory / "model_judgments"),
        execute_factory=lambda saved: ActionDispatch(guest, saved["context"]["execution"], directory / "raw_evidence"))
    progress = dict(owner) if args.operation != "run" else {"thread_id": thread_id, "started_at": now()}
    progress["status"] = "starting"
    review = None
    save(directory / "progress.json", progress)
    try:
        if args.operation == "run":
            # The lab lock also prevents two CLI runs from interleaving resets or dispatches.
            with store.lock(lock_name(lab)):
                document = json.loads(args.graph.read_text(encoding="utf-8"))
                execution = execution_context(document, args.node, lab, guest)
                created = service.create(document, args.node, thread_id=thread_id, execution=execution,
                                         require_new=True)
                state_path = save(directory / "state.json", created)
                if args.reset_lab:
                    rollback_lab(guest, lab["snapshots"], directory / "raw_evidence")
                save(directory / "progress.json", {**progress, "status": "executing"})
                view = service.resume(thread_id)
                state_path = save(directory / "state.json", view)
                review = independent_review(guest, view["state"], directory)
        elif args.operation == "resume":
            with store.lock("action:vmware-lab"):
                observation = json.loads(args.observation.read_text(encoding="utf-8")) if args.observation else None
                view = service.resume(thread_id, observation=observation, confirm_environment=args.confirm_environment)
                state_path = save(directory / "state.json", view)
                review = independent_review(guest, view["state"], directory)
        else:
            view = service.inspect(thread_id)
            state_path = save(directory / "state.json", view)
        progress.update(status=view["status"], finished_at=now())
        if review is not None:
            progress["review_verdict"] = review["verdict"]
        progress_path = save(directory / "progress.json", progress)
        print(json.dumps({"thread_id": thread_id, "status": view["status"],
                          "run_directory": str(directory.resolve()), "state_file": str(state_path.resolve()),
                          "progress_file": str(progress_path.resolve())}))
        completed = (view["state"].get("result") or {}).get("route") == "post"
        return 0 if args.operation == "inspect" or completed and review["verdict"] == "passed" else 1
    except Exception as exc:
        try:
            save(directory / "state.json", service.inspect(thread_id))
        except KeyError:
            pass
        progress.update(status="interrupted", error_type=type(exc).__name__, finished_at=now())
        save(directory / "progress.json", progress)
        print(json.dumps({"error_type": type(exc).__name__, "run_directory": str(directory.resolve())}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
