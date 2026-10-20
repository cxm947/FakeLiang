"""Independent node attempts using the live runtime and its existing stage services."""

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from time import sleep
import json
import traceback
from uuid import UUID, uuid4, uuid5

from run_action import save
from src.agents.pre_verifier.context import build_context as pre_context
from src.orchestration.runner import PostStageRunner, action_state
from src.session.pipeline_service import PipelineFailure
from src.session.execution_session import (ExecutionBinding, SessionRegistration,
                                           SessionRecord, SessionResolutionFailure)
from src.session.session_index import resolve_session
from src.session.tunnel import TunnelEndpoint


class NodeFailure(ValueError):
    def __init__(self, reason, detail=None):
        self.reason = reason
        super().__init__(detail or reason)


def write(path, value):
    return save(path, json.loads(json.dumps(value, ensure_ascii=False, default=str)))


def exception_record(exc):
    record = {"type": type(exc).__name__, "message": str(exc),
              "traceback": traceback.format_exc(), "detail": getattr(exc, "detail", None)}
    if isinstance(exc, PipelineFailure):
        record.update({key: getattr(exc, key)
                       for key in ("stage", "dispatched", "retryable", "hint")})
    return record


def registrations(rows, run_id):
    if not isinstance(rows, list):
        raise ValueError("sessions must be a JSON list")
    for row in rows:
        if not isinstance(row, dict) or "run_id" in row:
            raise ValueError("SessionRegistration inputs must be objects without run_id")
    return [SessionRegistration.model_validate({**row, "run_id": run_id}) for row in rows]


def executable_nodes(request):
    goals = set(request["document"].get("final_goal", []))
    return [node["id"] for node in request["document"]["nodes"] if node["id"] not in goals]


def _endpoints(runtime, run_id, node_id, binding):
    endpoints = [TunnelEndpoint.model_validate(row).model_dump(mode="json")
                 for row in binding.tunnel_endpoints]
    requirements = [row for row in runtime.request.get("tunnels", [])
                    if row["phase"] == "startup" or
                    (row["phase"] == "before" and row["node_id"] == node_id)]
    for requirement in requirements:
        supplied = [row for row in endpoints if
                    (row["target_host"], row["target_port"]) ==
                    (requirement["target_host"], requirement["target_port"])]
        if len(supplied) == 1:
            continue
        if supplied:
            raise NodeFailure("missing_tunnel", "Ambiguous manually supplied tunnel endpoints")
        tunnels = runtime.service.tunnels
        record = tunnels.registry.by_operation(run_id, requirement["operation_id"])
        if record is None or record.status != "active":
            raise NodeFailure("missing_tunnel", requirement["operation_id"])
        if (str(record.target_host), record.target_port) != (
                requirement["target_host"], requirement["target_port"]):
            raise NodeFailure("missing_tunnel", "Existing tunnel does not cover the declared target")
        try:
            if requirement.get("direction", "access") == "return":
                if record.direction != "return" or tunnels.refresh(run_id, record.tunnel_id).status != "active":
                    raise NodeFailure("missing_tunnel", "Return tunnel is not active")
            else:
                endpoint = tunnels.connect(run_id, record.tunnel_id,
                                           requirement["target_host"], requirement["target_port"])
                value = endpoint.model_dump(mode="json")
                if value not in endpoints:
                    endpoints.append(value)
        except Exception as exc:
            raise NodeFailure("missing_tunnel", str(exc)) from exc
    return endpoints


def select_binding(request, records, node_id, bindings):
    if bindings is not None:
        if node_id not in bindings:
            raise NodeFailure("missing_binding", "Explicit bindings file has no entry for " + node_id)
        try:
            binding = ExecutionBinding.model_validate(bindings[node_id])
        except ValueError as exc:
            raise NodeFailure("invalid_binding", str(exc)) from exc
    else:
        entry = request.get("entries", {}).get(node_id)
        if entry is None:
            raise NodeFailure("missing_binding", "No execution entry for " + node_id)
        reference = resolve_session(request["document"], node_id, records,
            controller_rules=request.get("controller_rules") or (),
            entry_actors=request.get("controller_actors") or {})
        if isinstance(reference, SessionResolutionFailure):
            reason = "missing_session" if reference.reason == "session_not_found" else reference.reason
            raise NodeFailure(reason, reference.reason)
        record = next(row for row in records if row.reference() == reference)
        addresses = [address for host in request["document"].get("hosts", [])
                     if host["host"] == record.host for address in host.get("ips", [])]
        if record.observed_address:
            addresses.append(record.observed_address)
        from src.session.binding import execution_binding
        binding = execution_binding(record, entry=entry, addresses=addresses)
    matching = [row for row in records if row.status == "active" and row.reference() == binding.session
                and (row.host, row.privilege, row.binding_kind) ==
                (binding.host, binding.identity, binding.binding_kind)]
    if len(matching) != 1:
        raise NodeFailure("missing_session", "Pinned session is missing, stale or has a different identity")
    expected_via = "kali" if binding.binding_kind == "controller_entry" else "session"
    if binding.via != expected_via:
        raise NodeFailure("invalid_binding", "Execution face differs from registered session kind")
    return binding


def resolve_binding(runtime, run_id, node_id, bindings):
    binding = select_binding(runtime.request, runtime.sessions.list_for_run(run_id), node_id, bindings)
    try:
        runtime.check_session(binding)
    except Exception as exc:
        raise NodeFailure("missing_session", str(exc)) from exc
    endpoints = _endpoints(runtime, run_id, node_id, binding)
    if bindings is not None and endpoints != binding.tunnel_endpoints:
        raise NodeFailure("missing_tunnel", "Frozen binding must include all required access endpoints")
    # Pass the frozen binding through unchanged: optional fields that were not
    # supplied must not appear as nulls in the evidence or in the next stage's input.
    dumped = binding.model_copy(update={"tunnel_endpoints": endpoints}).model_dump(
        mode="json", exclude_none=True)
    # `carrier` is filled by the driver after resolution; keep the frozen binding's shape
    # unchanged when it was not supplied.
    if dumped.get("carrier") is None:
        dumped.pop("carrier", None)
    return dumped


def check_nodes(request, nodes, directory, run_id, sessions, *, bindings=None):
    """Report local context errors without constructing a runtime or performing remote IO."""
    records = [SessionRecord(**row.model_dump(), status="active",
                             registered_at=datetime.now(timezone.utc)) for row in sessions]
    summary = {"run_id": run_id, "mode": "static_check", "nodes": [],
               "limitations": ["No owner/session or tunnel liveness check",
                               "No model calls, skill execution, Post observation or closeout"]}
    for node_id in nodes:
        folder = Path(directory) / node_id
        if folder.resolve().parent != Path(directory).resolve():
            raise ValueError("Node id must name a single evidence directory")
        folder.mkdir(parents=True, exist_ok=False)
        issues, binding = [], None
        binding_record = {"status": "validated", "input": {"document": request["document"],
            "node_id": node_id, "bindings": bindings,
            "sessions": [row.model_dump(mode="json") for row in records]}, "output": None, "exception": None}
        try:
            binding = select_binding(request, records, node_id, bindings).model_dump(mode="json")
            for endpoint in binding["tunnel_endpoints"]:
                TunnelEndpoint.model_validate(endpoint)
            binding_record["output"] = binding
        except Exception as exc:
            reason = getattr(exc, "reason", None) or type(exc).__name__
            binding_record.update(status="failed", exception=exception_record(exc), reason=reason)
            issues.append({"stage": "binding", "reason": reason})
        write(folder / "binding.json", binding_record)
        for stage in ("pre", "action"):
            record = {"status": "validated", "input": {"document": request["document"],
                "node_id": node_id, "environment": request.get("environment", {}),
                "execution": binding}, "output": None, "receipts": [], "exception": None}
            try:
                if stage == "pre":
                    record["output"] = pre_context(request["document"], node_id,
                        request.get("environment"), execution=binding)
                else:
                    record["output"] = action_state(request["document"], node_id,
                        environment=request.get("environment"), execution=binding)["context"]
            except Exception as exc:
                record.update(status="failed", exception=exception_record(exc), reason=type(exc).__name__)
                issues.append({"stage": stage, "reason": type(exc).__name__})
            write(folder / (stage + ".json"), record)
        write(folder / "post.json", {"status": "skipped", "reason": "requires_live_action_output",
            "input": {"document": request["document"], "node_id": node_id},
            "output": None, "receipts": [], "exception": None})
        row = {"node_id": node_id, "status": "failed" if issues else "validated",
               "failure_stage": issues[0]["stage"] if issues else None,
               "reason": issues[0]["reason"] if issues else None, "issues": issues,
               "evidence_directory": str(folder)}
        write(folder / "node.json", row)
        summary["nodes"].append(row)
        write(Path(directory) / "summary.json", summary)
    summary["failed"] = sum(row["status"] == "failed" for row in summary["nodes"])
    summary["validated"] = len(summary["nodes"]) - summary["failed"]
    summary["status"] = "failed" if summary["failed"] else "validated"
    write(Path(directory) / "summary.json", summary)
    return summary


class NodeLiveDriver:
    def __init__(self, runtime, run_id, directory, *, bindings=None):
        self.runtime, self.run_id = runtime, run_id
        self.directory, self.bindings = Path(directory), bindings

    def run_node(self, node_id):
        folder = self.directory / node_id
        if folder.resolve().parent != self.directory.resolve():
            raise ValueError("Node id must name a single evidence directory")
        folder.mkdir(parents=True, exist_ok=False)
        runtime = self.runtime
        runtime.evidence = SimpleNamespace(round_directory=folder)
        document = deepcopy(runtime.request["document"])
        environment = deepcopy(runtime.request.get("environment", {}))
        ids = {stage: str(uuid4()) for stage in ("pre", "action", "post")}
        post_runner = PostStageRunner(runtime.service.post.store, runtime.service.post.post_service,
            session_closeout=runtime.service.post.session_closeout, checkpoint_scope=ids["post"])
        row = {"node_id": node_id, "run_id": self.run_id, "status": "running",
               "failure_stage": None, "reason": None, "evidence_directory": str(folder),
               "stage_ids": ids}
        stages = {stage: {"status": "pending", "input": {"document": document,
                  "node_id": node_id, "environment": environment, "execution": None,
                  "stage_id": ids[stage]}, "output": None, "receipts": [], "exception": None}
                  for stage in ("pre", "action", "post")}
        stages["pre"]["input"]["run_id"] = ids["pre"]
        stages["action"]["input"]["thread_id"] = ids["action"]
        stages["post"]["input"]["checkpoint_scope"] = ids["post"]
        binding_record = {"status": "running", "input": {"node_id": node_id,
            "run_id": self.run_id, "document": document,
            "entries": runtime.request.get("entries", {}),
            "controller_rules": runtime.request.get("controller_rules", []),
            "controller_actors": runtime.request.get("controller_actors", {}),
            "tunnels": runtime.request.get("tunnels", []),
            "bindings": self.bindings, "sessions": []}, "output": None, "exception": None}
        write(folder / "binding.json", binding_record)
        write(folder / "node.json", row)
        for stage, record in stages.items():
            write(folder / (stage + ".json"), record)
        stage = "binding"
        active = binding_record
        try:
            binding_record["input"]["sessions"] = [record.model_dump(mode="json") for record in
                                                    runtime.sessions.list_for_run(self.run_id)]
            write(folder / "binding.json", binding_record)
            # A bind is read-only until it produces the stage binding, so a lost RPC can be
            # retried: one network blip must not fail a node before its first stage runs
            # (live 2026-10-18, node 22 bind: session_backend_rpc_unconfirmed).
            for attempt in range(4):
                try:
                    binding = resolve_binding(runtime, self.run_id, node_id, self.bindings)
                    # What actually carries this node's commands. Action retrieval prefers a
                    # method that names the carrier (a meterpreter-only dump over a generic one).
                    if binding.get("binding_kind") == "controller_entry":
                        carrier = "kali"
                        provider = "kali"
                    else:
                        provider = binding.get("provider") or "msf"
                        if provider == "msf":
                            metadata = runtime.owner.backend.get_session(
                                binding["session"]["session_id"],
                                instance_id=binding["session"].get("instance_id"))
                            carrier = metadata.type
                        else:
                            # ssh/webshell carry commands without an MSF session record.
                            carrier = provider
                    break
                except PipelineFailure as exc:
                    if getattr(exc, "retryable", None) is not True or attempt == 3:
                        raise
                    sleep(5.0)
            # Keep the frozen binding itself untouched (manual bindings pass through
            # unchanged); the carrier travels with the stage input only.
            execution = {**binding, "carrier": carrier, "provider": provider}
            binding_record.update(status="succeeded", output=binding)
            write(folder / "binding.json", binding_record)
            for record in stages.values():
                record["input"]["execution"] = deepcopy(execution)
            for stage in ("pre", "action", "post"):
                active = stages[stage]
                active["status"] = "running"
                if stage == "post":
                    active["input"].update(action_output=stages["action"]["output"],
                        run_id=self.run_id, source_attempt=1,
                        post_output_directory=str(folder / "post-output"))
                write(folder / (stage + ".json"), active)
                if stage == "pre":
                    active["created"] = runtime.service.pre.create(document, node_id,
                        environment=environment, execution=execution, run_id=ids[stage])
                    write(folder / "pre.json", active)
                    active["output"] = runtime.service.pre.resume(ids[stage])
                elif stage == "action":
                    session_record = next(record for record in
                        runtime.sessions.list_for_run(self.run_id)
                        if record.reference().model_dump() == binding["session"])
                    active["delivery"] = {"input": {"node_id": node_id,
                        "session": session_record.model_dump(mode="json")}, "output": None}
                    write(folder / "action.json", active)
                    delivery = runtime.delivery(document, node_id, session_record,
                                                execution=execution) or {}
                    active["delivery"]["output"] = delivery
                    action_environment = {**environment, **delivery}
                    active["input"]["environment"] = deepcopy(action_environment)
                    write(folder / "action.json", active)
                    active["created"] = runtime.service.action.create(document, node_id,
                        environment=action_environment, execution=execution, thread_id=ids[stage])
                    write(folder / "action.json", active)
                    active["output"] = runtime.service.action.resume(ids[stage])
                else:
                    active["output"] = post_runner.accept_action(self.run_id, document,
                        node_id, stages["action"]["output"], environment=environment,
                        source_attempt=1, post_output_directory=folder / "post-output")
                write(folder / (stage + ".json"), active)
                self._validate(stage, node_id, ids, active["output"])
                active["status"] = "succeeded"
                write(folder / (stage + ".json"), active)
            row["status"] = "succeeded"
        except Exception as exc:
            reason = getattr(exc, "reason", None) or getattr(exc, "detail", None) or type(exc).__name__
            active.update(status="failed", reason=reason, exception=exception_record(exc))
            row.update(status="failed", failure_stage=stage, reason=reason)
            if stage != "binding":
                try:
                    active["checkpoint"] = (post_runner.inspect(self.run_id) if stage == "post" else
                                             getattr(runtime.service, stage).inspect(ids[stage]))
                    if stage == "post":
                        current = active["checkpoint"]["state"].get("current", {})
                        post_id = current.get("post_thread_id")
                        active["child_checkpoints"] = {}
                        if post_id:
                            for child in current.get("child_contexts") or {"single": None}:
                                thread_id = str(uuid5(UUID(post_id), child)) if child != "single" else post_id
                                try:
                                    child_view = post_runner.post_service.inspect(thread_id)
                                except Exception as child_exc:
                                    child_view = {"exception": exception_record(child_exc)}
                                active["child_checkpoints"][child] = child_view
                except Exception as inspect_exc:
                    active["checkpoint_exception"] = exception_record(inspect_exc)
            write(folder / (stage + ".json"), active)
        finally:
            binding_record["receipts"] = [json.loads(receipt.read_text(encoding="utf-8"))
                for receipt in sorted((folder / "execution" / "tunnels").glob("*.json"))]
            write(folder / "binding.json", binding_record)
            for name, record in stages.items():
                if record["status"] == "pending":
                    record.update(status="skipped", reason="upstream_failed")
                record["receipts"] = [json.loads(receipt.read_text(encoding="utf-8"))
                    for receipt in sorted((folder / "execution" / name).glob("*.json"))]
                write(folder / (name + ".json"), record)
            write(folder / "node.json", row)
        return row

    @staticmethod
    def _validate(stage, node_id, ids, output):
        if stage == "post":
            view = output.get("post_results", {}).get(node_id + ":" + ids["action"], {})
            verdict = (view.get("state", {}).get("result") or {}).get("result")
            if verdict != "通过":
                raise NodeFailure("post_rejected" if verdict == "不通过" else "post_unconfirmed")
            if view.get("nodeComplete") is False:
                raise NodeFailure("post_passed_session_not_ready")
        else:
            result = output.get("state", {}).get("result") or {}
            if stage == "pre" and result.get("result") not in {"通过", "未知"}:
                # An unconfirmed fact is handed to Action with its unknown facts
                # recorded; only a confirmed negative blocks the node.
                raise NodeFailure("pre_rejected" if result.get("result") == "不通过" else "pre_unconfirmed")
            if stage == "action" and result.get("route") != "post":
                raise NodeFailure((result.get("failure") or {}).get("detail") or "action_unconfirmed")

    def run(self, nodes):
        summary = {"run_id": self.run_id, "status": "running", "nodes": []}
        write(self.directory / "summary.json", summary)
        for node_id in nodes:
            summary["nodes"].append(self.run_node(node_id))
            write(self.directory / "summary.json", summary)
        summary["succeeded"] = sum(row["status"] == "succeeded" for row in summary["nodes"])
        summary["failed"] = len(summary["nodes"]) - summary["succeeded"]
        summary["status"] = "failed" if summary["failed"] else "succeeded"
        write(self.directory / "summary.json", summary)
        return summary
