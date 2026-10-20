"""Explicit offline doubles. No commands, sockets, subprocesses or providers.

Only model replies, external owners and registry storage are replaced. The
production stage services, checkpoint graphs, resolver, closeout/migration and
tunnel transition validator execute normally.
"""

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path

from langchain_core.runnables import RunnableLambda

from src.agents._model.client import ModelConfig
from src.agents.planner.schema import PlannerInput
from src.agents.planner.validation import ready_nodes
from src.graph.predicates import parse_parameters
from src.session.action_service import ActionService
from src.session.carrier import CarrierReference
from src.session.execution_session import SessionRecord, SessionRegistration, SessionReference
from src.session.pipeline_service import PipelineService
from src.session.planner_service import PlannerService
from src.session.planner_store import PlannerStore
from src.session.post_service import PostService
from src.session.pre_service import PreService
from src.session.session_closeout import SessionCloseout
from src.session.session_migration import CallbackReceipt, MigrationSettings, PortPool, SessionMigration
from src.session.session_registry import SessionConflict
from src.session.tunnel import CleanupReceipt, TunnelFailure, TunnelRecord
from src.session.tunnel_registry import TunnelRegistry
from src.session.tunnel_service import TunnelService


def _save(path, rows):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


class OfflineSessions:
    """Fixture storage only; deployment still uses SessionRegistry/PostgreSQL."""

    def __init__(self, path):
        self.path = path
        self.rows = {key: SessionRecord.model_validate(raw) for key, raw in
                     (json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}).items()}

    def register(self, request):
        request = SessionRegistration.model_validate(request)
        previous = next((r for r in self.rows.values() if
                         (r.run_id, r.operation_id) == (request.run_id, request.operation_id)), None)
        if previous:
            if any(getattr(previous, k) != v for k, v in request.model_dump().items()):
                raise SessionConflict("Fixture registration changed")
            return previous
        if request.session_id in self.rows or self.find(request.run_id, request.host, request.privilege):
            raise SessionConflict("Fixture session key already registered")
        record = SessionRecord(**request.model_dump(), status="active", registered_at=datetime.now(timezone.utc))
        self.rows[record.session_id] = record
        _save(self.path, {key: row.model_dump(mode="json") for key, row in self.rows.items()})
        return record

    def list_for_run(self, run_id):
        return [r for r in self.rows.values() if r.run_id == run_id]

    def register_exact(self, request, *, supersedes=None):
        record = self.rows.get(request.session_id)
        if record is not None and record.operation_id != request.operation_id:
            if any(getattr(record, key) != getattr(request, key) for key in (
                    "run_id", "session_id", "instance_id", "generation", "host", "privilege", "binding_kind")):
                raise SessionConflict("Fixture exact M differs")
            return record
        if supersedes is not None and supersedes.session_id != request.session_id:
            old = self.rows.get(supersedes.session_id)
            if old is not None and old.status == "active":
                self.rows[supersedes.session_id] = old.model_copy(update={"status": "closed"})
                _save(self.path, {key: row.model_dump(mode="json")
                                  for key, row in self.rows.items()})
        return self.register(request)

    def commit(self):
        pass  # Every fixture registration is already written to its local file.

    def find(self, run_id, host, privilege):
        return next((r for r in self.rows.values() if
            (r.run_id, r.host, r.privilege, r.status) == (run_id, host, privilege, "active")), None)


class OfflineTunnels(TunnelRegistry):
    def __init__(self, path):
        self.path = path
        self.rows = {key: TunnelRecord.model_validate(raw) for key, raw in
            (json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}).items()}

    @contextmanager
    def lock(self, run_id, operation_id):
        from filelock import FileLock
        with FileLock(str(self.path) + ".lock"):
            yield

    def _one(self, sql, values):
        if sql.startswith("INSERT"):
            values = dict(values)
            values["session"] = values["session"].obj
            row = TunnelRecord.model_validate(values)
        elif "UPDATE" in sql:
            status, started, proof, run_id, tunnel_id, expected = values
            old = self.get(run_id, tunnel_id)
            if old.status != expected:
                return None
            row = old.model_copy(update={"status": status, "started": started,
                "cleanup_receipt": CleanupReceipt.model_validate(proof.obj) if proof else None,
                "updated_at": datetime.now(timezone.utc)})
        else:
            run_id, value = values
            return next((r for r in self.rows.values() if r.run_id == run_id and
                (r.operation_id if "operation_id =" in sql else r.tunnel_id) == value), None)
        self.rows[row.tunnel_id] = row
        _save(self.path, {key: row.model_dump(mode="json") for key, row in self.rows.items()})
        return row


class OfflineModel:
    def __init__(self, stage, runtime):
        self.stage, self.runtime = stage, runtime

    def with_structured_output(self, schema, **options):
        def invoke(messages):
            payload = json.loads(next(m["content"] if isinstance(m, dict) else m.content for m in messages
                if (m.get("role") in {"human", "user"} if isinstance(m, dict) else m.type == "human")))
            self.runtime.events.append({"stage": self.stage + "_model", "input": payload})
            fields = schema["properties"]
            if "next_node_id" in fields:
                ready = sorted(ready_nodes(PlannerInput.model_validate(payload)))
                output = {"why": "offline fixture", "status": "continue" if ready else "finish",
                          "next_node_id": ready[0] if ready else None}
            elif "tool" in fields:
                execution = payload.get("execution", payload.get("context", {}).get("execution", {}))
                # A real interpreter name: the typed tool contract validates it before
                # dispatch, and a placeholder would be recorded as an interrupted command.
                command = "offline fixture " + str(payload.get("current", {}).get("nonce", ""))
                if {"target", "arguments"} <= set(fields):
                    output = {"tool": "run_command",
                              "target": ("session" if execution.get("via") == "session" else "kali"),
                              "arguments": {"interpreter": "sh", "command": command}}
                else:
                    output = {"tool": "cmd", "name": "sh",
                              "via": execution.get("via", "kali"), "content": command}
            elif "action_complete" in fields:
                output = {"result": "passed", "action_complete": True, "reason": "offline fixture"}
            elif "fact_id" in fields:
                node = payload["node"]["id"]
                output = {"fact_id": payload["leaf"]["id"],
                          "result": self.runtime.pre_results.get(node, "通过"), "reason": "offline fixture"}
            else:
                node = payload["context"]["node"]["id"]
                output = {"node_id": node, "result": self.runtime.post_results.get(node, "通过"),
                          "reason": "offline fixture nonce observation"}
            return {"parsed": output, "raw": None, "parsing_error": None}
        return RunnableLambda(invoke)


class OfflinePre:
    definitions = [{"name": "fixture", "inputSchema": {"type": "object"}}]

    def __init__(self, state, runtime):
        self.state, self.runtime = state, runtime

    def __enter__(self):
        self.runtime.events.append({"stage": "pre_bind", "execution": self.state["context"]["execution"]})
        return self

    def __exit__(self, *args):
        pass

    def execute(self, request):
        self.runtime.events.append({"stage": "pre_execute", "request": request})
        return {"is_error": False, "response": {"stdout": "offline prerequisite evidence"}}


class OfflinePost:
    def __init__(self, runtime):
        self.runtime = runtime

    def observe(self, request, context, *, operation_id, nonce):
        self.runtime.events.append({"stage": "post_observe", "context": context})
        from src.tools.receipt import make_receipt
        return make_receipt(confirmed=True, succeeded=True, response={
            "stdout": "AGV_POST_NONCE=" + nonce,
            "operation_id": operation_id, "target_host": context["target_host"],
            "nonce_observed": nonce, "carrier_ref": context["current_carrier_ref"]})

    def lookup_observation(self, operation_id):
        return None


class OfflineMigration:
    def __init__(self, runtime):
        self.runtime = runtime

    @contextmanager
    def reserve_receiver(self, payload):
        self.payload = payload
        self.runtime.events.append({"stage": "migration_reserve"})
        try:
            yield self
        finally:
            self.runtime.events.append({"stage": "migration_release"})

    def start(self):
        self.runtime.events.append({"stage": "migration_start"})

    def wait_ready(self, timeout):
        return True

    def deliver(self, entry, payload, *, timeout):
        self.runtime.events.append({"stage": "migration_deliver", "kind": entry.kind})

    def wait_callback(self, timeout):
        payload = self.payload
        return CallbackReceipt(**{key: getattr(payload, key) for key in
            ("run_id", "operation_id", "host", "privilege")},
            reference=SessionReference(session_id="migrated:" + payload.operation_id,
                instance_id="offline-owner", generation=1))


class OfflineTunnelOwner:
    def __init__(self, runtime):
        self.runtime = runtime

    def install(self, record):
        self.runtime.events.append({"stage": "tunnel_build", "tunnel_id": record.tunnel_id})

    def is_alive(self, record):
        self.runtime.events.append({"stage": "tunnel_connect", "tunnel_id": record.tunnel_id})
        return True


class OfflineRuntime:
    def __init__(self, directory, *, channel_kinds=None):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.events, self.pre_results, self.post_results = [], {}, {}
        self.channel_kinds = channel_kinds or {}
        self.sessions = OfflineSessions(directory / "offline-sessions.json")
        store = PlannerStore("sqlite:///" + str(directory / "pipeline.db"))
        store.setup()
        config = ModelConfig(model="offline")
        def options(stage):
            return {"model_config": config, "model_factory": lambda: OfflineModel(stage, self)}
        planner = PlannerService(store, **options("planner"))
        pre = PreService(store, gateway_factory=lambda state: OfflinePre(state, self), **options("pre"))
        action = ActionService(store, execute_factory=self.action_executor, **options("action"))
        post = PostService(store, gateway=OfflinePost(self), **options("post"))
        ports = PortPool(directory / "ports", 42000, 42999)
        closeout = SessionCloseout(store, self.sessions, migration=SessionMigration(OfflineMigration(self), ports,
            MigrationSettings(callback_host="192.0.2.10", payload_ref="offline-artifact")),
            verify_destination=lambda request, reference: {"reference": reference.model_dump(),
                "provider": "console", "host": request.host, "privilege": request.privilege,
                "alive": True, "managed": True})
        tunnels = TunnelService(OfflineTunnels(directory / "offline-tunnels.json"), self.sessions,
                                ports, OfflineTunnelOwner(self))
        self.service = PipelineService(planner, pre, action, post, closeout, tunnels)

    def seed(self, run_id, host="origin", privilege="root"):
        return self.sessions.register(SessionRegistration(run_id=run_id, operation_id="seed",
            session_id="seed:" + run_id, instance_id="offline-owner", generation=1,
            host=host, privilege=privilege, source_node_id="seed", source_attempt=1))

    def action_executor(self, state):
        def execute(request):
            self.events.append({"stage": "action_execute", "execution": state["context"]["execution"]})
            observation = {"effect_known": True, "receipt_confirmed": True,
                           "command_succeeded": True,
                           "response": {"stdout": "offline action evidence"}}
            facts = [child for child in state["context"]["children"]
                     if child["description"].startswith("execCode(")]
            if facts:
                parameters = parse_parameters(facts[0]["description"])
                node, attempt = state["context"]["node"]["id"], state["run"]["id"]
                carrier = CarrierReference(ref="carrier:" + attempt, kind="ssh", owner="offline-owner",
                    handle="handle:" + attempt, target_host=parameters["host"], source_node_id=node,
                    source_attempt_id=attempt, generation="1", lifecycle="available")
                kind = self.channel_kinds.get(node, "unified")
                if kind == "unified":
                    carrier = carrier.model_copy(update={"owner": "console", "kind": "msf"})
                channel = ({"kind": kind, "reference": {"session_id": "session:" + attempt,
                    "instance_id": "offline-owner", "generation": 1}} if kind == "unified" else
                    {"kind": kind, "owner": "offline-owner", "handle": carrier.handle})
                observation["exported_carrier"] = {"carrier": carrier.model_dump(),
                    "privilege": parameters["user"], "channel": channel,
                    "reference": {"session_id": "session:" + attempt,
                                  "instance_id": "offline-owner", "generation": 1}}
            return observation
        return execute


def demo_request():
    nodes, edges = [], []
    parent = {"id": "seed-fact", "type": "OR", "description": "execCode(origin,root)", "host": "origin"}
    for i, host in enumerate(("pivot", "target", "last", "last")):
        node_id = chr(ord("a") + i)
        child = {"id": "fact:" + node_id, "type": "OR", "host": host,
                 "description": f"execCode({host},root)" if i < 3 else f"disableFirewall({host})"}
        source = parent["host"]
        leaf = {"id": "leaf:" + node_id, "type": "LEAF", "description": f"hacl({source},{host},tcp,80)",
                "source_host": source, "target_host": host, "protocol": "tcp", "port": "80"}
        nodes.append({"id": node_id, "type": "AND", "description": "offline action " + node_id,
            "rule_desc": "offline fixture", "host": host,
            "dependencies": {"parents": [deepcopy(parent), leaf], "children": [child]}})
        if i:
            edges.append({"src": chr(ord("a") + i - 1), "dst": node_id})
        parent = child
    return {"document": {"nodes": nodes, "edges": edges, "final_goal": [],
                "hosts": [{"host": h, "ips": [f"192.0.2.{10+i}"]}
                          for i, h in enumerate(("origin", "pivot", "target", "last"))]},
        "entries": {n["id"]: {"via": "session", "platform": "linux"} for n in nodes},
        "tunnels": [{"phase": "after", "node_id": "a", "mode": "build", "operation_id": "demo-tunnel",
            "direction": "access", "pivot_host": "pivot", "privilege": "root", "listen_host": "127.0.0.1",
            "target_host": "192.0.2.12", "target_port": 80},
            {"phase": "before", "node_id": "b", "mode": "connect", "operation_id": "demo-tunnel",
             "target_host": "192.0.2.12", "target_port": 80}]}
