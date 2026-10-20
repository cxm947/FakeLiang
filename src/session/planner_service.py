"""Manual Planner recovery using LangGraph state as the only source of truth."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from uuid import UUID, uuid4, uuid5

from langgraph.graph import START

from src.agents._model.client import create_chat_model, load_model_config
from src.agents.planner.agent import build_planner, PROMPT_PATH
from src.agents.planner.schema import PlannerInput
from src.agents.prompting import load_prompt
from .planner_store import RunConflict, now


def engine_version():
    folder = PROMPT_PATH.parent.parent
    content = b"planner-official-recovery-v2"
    for filename in ("agent.py", "schema.py", "validation.py"):
        content += (folder / filename).read_bytes()
    content += Path(__file__).read_bytes()
    return sha256(content).hexdigest()


def config_for(run_id):
    return {"configurable": {"thread_id": run_id}, "recursion_limit": 20,
            "metadata": {"agv_kind": "planner"}}


def completed(state):
    # Empty snapshot.next can also mean a task result exists only in pending
    # writes. It is not by itself proof that validation reached END.
    return state["decision"] is not None or (len(state["attempts"]) >= 3 and state["error"] is not None)


def saved_state(snapshot):
    state = dict(snapshot.values)
    for task in snapshot.tasks:
        if isinstance(task.result, dict):
            state.update(task.result)
    return state


def update_run(graph, config, snapshot, changes):
    # Our graph is sequential. Finish the already-written node's transition
    # when its output survived but its full checkpoint did not.
    written = [task for task in snapshot.tasks if isinstance(task.result, dict)]
    values = {**(written[0].result if written else {}), **changes}
    return graph.update_state(config, values, as_node=written[0].name if written else None)


class PlannerService:
    def __init__(self, store, *, model_config=None, model_factory=None):
        self.store = store
        self.model_config = model_config or load_model_config()
        self.model_factory = model_factory or (lambda: create_chat_model(self.model_config))

    def _graph(self, saver, *, execute=False, document=None):
        return build_planner(self.model_factory() if execute else None, checkpointer=saver,
            structured_method=self.model_config.structured_method, document=document)

    def create(self, context, *, run_id=None, workflow_id=None, parent_run_id=None):
        run_id = str(UUID(run_id)) if run_id else str(uuid4())
        workflow_id = str(UUID(workflow_id)) if workflow_id else run_id
        context = PlannerInput.model_validate(context).model_dump()
        with self.store.lock(run_id), self.store.checkpointer() as saver:
            graph = self._graph(saver)
            config = config_for(run_id)
            snapshot = graph.get_state(config)
            if snapshot.values:
                previous = snapshot.values
                if (previous["context"] != context or previous["run"]["workflow_id"] != workflow_id
                        or previous["run"].get("parent_run_id") != parent_run_id):
                    raise RunConflict("Run id already exists with different input")
            else:
                graph.update_state(config, {
                    "context": context, "attempts": [], "response": None,
                    "error": None, "decision": None, "request_messages": [], "calls": [],
                    "run": {"id": run_id, "workflow_id": workflow_id, "parent_run_id": parent_run_id,
                        "model": self.model_config.model_dump(), "prompt": load_prompt(PROMPT_PATH),
                        "engine_version": engine_version(), "created_at": now(),
                        "resume_count": 0, "superseded_by": None}}, as_node=START)
        return self.inspect(run_id)

    def inspect(self, run_id):
        run_id = str(UUID(run_id))
        with self.store.checkpointer() as saver:
            snapshot = self._graph(saver).get_state(config_for(run_id))
            return self._view(snapshot, active=self.store.active(run_id))

    def list(self, limit=50):
        keys = ("id", "workflow_id", "status", "created_at", "updated_at", "active", "can_resume")
        return [{key: detail[key] for key in keys}
                for run_id in self.store.list_ids(limit) for detail in [self.inspect(run_id)]]

    def resume(self, run_id, *, verified_context=None):
        """A changed context starts a new decision and preserves old history.

        verified_context is an external check result, not a claim this Planner
        verified live connections or other environmental prerequisites.
        """
        run_id = str(UUID(run_id))
        verified = (PlannerInput.model_validate(verified_context).model_dump()
                    if verified_context is not None else None)
        with self.store.lock(run_id), self.store.checkpointer() as saver:
            config = config_for(run_id)
            graph = self._graph(saver)
            snapshot = graph.get_state(config)
            if not snapshot.values:
                raise KeyError(run_id)
            state = saved_state(snapshot)
            run = deepcopy(state["run"])
            if run["superseded_by"]:
                return self._view(snapshot)
            if verified is not None and verified != state["context"]:
                # Stable child id: retrying after a failed parent write is idempotent.
                digest = sha256(json.dumps(verified, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
                replacement = self.create(verified, run_id=str(uuid5(UUID(run_id), digest)),
                    workflow_id=run["workflow_id"], parent_run_id=run_id)
                run["superseded_by"] = replacement["id"]
                update_run(graph, config, snapshot, {"run": run})
                return self._view(graph.get_state(config))
            if completed(state):
                return self._view(snapshot)
            if run["resume_count"] and verified is None:
                view = self._view(snapshot)
                view["status"] = "awaiting_context_confirmation"
                return view
            if run["engine_version"] != engine_version() or run["model"] != self.model_config.model_dump():
                raise RunConflict("Runtime or model configuration changed; restore the original version to resume")
            run["resume_count"] += 1
            changes = {"run": run}
            # Without a saved reply the previous request MAY have reached the
            # provider. A manual retry may incur a second charge.
            if snapshot.next == ("call_model",):
                calls = deepcopy(state["calls"])
                calls[-1]["status"] = "unconfirmed"
                calls.append({"attempt": len(state["attempts"]) + 1,
                    "request_messages": state["request_messages"], "prepared_at": now(),
                    "status": "prepared", "response": None})
                changes["calls"] = calls
            update_run(graph, config, snapshot, changes)
            graph = self._graph(saver, execute=True, document=run["prompt"])
            # Prepare is saved before model invocation; a saved reply resumes
            # at validation. A checkpoint failure must stop further work.
            graph.invoke(None, config=config, durability="sync")
            return self._view(graph.get_state(config))

    @staticmethod
    def _view(snapshot, *, active=False):
        state = saved_state(snapshot)
        if not state or "run" not in state:
            raise KeyError("Task not found")
        run = deepcopy(state["run"])
        if run["superseded_by"]:
            status = "superseded"
        elif completed(state):
            status = ("exhausted" if state["error"] else
                      "finished" if state["decision"]["status"] == "finish" else "awaiting_precheck")
        else:
            status = "created" if not run["resume_count"] else "running" if active else "interrupted"
        view = {**run, "status": status, "updated_at": snapshot.created_at,
            "context": state["context"], "decision": state["decision"], "error": state["error"],
            "active": active, "can_resume": not active and status in {"created", "interrupted"},
            "requires_context_confirmation": status == "interrupted",
            "next_steps": list(snapshot.next), "handoff": None}
        if status == "awaiting_precheck":
            view["handoff"] = {"node_id": state["decision"]["next_node_id"],
                               "requires_precheck": True, "execution_started": False}
        for number in range(1, 4):
            calls = deepcopy([c for c in state.get("calls", []) if c["attempt"] == number])
            for call in calls:
                if call["status"] == "prepared" and not active:
                    call["status"] = "unconfirmed"
            record = next((a for a in state["attempts"] if a["attempt"] == number), None)
            view[f"attempt_{number}"] = ({"calls": calls, "validation": record} if calls or record else None)
        view["runtime_errors"] = [str(t.error) for t in snapshot.tasks if t.error]
        return view
