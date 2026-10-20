"""Manual Pre tasks stored exclusively in official LangGraph checkpoints."""

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

from langgraph.graph import START

from src.agents._model.client import create_chat_model, load_model_config
from src.agents.pre_verifier.context import build_context
from src.agents.pre_verifier.retrieval import PreSkillIndex
from src.agents.pre_verifier.workflow import build_pre, initial_state
from .planner_service import saved_state, update_run
from .planner_store import RunConflict, now


def engine_version():
    folder = Path(__file__).resolve().parents[1] / "agents" / "pre_verifier"
    content = Path(__file__).read_bytes()
    for path in sorted(folder.glob("*.py")):
        content += path.read_bytes()
    return sha256(content).hexdigest()


def config_for(run_id):
    return {"configurable": {"thread_id": "pre:" + str(UUID(run_id))},
            "recursion_limit": 1000, "metadata": {"agv_kind": "pre"}}


class PreService:
    def __init__(self, store, *, gateway_factory, model_config=None, model_factory=None, index=None):
        self.store = store
        self.gateway_factory = gateway_factory
        self.model_config = model_config or load_model_config()
        self.model_factory = model_factory or (lambda: create_chat_model(self.model_config))
        self.index = index if index is not None else PreSkillIndex()

    def create(self, graph_document, node_id, *, environment=None, run_id=None, execution=None):
        context = build_context(graph_document, node_id, environment, execution=execution)
        return self._create_context(context, run_id=run_id)

    def _create_context(self, context, *, run_id=None):
        """Internal handoff: context was extracted and frozen from the input graph."""
        run_id = str(UUID(run_id)) if run_id else str(uuid4())
        with self.store.lock("pre:" + run_id), self.store.checkpointer() as saver:
            graph = build_pre(checkpointer=saver)
            config = config_for(run_id)
            snapshot = graph.get_state(config)
            if snapshot.values:
                if snapshot.values["context"] != context:
                    raise RunConflict("Pre id exists with different input; create a new task")
            else:
                state = initial_state(context, self.index, [])
                state["run"] = {"id": run_id, "created_at": now(), "resume_count": 0,
                                "model": self.model_config.model_dump(), "engine_version": engine_version(),
                                "recoveries": []}
                graph.update_state(config, state, as_node=START)
        return self.inspect(run_id)

    def inspect(self, run_id):
        with self.store.checkpointer() as saver:
            snapshot = build_pre(checkpointer=saver).get_state(config_for(run_id))
            state = saved_state(snapshot)
            if not state:
                raise KeyError(run_id)
            active = self.store.active("pre:" + str(UUID(run_id)))
            status = ("awaiting_action" if state.get("result", {}).get("route") == "action" else "blocked") if state.get("result") else (
                "created" if state["run"]["resume_count"] == 0 else "running" if active else "interrupted")
            return {"id": state["run"]["id"], "status": status, "active": active,
                    "can_resume": not active and state.get("result") is None,
                    "next_steps": list(snapshot.next), "state": state}

    def list(self, limit=50):
        with self.store.checkpointer() as saver:
            ids = []
            for item in saver.list(None, filter={"agv_kind": "pre"}):
                run_id = item.config["configurable"]["thread_id"].removeprefix("pre:")
                if run_id not in ids:
                    ids.append(run_id)
                if len(ids) >= limit:
                    break
        return [{k: v for k, v in self.inspect(i).items() if k != "state"} for i in ids]

    def resume(self, run_id, *, confirm_environment=False):
        run_id = str(UUID(run_id))
        with self.store.lock("pre:" + run_id), self.store.checkpointer() as saver:
            config = config_for(run_id)
            graph = build_pre(checkpointer=saver)
            snapshot = graph.get_state(config)
            state = saved_state(snapshot)
            if not state:
                raise KeyError(run_id)
            if state.get("result") is None:
                run = deepcopy(state["run"])
                if run["resume_count"] and not confirm_environment:
                    raise RunConflict("Interrupted Pre requires confirmation that the saved environment is still valid; otherwise create a new task")
                if run["engine_version"] != engine_version() or run["model"] != self.model_config.model_dump():
                    raise RunConflict("Pre runtime or model changed; create a new task or restore the original version")
                # Discover before execution. An unavailable gateway is a run-level error,
                # not a set of fabricated UNKNOWN checks that silently lets Action run.
                with self.gateway_factory(deepcopy(state)) as gateway:
                    if state["tools"] and state["tools"] != gateway.definitions:
                        raise RunConflict("MCP definitions changed; create a new task")
                    if run["resume_count"]:
                        run["recoveries"].append({"at": now(), "next_steps": list(snapshot.next),
                            "external_call_unconfirmed": any(n in {"generate", "execute", "assess"} for n in snapshot.next)})
                    run["resume_count"] += 1
                    update_run(graph, config, snapshot, {"run": run, "tools": gateway.definitions})
                    graph = build_pre(self.model_factory(), gateway, checkpointer=saver,
                                      structured_method=self.model_config.structured_method)
                    graph.invoke(None, config=config, durability="sync")
        return self.inspect(run_id)
