"""Single-round Planner -> Pre inspection entry; full execution uses PipelineService."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import TypedDict
from uuid import UUID, uuid4, uuid5

from langgraph.graph import StateGraph, START, END

from src.agents.planner.agent import build_input
from src.agents.planner.schema import PlannerInput
from src.agents.pre_verifier.context import build_context
from .planner_service import engine_version as planner_version, saved_state, update_run
from .pre_service import engine_version as pre_version
from .planner_store import RunConflict, now


class HandoffState(TypedDict):
    planner_context: dict
    pre_contexts: dict
    graph_hash: str
    planner: dict | None
    pre: dict | None
    result: dict | None
    run: dict


def engine_version():
    return sha256(Path(__file__).read_bytes() + planner_version().encode() + pre_version().encode()).hexdigest()


def config_for(run_id):
    return {"configurable": {"thread_id": "planner-pre:" + str(UUID(run_id))},
            "metadata": {"agv_kind": "planner-pre"}}


class PlannerPreService:
    def __init__(self, planner, pre):
        if planner.store.dsn != pre.store.dsn:
            raise ValueError("Planner and Pre must use the same checkpoint store")
        self.planner, self.pre, self.store = planner, pre, planner.store

    def _graph(self, saver, *, confirm_environment=False):
        def plan(state):
            run_id = state["run"]["planner_id"]
            self.planner.create(state["planner_context"], run_id=run_id,
                                workflow_id=state["run"]["id"])
            view = self.planner.resume(run_id, verified_context=state["planner_context"] if confirm_environment else None)
            if view["status"] not in {"awaiting_precheck", "finished", "exhausted"}:
                raise RunConflict("Planner has not completed; inspect its saved task before continuing")
            return {"planner": {"id": run_id, "status": view["status"],
                                 "decision": view["decision"], "error": view["error"]}}

        def check(state):
            node_id = state["planner"]["decision"]["next_node_id"]
            run_id = state["run"]["pre_id"]
            self.pre._create_context(state["pre_contexts"][node_id], run_id=run_id)
            view = self.pre.resume(run_id, confirm_environment=confirm_environment)
            if view["state"].get("result") is None:
                raise RunConflict("Pre has not completed; inspect its saved task before continuing")
            return {"pre": {"id": run_id, "result": view["state"]["result"]}}

        def handoff(state):
            decision = state["planner"].get("decision")
            if state["planner"]["status"] == "exhausted":
                status = "planner_exhausted"
            elif decision["status"] == "finish":
                status = "finished"
            else:
                status = "awaiting_action" if state["pre"]["result"]["route"] == "action" else "awaiting_post"
            return {"result": {"status": status, "node_id": decision["next_node_id"] if decision else None,
                "pre_result": state["pre"]["result"] if state["pre"] else None,
                "action_executed": False, "post_executed": False,
                "previous_results": state["planner_context"]["previous_results"]}}

        graph = StateGraph(HandoffState)
        graph.add_node("plan", plan)
        graph.add_node("check", check)
        graph.add_node("handoff", handoff)
        graph.add_edge(START, "plan")
        graph.add_conditional_edges("plan", lambda s: "check" if s["planner"]["status"] == "awaiting_precheck" else "handoff")
        graph.add_edge("check", "handoff")
        graph.add_edge("handoff", END)
        return graph.compile(checkpointer=saver)

    def create(self, document, *, environment=None, run_id=None):
        run_id = str(UUID(run_id)) if run_id else str(uuid4())
        # This inspection entry stops at the Pre boundary.
        states = {str(n["id"]): {"terminal_record": None} for n in document["nodes"]}
        planner_context = PlannerInput.model_validate(build_input(document, states, [])).model_dump()
        contexts = {n["id"]: build_context(document, n["id"], environment)
                    for n in document["nodes"] if n["id"] not in document["final_goal"]}
        # Store extracted, credential-free contexts rather than the raw account facts.
        inputs = {"planner_context": planner_context, "pre_contexts": contexts,
                  "graph_hash": sha256(json.dumps(document, sort_keys=True, ensure_ascii=False).encode()).hexdigest()}
        with self.store.lock("planner-pre:" + run_id), self.store.checkpointer() as saver:
            graph, config = self._graph(saver), config_for(run_id)
            snapshot = graph.get_state(config)
            if snapshot.values:
                if (any(snapshot.values.get(k) != v for k, v in inputs.items() if k != "planner_context")
                        or snapshot.values["planner_context"]["graph"] != planner_context["graph"]):
                    raise RunConflict("Handoff id exists with different input")
            else:
                graph.update_state(config, {**deepcopy(inputs), "planner": None, "pre": None, "result": None,
                    "run": {"id": run_id, "created_at": now(), "resume_count": 0,
                        "engine_version": engine_version(),
                        "planner_id": str(uuid5(UUID(run_id), "planner")),
                        "pre_id": str(uuid5(UUID(run_id), "pre"))}}, as_node=START)
        return self.inspect(run_id)

    def inspect(self, run_id):
        with self.store.checkpointer() as saver:
            snapshot = self._graph(saver).get_state(config_for(run_id))
            state = saved_state(snapshot)
            if not state:
                raise KeyError(run_id)
            active = self.store.active("planner-pre:" + str(UUID(run_id)))
            status = (state["result"]["status"] if state.get("result") else "running" if active else
                      "created" if state["run"]["resume_count"] == 0 else "interrupted")
            return {"id": state["run"]["id"], "status": status, "active": active,
                    "next_steps": list(snapshot.next), "state": state}

    def resume(self, run_id, *, confirm_environment=False):
        run_id = str(UUID(run_id))
        with self.store.lock("planner-pre:" + run_id), self.store.checkpointer() as saver:
            graph = self._graph(saver, confirm_environment=confirm_environment)
            config = config_for(run_id)
            snapshot = graph.get_state(config)
            state = saved_state(snapshot)
            if not state:
                raise KeyError(run_id)
            if state.get("result") is None:
                run = deepcopy(state["run"])
                if run["resume_count"] and not confirm_environment:
                    raise RunConflict("Interrupted handoff requires saved-environment confirmation")
                if run["engine_version"] != engine_version():
                    raise RunConflict("Runtime changed; create a new handoff task")
                run["resume_count"] += 1
                update_run(graph, config, snapshot, {"run": run})
                config["recursion_limit"] = max(25, 3 * len(state["pre_contexts"]) + 10)
                graph.invoke(None, config, durability="sync")
        return self.inspect(run_id)
