"""Action lifecycle backed only by official checkpoints and PlannerStore locks."""

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

from src.agents._model.client import create_chat_model, load_model_config
from src.agents.executor.agent import PROMPT_PATH
from src.agents.executor.retrieval import (ActionSkillIndex, fact_predicate, predicate_key,
                                           query_text)
from src.agents.executor.schema import ActionObservation
from src.agents.executor.workflow import ActionWorkflow
from src.agents.prompting import load_prompt
from src.orchestration import runner
from .planner_service import saved_state
from .planner_store import RunConflict, now
from .pipeline_service import PipelineFailure


def engine_version():
    folder = Path(__file__).resolve().parents[1] / "agents" / "executor"
    content = Path(__file__).read_bytes() + Path(runner.__file__).read_bytes()
    for path in sorted(folder.glob("*.py")):
        content += path.read_bytes()
    return sha256(content + PROMPT_PATH.read_bytes()).hexdigest()


def config_for(thread_id):
    return {"configurable": {"thread_id": "action:" + str(UUID(thread_id))},
            "recursion_limit": 200, "metadata": {"agv_kind": "action"}}


class ActionService:
    def __init__(self, store, *, execute=None, execute_factory=None, model_config=None,
                 model_factory=None, index=None):
        if execute is not None and execute_factory is not None:
            raise ValueError("Configure execute or execute_factory, not both")
        self.store = store
        self.execute = execute
        self.execute_factory = execute_factory
        self.model_config = model_config or load_model_config()
        self.model_factory = model_factory or (lambda: create_chat_model(self.model_config))
        self.index = index if index is not None else ActionSkillIndex()

    def create(self, document, node_id, *, thread_id=None, execution=None, environment=None,
               require_new=False):
        """Create is durable and idempotent; command dispatch requires resume."""
        thread_id = str(UUID(thread_id)) if thread_id else str(uuid4())
        if execution is not None and not isinstance(execution, dict):
            raise ValueError("Action execution context must be a dictionary")
        config = config_for(thread_id)
        budget = None
        if isinstance(environment, dict) and "max_steps" in environment:
            environment = dict(environment)
            budget = environment.pop("max_steps")
        if budget is None and isinstance(execution, dict):
            budget = execution.get("max_steps")
        # Acquire before context extraction/retrieval so simultaneous creates on
        # one thread are rejected, including the first checkpoint creation.
        with self.store.lock(config["configurable"]["thread_id"]), self.store.checkpointer() as saver:
            workflow = ActionWorkflow(checkpointer=saver)
            state = runner.action_state(
                document, node_id, execution=execution, environment=environment,
                max_steps=int(budget) if budget else None)
            snapshot = workflow.snapshot(config)
            # Derived input is built before the comparison too: a repeated create must
            # see the same frozen context, not a fresh one missing runtime-enriched keys.
            from src.graph.predicates import credential_candidates
            state["context"]["credential_candidates"] = credential_candidates(document)
            if snapshot.values:
                if require_new:
                    raise RunConflict("Action thread already exists; a new run requires a new thread")
                saved_context = saved_state(snapshot)["context"]
                incoming = state["context"]
                if "credential_candidates" not in saved_context:
                    # Older checkpoints predate this derived field; compare what they hold.
                    incoming = {key: value for key, value in incoming.items()
                                if key != "credential_candidates"}
                if saved_context != incoming:
                    raise RunConflict("Action thread exists with different input; create a new task")
            else:
                context = state["context"]
                # Material names the graph already declares. The deployment seeded the
                # encrypted store under these ids; the model only ever sees the names.
                node = context["node"]
                children = context.get("children", [])
                child_predicates = [fact_predicate(fact) for fact in children]
                state["skills"] = self.index.retrieve(
                    query_text(node, children, execution),
                    platform=(execution or {}).get("platform"),
                    predicate=predicate_key(node, children),
                    carrier=(execution or {}).get("carrier"),
                    # The facts this node owes decide which method family can satisfy it.
                    serves=tuple(child_predicates),
                    # One node runs one method. A card is a complete procedure for the
                    # node, so offering a second, differently-shaped recipe only invited
                    # the model to mix them.
                    limit=1)
                # A card declares the deployment materials it needs. Resolve those names
                # against this run's pushed materials before the model ever sees the card:
                # a missing artifact is a deployment error, not a model decision.
                card = state["skills"][0] if state["skills"] else {}
                required = [str(name) for name in (card.get("materials") or [])
                            if str(name).strip()]
                materials = ((state["context"].get("materials")
                              or (environment or {}).get("materials") or {}))
                missing = [name for name in required
                           if not str(materials.get(name) or "").strip()]
                if missing:
                    raise PipelineFailure("参数没给到",
                                          "action_material_missing:" + ",".join(missing))
                state["run"] = {"id": thread_id, "thread_id": thread_id, "created_at": now(),
                    "resume_count": 0, "model": self.model_config.model_dump(),
                    "prompt": load_prompt(PROMPT_PATH), "engine_version": engine_version(),
                    "recoveries": []}
                workflow.initialize(state, config)
        return self.inspect(thread_id)

    def inspect(self, thread_id):
        config = config_for(thread_id)
        with self.store.checkpointer() as saver:
            snapshot = ActionWorkflow(checkpointer=saver).snapshot(config)
            state = saved_state(snapshot)
            if not state:
                raise KeyError(thread_id)
            active = self.store.active(config["configurable"]["thread_id"])
            result = state.get("result")
            status = (result["status"] if result else "running" if active else
                      "created" if not state["run"]["resume_count"] else "interrupted")
            needs_observation = (status == "paused" or
                "execute" in snapshot.next and not state["current"].get("observation"))
            return {"id": state["run"]["id"], "thread_id": state["run"]["thread_id"],
                    "status": status, "active": active,
                    "can_resume": not active and (not result or status == "paused"),
                    "requires_observation": needs_observation,
                    "requires_environment_confirmation": status == "interrupted",
                    "next_steps": list(snapshot.next), "updated_at": snapshot.created_at,
                    "state": state}

    def list(self, limit=50):
        with self.store.checkpointer() as saver:
            ids = []
            for item in saver.list(None, filter={"agv_kind": "action"}):
                key = item.config["configurable"]["thread_id"]
                if not key.startswith("action:"):
                    continue
                thread_id = key.removeprefix("action:")
                if thread_id not in ids:
                    ids.append(thread_id)
                if len(ids) >= limit:
                    break
        return [{k: v for k, v in self.inspect(i).items() if k != "state"} for i in ids]

    def resume(self, thread_id, *, observation=None, confirm_environment=False):
        thread_id = str(UUID(thread_id))
        config = config_for(thread_id)
        verified = ActionObservation.model_validate(observation).model_dump(exclude_none=True) if observation is not None else None
        if verified is not None and not verified["effect_known"]:
            raise ValueError("Reconciliation requires a known effect")
        with self.store.lock(config["configurable"]["thread_id"]), self.store.checkpointer() as saver:
            workflow = ActionWorkflow(checkpointer=saver)
            snapshot = workflow.snapshot(config)
            state = saved_state(snapshot)
            if not state:
                raise KeyError(thread_id)
            result = state.get("result")
            terminal = result and result["status"] != "paused"
            needs_observation = (result and result["status"] == "paused" or
                "execute" in snapshot.next and not state["current"].get("observation"))
            if terminal:
                if verified is not None:
                    raise ValueError("Completed Action cannot accept reconciliation")
            elif needs_observation and verified is None:
                # This path needs neither an execution channel nor a model. The
                # workflow freezes uncertain dispatch instead of replaying it.
                workflow.resume(config)
            else:
                if verified is not None and not needs_observation:
                    raise ValueError("Only an unconfirmed execution can be reconciled")
                run = deepcopy(state["run"])
                if run["resume_count"] and not confirm_environment:
                    raise RunConflict("Interrupted Action requires saved-environment confirmation")
                if run["engine_version"] != engine_version() or run["model"] != self.model_config.model_dump():
                    raise RunConflict("Action runtime or model changed; restore the original version to resume")
                execute = self.execute_factory(deepcopy(state)) if self.execute_factory else self.execute
                if not callable(execute):
                    raise RunConflict("Action executor is not configured; inject execute or execute_factory")
                workflow = runner.build_action_workflow(model=self.model_factory(), execute=execute,
                    checkpointer=saver, structured_method=self.model_config.structured_method,
                    prompt=run["prompt"])
                if run["resume_count"]:
                    run["recoveries"].append({"at": now(), "next_steps": list(snapshot.next),
                                              "reconciled": verified is not None})
                run["resume_count"] += 1
                workflow.update_run(config, run)
                workflow.resume(config, observation=verified)
        return self.inspect(thread_id)
