"""Post lifecycle: persist the Action handoff before any live observation."""

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

from src.agents._model.client import create_chat_model, load_model_config
from src.agents.executor.schema import Observation
from src.agents.post_verifier.context import build_context
from src.agents.post_verifier.retrieval import PostSkillIndex
from src.agents.post_verifier.workflow import build_post, initial_state
from src.orchestration import runner
from .planner_service import saved_state
from .planner_store import RunConflict, now


def engine_version():
    folder = Path(__file__).resolve().parents[1] / "agents" / "post_verifier"
    content = Path(__file__).read_bytes() + Path(runner.__file__).read_bytes()
    for path in sorted(folder.rglob("*")):
        if path.suffix in {".py", ".yaml"}:
            content += path.read_bytes()
    return sha256(content).hexdigest()


def config_for(thread_id):
    return {"configurable": {"thread_id": "post:" + str(UUID(thread_id))},
            "recursion_limit": 200, "metadata": {"agv_kind": "post"}}


class PostService:
    def __init__(self, store, *, gateway=None, gateway_factory=None,
                 model_config=None, model_factory=None, index=None):
        if gateway is not None and gateway_factory is not None:
            raise ValueError("Configure gateway or gateway_factory, not both")
        self.store = store
        self.gateway = gateway
        self.gateway_factory = gateway_factory
        self.model_config = model_config or load_model_config()
        self.model_factory = model_factory or (lambda: create_chat_model(self.model_config))
        self.index = index if index is not None else PostSkillIndex()

    def create(self, document, node_id, *, action_state=None, carrier_inventory=None,
               current_carrier_ref=None, no_carrier_reason=None, proposition=None,
               environment=None, run_id=None, attempt_id=None, thread_id=None,
               require_new=False, post_output_directory=None, evidence_policy=None):
        """Create only checkpoints the frozen handoff; it never dispatches."""
        thread_id = str(UUID(thread_id)) if thread_id else str(uuid4())
        action = deepcopy(action_state) if action_state is not None else None
        if action is not None and isinstance(action.get("state"), dict):
            action = action["state"]
        if carrier_inventory is None and action:
            carrier_inventory = action.get("carrier_inventory")
        if current_carrier_ref is None and action:
            current_carrier_ref = action.get("current_carrier_ref")
        action_run = (action or {}).get("run", {})
        context = build_context(document, node_id, environment,
            action_state=action, carrier_inventory=carrier_inventory,
            current_carrier_ref=current_carrier_ref, no_carrier_reason=no_carrier_reason,
            proposition=proposition, run_id=run_id or action_run.get("workflow_id") or
            action_run.get("id") or thread_id, attempt_id=attempt_id, evidence_policy=evidence_policy)
        return self._create_context(context, thread_id=thread_id, require_new=require_new,
                                    post_output_directory=post_output_directory)

    def _create_context(self, context, *, thread_id=None, require_new=False,
                        post_output_directory=None):
        """Internal runner handoff; graph extraction has already frozen context."""
        thread_id = str(UUID(thread_id)) if thread_id else str(uuid4())
        config = config_for(thread_id)
        with self.store.lock(config["configurable"]["thread_id"]), self.store.checkpointer() as saver:
            workflow = build_post(checkpointer=saver)
            snapshot = workflow.snapshot(config)
            if snapshot.values:
                if require_new:
                    raise RunConflict("Post thread already exists; a new run requires a new thread")
                if saved_state(snapshot)["context"] != context:
                    raise RunConflict("Post thread exists with different input; create a new task")
                if post_output_directory is not None and saved_state(snapshot)["run"].get(
                        "post_output_directory") != str(post_output_directory):
                    raise RunConflict("Post thread exists with a different evidence directory")
            else:
                state = initial_state(context, self.index)
                state["run"] = {"id": thread_id, "thread_id": thread_id,
                    "created_at": now(), "resume_count": 0,
                    "model": self.model_config.model_dump(), "engine_version": engine_version(),
                    "recoveries": [], "post_output_directory": str(post_output_directory)
                    if post_output_directory is not None else None}
                # initialize() is synchronous and completes its official saver
                # write before resume is allowed to resolve or use a carrier.
                workflow.initialize(state, config)
        return self.inspect(thread_id)

    def inspect(self, thread_id):
        config = config_for(thread_id)
        with self.store.checkpointer() as saver:
            snapshot = build_post(checkpointer=saver).snapshot(config)
            state = saved_state(snapshot)
            if not state:
                raise KeyError(thread_id)
            active = self.store.active(config["configurable"]["thread_id"])
            result = state.get("result")
            status = "completed" if result else "running" if active else (
                "created" if not state["run"]["resume_count"] else "interrupted")
            return {"id": state["run"]["id"], "thread_id": state["run"]["thread_id"],
                    "status": status, "active": active, "can_resume": not active and not result,
                    "next_steps": list(snapshot.next), "updated_at": snapshot.created_at,
                    "state": state}

    def list(self, limit=50):
        with self.store.checkpointer() as saver:
            ids = []
            for item in saver.list(None, filter={"agv_kind": "post"}):
                key = item.config["configurable"]["thread_id"]
                if not key.startswith("post:"):
                    continue
                thread_id = key.removeprefix("post:")
                if thread_id not in ids:
                    ids.append(thread_id)
                if len(ids) >= limit:
                    break
        return [{k: v for k, v in self.inspect(i).items() if k != "state"} for i in ids]

    def resume(self, thread_id, *, observation=None):
        config = config_for(thread_id)
        verified = Observation.model_validate(observation).model_dump() if observation is not None else None
        with self.store.lock(config["configurable"]["thread_id"]), self.store.checkpointer() as saver:
            workflow = build_post(checkpointer=saver)
            snapshot = workflow.snapshot(config)
            state = saved_state(snapshot)
            if not state:
                raise KeyError(thread_id)
            if state.get("result"):
                if verified is not None:
                    raise ValueError("Completed Post cannot accept reconciliation")
            else:
                run = deepcopy(state["run"])
                if run["engine_version"] != engine_version() or run["model"] != self.model_config.model_dump():
                    raise RunConflict("Post runtime or model changed; restore the original version to resume")
                live = state["context"]["evidence_policy"]["mode"] == "live_observation"
                pending = set(snapshot.next)
                needs_gateway = live and bool(pending & {"prepare", "generate", "dispatch_intent", "execute"})
                candidate = state["context"].get("carrier_export")
                if candidate and (candidate["carrier"]["kind"] == "unknown" or not candidate.get("reference")):
                    needs_gateway = False
                gateway = ((self.gateway_factory(deepcopy(state)) if self.gateway_factory else self.gateway)
                           if needs_gateway else None)
                needs_model = live and bool(pending - {"finish"})
                workflow = runner.build_post_workflow(model=self.model_factory() if needs_model else None, gateway=gateway,
                    checkpointer=saver, structured_method=self.model_config.structured_method)
                if run["resume_count"]:
                    run["recoveries"].append({"at": now(), "next_steps": list(snapshot.next),
                                              "reconciled": verified is not None})
                run["resume_count"] += 1
                workflow.update_run(config, run)
                workflow.resume(config, observation=verified)
        return self.inspect(thread_id)
