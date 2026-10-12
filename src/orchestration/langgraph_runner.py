"""Serial outer scheduling with private, synchronous recovery state."""
from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Callable, TypedDict

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph

from runtime.credential_source import validate_materials_dir
from runtime.lean import mask_secrets
from runtime.locking import AlreadyRunning, acquire_orchestrator
from .contracts import WalkResult


class WalkGraphState(TypedDict):
    walk: dict
    selected_node_id: str
    route: str
    attempts: dict
    exhausted_nodes: list[str]
    cell: str
    stop_reason: str
    active_step: dict
    model_calls: list[dict]
    planner_pending: dict
    run_binding: str


def checkpoint_identity(*, root, repository, materials_dir=None):
    run_root = Path(root).resolve()
    run_key = os.path.normcase(str(run_root))
    repository = Path(repository).resolve()
    private_root = materials_dir or (
        repository.parent / (repository.name + "-private")
    )
    private_root = validate_materials_dir(
        private_root, run_dirs=(run_root,), repository=repository
    )
    path = private_root / "checkpoints" / (
        sha256(run_key.encode("utf-8")).hexdigest() + ".sqlite3"
    )
    return path, run_key


def read_progress(saver, thread_id, checkpoint_id):
    """A single overwrite row is graph progress, never another action journal."""
    with saver.cursor() as cursor:
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS runtime_progress "
            "(thread_id TEXT PRIMARY KEY, checkpoint_id TEXT, state TEXT NOT NULL)"
        )
        row = cursor.execute(
            "SELECT checkpoint_id, state FROM runtime_progress WHERE thread_id = ?",
            (thread_id,),
        ).fetchone()
    if row is None or row[0] != checkpoint_id:
        return None
    value = json.loads(row[1])
    if not isinstance(value, dict):
        raise ValueError("WALK_PROGRESS_INVALID")
    return value


def run_walk_graph(
    *, root, repository, materials_dir, max_nodes, walk: WalkResult,
    secrets, planner: Callable[[dict], bool], step: Callable[[dict], None],
    stop_reason: Callable[[dict], str],
    selected_node: Callable[[], str],
    resume=False, attach_save=None, restore_walk=None, run_binding="",
) -> WalkResult:
    class MaskedSerializer(JsonPlusSerializer):
        def dumps_typed(self, value):
            if isinstance(value, BaseException):
                value = repr(value)
            return super().dumps_typed(mask_secrets(value, secrets))

    path, thread_id = checkpoint_identity(
        root=root, repository=repository, materials_dir=materials_dir
    )
    config = {
        "configurable": {"thread_id": thread_id},
        "recursion_limit": 2 * max(0, max_nodes) + 3,
    }
    reentry = {}

    def snapshot(route, state=None):
        state = state if state is not None else {}
        value = mask_secrets({
            "walk": asdict(walk),
            "selected_node_id": selected_node(),
            "route": route,
            "attempts": state.get("attempts", {}),
            "exhausted_nodes": state.get("exhausted_nodes", []),
            "cell": state.get("cell", ""),
            "stop_reason": state.get("stop_reason", ""),
            "active_step": state.get("active_step", {}),
            "model_calls": state.get("model_calls", []),
            "planner_pending": state.get("planner_pending", {}),
            "run_binding": run_binding,
        }, secrets)
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))

    def restored(state):
        if reentry:
            state.update(reentry)
            reentry.clear()
        return state

    def planner_node(state):
        state = restored(state)
        route = "step" if planner(state) else "done"
        return snapshot(route, state)

    def step_node(state):
        state = restored(state)
        step(state)
        return snapshot("planner" if len(walk.order) < max_nodes else "done", state)

    def done_node(state):
        state = restored(state)
        state["stop_reason"] = stop_reason(state)
        print("[walk] stop_reason=" + state["stop_reason"], flush=True)
        return snapshot("done", state)

    def next_node(state):
        return state["route"]

    builder = StateGraph(WalkGraphState)
    builder.add_node("planner", planner_node)
    builder.add_node("step", step_node)
    builder.add_node("done", done_node)
    builder.add_conditional_edges(
        START, next_node, {"planner": "planner", "done": "done"}
    )
    builder.add_conditional_edges(
        "planner", next_node, {"step": "step", "done": "done"}
    )
    builder.add_conditional_edges(
        "step", next_node, {"planner": "planner", "done": "done"}
    )
    builder.add_edge("done", END)

    guard = acquire_orchestrator(root)
    if isinstance(guard, AlreadyRunning):
        raise RuntimeError("WALK_ALREADY_RUNNING")
    with guard:
        if resume and not path.is_file():
            raise ValueError("WALK_CHECKPOINT_MISSING")
        path.parent.mkdir(parents=True, exist_ok=True)
        with SqliteSaver.from_conn_string(str(path)) as saver:
            saver.serde = MaskedSerializer(pickle_fallback=False)
            graph = builder.compile(checkpointer=saver)
            saved = saver.get_tuple(config)
            if saved is not None and not resume:
                raise ValueError("WALK_CHECKPOINT_EXISTS: use --resume or a new run root")
            if saved is None and resume:
                raise ValueError("WALK_CHECKPOINT_MISSING")
            if saved is not None:
                state = graph.get_state(config)
                if not state.next and state.values.get("route") == "done" and state.values.get("stop_reason"):
                    raise ValueError("WALK_ALREADY_FINISHED")
                recovered = dict(state.values)
                if saved.metadata.get("source") == "input" and "walk" not in recovered:
                    initial = saved.checkpoint["channel_values"].get(START)
                    if isinstance(initial, dict):
                        recovered = dict(initial, **recovered)
                progress = read_progress(saver, thread_id, saved.checkpoint["id"])
                completed = any(
                    channel in {"walk", "route"}
                    for _task, channel, _value in (saved.pending_writes or ())
                )
                if progress is not None and not completed:
                    recovered.update(progress)
                if recovered.get("run_binding", "") != run_binding:
                    raise ValueError("WALK_RESUME_BINDING_CHANGED")
                if restore_walk is None:
                    values = recovered.get("walk", {})
                    for name in WalkResult.__dataclass_fields__:
                        if name in values:
                            setattr(walk, name, values[name])
                else:
                    restore_walk(recovered)
                reentry.update(recovered)

            def save_state(state):
                current = saver.get_tuple(config)
                anchor = current.checkpoint["id"] if current is not None else None
                value = snapshot(state.get("route", "planner"), state)
                with saver.cursor() as cursor:
                    cursor.execute(
                        "CREATE TABLE IF NOT EXISTS runtime_progress "
                        "(thread_id TEXT PRIMARY KEY, checkpoint_id TEXT, "
                        "state TEXT NOT NULL)"
                    )
                    cursor.execute(
                        "INSERT OR REPLACE INTO runtime_progress VALUES (?, ?, ?)",
                        (thread_id, anchor, json.dumps(
                            value, ensure_ascii=False, allow_nan=False)),
                    )

            if attach_save is not None:
                attach_save(save_state)
            graph.invoke(
                None if saved is not None else snapshot(
                    "planner" if len(walk.order) < max_nodes else "done"),
                config=config, durability="sync",
            )
    return walk
