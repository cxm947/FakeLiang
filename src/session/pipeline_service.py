"""One durable Planner -> Pre -> Action -> Post -> closeout -> Planner loop.

All IO owners are injected. This module never creates a VM, socket or model.
Failures stop the run; no cross-stage fallback or automatic replay is allowed.
"""

from copy import deepcopy
from typing import Annotated, Literal, TypedDict
from uuid import UUID, uuid4, uuid5

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.agents.planner.agent import build_input
from src.agents.planner.schema import PlannerInput
from src.orchestration.runner import PostStageRunner
from .execution_session import SessionResolutionFailure
from .planner_service import saved_state
from .session_index import resolve_session
from .session_migration import CloseoutFailure
from .tunnel import Port, TunnelRequest


class EntryOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    #: The frozen entry for one graph node: the kali entry, or the node's own session.
    via: Literal["kali", "session"]
    platform: Literal["linux", "windows"]


class TunnelSchedule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    phase: Literal["startup", "before", "after"]
    node_id: str | None = None
    operation_id: str = Field(min_length=1)

    @model_validator(mode="after")
    def schedule(self):
        if (self.phase == "startup") != (self.node_id is None):
            raise ValueError("startup has no node; before/after requires node_id")
        return self


class BuildTunnel(TunnelSchedule):
    mode: Literal["build"]
    direction: Literal["access", "return"]
    pivot_host: str = Field(min_length=1)
    privilege: str = Field(min_length=1)
    listen_host: str = Field(min_length=1)
    target_host: str = Field(min_length=1)
    target_port: Port


class ConnectTunnel(TunnelSchedule):
    mode: Literal["connect"]
    target_host: str = Field(min_length=1)
    target_port: Port


class PipelineInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document: dict
    entries: dict[str, EntryOptions]
    #: Graph actor -> run's controller entry session_id, and the rules allowed to
    #: originate from the control end. Both are declarations, never inferences.
    controller_actors: dict[str, str] = Field(default_factory=dict)
    controller_rules: list[str] = Field(default_factory=list)
    environment: dict = Field(default_factory=dict)
    tunnels: list[Annotated[BuildTunnel | ConnectTunnel, Field(discriminator="mode")]] = Field(default_factory=list)

    @model_validator(mode="after")
    def references(self):
        nodes = {n["id"] for n in self.document["nodes"]} - set(self.document["final_goal"])
        if set(self.entries) != nodes:
            raise ValueError("entries must supply exactly one execution entry for every action")
        if any(t.node_id is not None and t.node_id not in nodes for t in self.tunnels):
            raise ValueError("Tunnel schedule references an unknown action")
        return self


#: Default semantics for the detail codes the platform uses. A failure record answers four
#: questions the planner and the retry policy need: which stage, what code, was anything
#: dispatched, and may the same operation be repeated safely?
_DETAIL_FLAGS = (
    ("session_backend_rpc_unconfirmed", {"retryable": True, "dispatched": None}),
    ("owner_tunnel_", {"retryable": True, "dispatched": False}),
    ("owner_pivot_", {"retryable": True, "dispatched": False}),
    ("owner_delivery_", {"retryable": True, "dispatched": False}),
    ("action_carrier_", {"retryable": False, "dispatched": True}),
    ("action_unconfirmed", {"retryable": False, "dispatched": True}),
    ("post_unconfirmed", {"retryable": False, "dispatched": True}),
    ("post_passed_session_not_ready", {"retryable": False, "dispatched": True}),
)


def _detail_flags(detail):
    text = str(detail or "")
    for prefix, flags in _DETAIL_FLAGS:
        if text.startswith(prefix):
            return flags
    return {"retryable": None, "dispatched": None}


class PipelineFailure(ValueError):
    def __init__(self, category: Literal["参数没给到", "会话没接上", "技能卡写得不好"], detail,
                 *, stage=None, dispatched=None, retryable=None, hint=""):
        self.category, self.detail = category, detail
        flags = _detail_flags(detail)
        self.stage = stage
        self.dispatched = flags["dispatched"] if dispatched is None else dispatched
        self.retryable = flags["retryable"] if retryable is None else retryable
        self.hint = str(hint or "")
        super().__init__(detail)

    def as_record(self):
        return {"stage": self.stage, "category": self.category, "detail": self.detail,
                "dispatched": self.dispatched, "retryable": self.retryable,
                "hint": self.hint}


class PipelineState(TypedDict):
    run_id: str
    input: dict
    planner_context: dict
    current: dict
    rounds: list[dict]
    tunnel_results: list[dict]
    prepared_endpoints: list[dict]
    failure: dict | None
    finished: bool


def unverified_goals(document, rows):
    """Terminal goals that no passed action result backs.

    A goal is an OR node; it is proven when one of its AND parents (the actions this run
    executes) has a `通过` record. The planner's "finished" decision alone cannot stand in for
    that, or a run stops on a node it never attempted and still reports completion.
    """
    passed = {str(row.get("node_id")) for row in (rows or [])
              if str(row.get("结果")) == "通过"}
    nodes = {str(node["id"]): node for node in document.get("nodes", [])}
    missing = []
    for goal in document.get("final_goal") or []:
        parents = [str(item["id"]) for item in
                   (nodes.get(str(goal), {}).get("dependencies", {}) or {}).get("parents", [])
                   if str(item.get("type")) == "AND"]
        if not any(parent in passed for parent in parents):
            missing.append(str(goal))
    return missing


class PipelineService:
    def __init__(self, planner, pre, action, post, closeout, tunnels, *, evidence=None,
                 delivery_hook=None, session_alive=None):
        #: Optional deployment hook: for one selected node it prepares whatever the
        #: Action needs beyond the frozen input (for example a run's hand-over).
        self.delivery_hook = delivery_hook
        #: Optional liveness probe: (session_id, instance_id) -> truthy when the owner still
        #: holds that exact incarnation. The pipeline binds nodes to registered sessions, and
        #: a session that died mid-run must not be reused as if it were alive.
        self.session_alive = session_alive
        self.store = planner.store
        if any(s.store.dsn != self.store.dsn for s in (pre, action, post, closeout)):
            raise PipelineFailure("参数没给到", "All stages must share the checkpoint store")
        self.planner, self.pre, self.action = planner, pre, action
        self.closeout, self.tunnels = closeout, tunnels
        self.sessions = closeout.registry
        self.evidence = evidence
        self.post = PostStageRunner(self.store, post, session_closeout=closeout)

    @staticmethod
    def config_for(run_id, size=1):
        try:
            run_id = str(UUID(run_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise PipelineFailure("参数没给到", "run_id must be a UUID") from exc
        return {"configurable": {"thread_id": "pipeline:" + run_id},
                "metadata": {"agv_kind": "pipeline"}, "recursion_limit": 12 * size + 30}

    def _tunnels(self, state, phase):
        current = state.get("current", {})
        node = current.get("node_id") if phase != "startup" else None
        results, endpoints = [], []
        for raw in state["input"]["tunnels"]:
            if (raw["phase"], raw["node_id"]) != (phase, node):
                continue
            if raw["mode"] == "build":
                session = self.sessions.find(state["run_id"], raw["pivot_host"], raw["privilege"])
                if session is None:
                    raise PipelineFailure("会话没接上", "tunnel_session_not_found")
                request = TunnelRequest(**{key: raw[key] for key in (
                    "operation_id", "direction", "pivot_host", "privilege", "listen_host",
                    "target_host", "target_port")}, run_id=state["run_id"], session=session.reference(),
                    source_node_id=session.source_node_id, source_attempt=session.source_attempt)
                record = self.tunnels.prepare(request)
                result = self.tunnels.build(state["run_id"], record.tunnel_id).model_dump(mode="json")
            else:
                record = self.tunnels.registry.by_operation(state["run_id"], raw["operation_id"])
                if record is None:
                    raise PipelineFailure("会话没接上", "tunnel_not_found")
                result = self.tunnels.connect(state["run_id"], record.tunnel_id,
                    raw["target_host"], raw["target_port"]).model_dump(mode="json")
                endpoints.append(result)
            results.append({"directive": raw, "result": result})
        return results, endpoints

    def _graph(self, saver, *, confirm_environment=False, interrupt_after=None):
        def guard(stage, operation):
            def invoke(state):
                try:
                    return operation(state)
                except PipelineFailure as exc:
                    # The structured record travels with the failure: stage, whether the
                    # operation was already dispatched, and whether a retry is safe.
                    failure = {key: value for key, value in exc.as_record().items()
                               if value is not None and value != ""}
                except CloseoutFailure as exc:
                    failure = {"category": "会话没接上", "detail": exc.code}
                except (ValueError, KeyError, TypeError) as exc:
                    failure = {"category": "参数没给到", "detail": str(exc)}
                except Exception as exc:
                    failure = {"category": "会话没接上", "detail": type(exc).__name__}
                return {"failure": {"stage": stage, **failure}}
            return invoke

        def startup(state):
            results, endpoints = self._tunnels(state, "startup")
            return {"tunnel_results": results, "prepared_endpoints": endpoints}

        def plan(state):
            ordinal = len(state["rounds"]) + 1
            ids = {stage + "_id": str(uuid5(UUID(state["run_id"]), f"{stage}:{ordinal}"))
                   for stage in ("planner", "pre", "action")}
            self.planner.create(state["planner_context"], run_id=ids["planner_id"], workflow_id=state["run_id"])
            view = self.planner.resume(ids["planner_id"],
                verified_context=state["planner_context"] if confirm_environment else None)
            if view["status"] == "exhausted":
                raise PipelineFailure("技能卡写得不好", "planner_output_invalid")
            if view["status"] not in {"finished", "awaiting_precheck"}:
                raise PipelineFailure("会话没接上", "planner_incomplete")
            if view["status"] == "finished":
                # The planner's own word is not proof: every terminal goal must be backed by
                # a passed action record. Without this a run could stop after a node that was
                # never attempted and still call itself complete (live 2026-10-18: the first
                # "completed" run had no result for nodes 44/47).
                missing = unverified_goals(state["input"]["document"],
                                           state["planner_context"]["previous_results"])
                if missing:
                    raise PipelineFailure("会话没接上",
                                          "pipeline_goal_unverified: " + ", ".join(missing))
            return {"finished": view["status"] == "finished", "current": {
                **ids, "number": ordinal, "node_id": view["decision"]["next_node_id"], "planner": view}}

        def bind(state):
            current = deepcopy(state["current"])
            records = self.sessions.list_for_run(state["run_id"])
            reference = resolve_session(state["input"]["document"], current["node_id"], records,
                controller_rules=state["input"].get("controller_rules") or (),
                entry_actors=state["input"].get("controller_actors") or {})
            if isinstance(reference, SessionResolutionFailure):
                raise PipelineFailure("会话没接上", reference.reason)
            record = next(r for r in records if r.reference() == reference)
            # A registered console session can die while the run continues (a service-launched
            # payload, a probe that recycles it). Binding the node to that stale entry makes
            # every later step fail on a route that no longer exists, and the failure looks
            # like a broken module (live 2026-10-18, final-03 round 6: node 44 bound to the
            # dead pc1 session 3 while session 5 was alive). Verify, and fall back to another
            # live session for the same host and privilege before giving up.
            if record.binding_kind != "controller_entry" and (record.provider or "msf") == "msf":
                alive = True
                if callable(self.session_alive):
                    try:
                        alive = bool(self.session_alive(record.session_id, record.instance_id))
                    except Exception:
                        alive = False
                if not alive:
                    replacement = next((row for row in records
                        if row.binding_kind != "controller_entry"
                        and (row.provider or "msf") == "msf"
                        and row.host == record.host and row.privilege == record.privilege
                        and row.session_id != record.session_id), None)
                    if replacement is None:
                        raise PipelineFailure("会话没接上", "session_registry_stale")
                    reference = replacement.reference()
                    record = replacement
            results, endpoints = self._tunnels(state, "before")
            from src.session.binding import execution_binding
            addresses = {*(next((item.get("ips") or [] for item in
                                 state["input"]["document"].get("hosts", [])
                                 if item.get("host") == record.host), [])),
                         *([record.observed_address] if record.observed_address else [])}
            current["execution"] = execution_binding(
                record,
                entry=state["input"]["entries"][current["node_id"]],
                addresses=addresses,
                endpoints=[*state["prepared_endpoints"], *endpoints]).model_dump(
                    exclude_none=True)
            # The deployment may add per-node inputs (for example the hand-over this
            # attempt must run); they ride with the round, not with the frozen input.
            current["delivery"] = ((self.delivery_hook(
                state["input"]["document"], current["node_id"], record,
                execution=current["execution"]) or {}) if self.delivery_hook else {})
            return {"current": current, "tunnel_results": [*state["tunnel_results"], *results]}

        def pre(state):
            current = deepcopy(state["current"])
            self.pre.create(state["input"]["document"], current["node_id"],
                environment=state["input"]["environment"], execution=current["execution"], run_id=current["pre_id"])
            current["pre"] = self.pre.resume(current["pre_id"], confirm_environment=confirm_environment)
            result = current["pre"]["state"].get("result")
            if not result:
                raise PipelineFailure("会话没接上", "pre_incomplete")
            # An unconfirmed Pre fact is not a rejection: the Pre stage routes it to Action
            # with its unknown facts recorded, and Action is where the fact gets observed.
            # Only a confirmed negative blocks the node (live 2026-10-18: node 2's
            # `isFirewall(dc,enabled)` came back unknown and the whole run stopped).
            if result["result"] == "\u4e0d\u901a\u8fc7":
                raise PipelineFailure("技能卡写得不好", "pre_rejected")
            return {"current": current}

        def action(state):
            current = deepcopy(state["current"])
            self.action.create(state["input"]["document"], current["node_id"],
                thread_id=current["action_id"], execution=current["execution"],
                environment={**state["input"]["environment"], **(current.get("delivery") or {})})
            current["action"] = self.action.resume(current["action_id"], confirm_environment=confirm_environment)
            result = current["action"]["state"].get("result")
            if not result or result.get("route") != "post":
                failure = (result or {}).get("failure", {})
                detail = str(failure.get("detail") or "")
                if detail == "action_carrier_export_invalid":
                    raise PipelineFailure("参数没给到", detail)
                # Keep the Action's own reason. A single catch-all code hides whether the
                # failure was a lost RPC, a rejected contract, or an unconfirmed effect, and
                # the planner then retries without knowing what to change (review finding
                # P0, 2026-10-19).
                if detail:
                    raise PipelineFailure(str(failure.get("category") or "会话没接上"), detail)
                raise PipelineFailure("会话没接上", "action_unconfirmed")
            return {"current": current}

        def post(state):
            current = deepcopy(state["current"])
            pending = self.post.inspect(state["run_id"])
            if pending["next_steps"]:
                self.post.resume(state["run_id"])
            result = self.post.accept_action(state["run_id"], state["input"]["document"],
                current["node_id"], current["action"], source_attempt=current["number"],
                environment=state["input"]["environment"])
            key = current["node_id"] + ":" + current["action_id"]
            current["post"] = result["post_results"][key]
            current["session"] = result["session_results"].get(key)
            if current["post"].get("postPassed") and not current["post"].get("nodeComplete", True):
                return {"current": current, "failure": {"category": "会话没接上",
                    "detail": "post_passed_session_not_ready", "stage": "post"}}
            conclusion = current["post"]["state"].get("result")
            if not conclusion or conclusion["result"] == "未知":
                observation = current["post"]["state"].get("current", {}).get("observation") or {}
                code = observation.get("response", {}).get("error_code")
                if code == "post_target_state_observation_rejected":
                    raise PipelineFailure("参数没给到", code)
                if code in {"post_observation_channel_unavailable", "post_carrier_channel_unavailable"}:
                    raise PipelineFailure("会话没接上", code)
                # Keep whatever the verifier actually said. A catch-all code tells the planner
                # nothing about whether the evidence was missing, the channel was gone, or the
                # request was rejected (review finding P0).
                reason = (observation.get("response", {}).get("detail")
                          or (conclusion or {}).get("reason")
                          or "post_unconfirmed")
                raise PipelineFailure("会话没接上", str(reason))
            return {"current": current}

        def tunnels(state):
            results, endpoints = self._tunnels(state, "after")
            return {"tunnel_results": [*state["tunnel_results"], *results],
                    "prepared_endpoints": [*state["prepared_endpoints"], *endpoints]}

        def feedback(state):
            current = deepcopy(state["current"])
            result = (current["post"]["state"]["result"]["result"] if "post" in current else
                      current["pre"]["state"]["result"]["result"])
            row = {"node_id": current["node_id"], "结果": result}
            context = deepcopy(state["planner_context"])
            context["previous_results"].append(row)
            context["last_result"] = row
            current["feedback"] = row
            return {"planner_context": PlannerInput.model_validate(context).model_dump(),
                    "rounds": [*state["rounds"], current]}

        graph = StateGraph(PipelineState)
        for name, operation in (("startup", startup), ("plan", plan), ("bind", bind),
                ("pre", pre), ("action", action), ("post", post), ("tunnels", tunnels), ("feedback", feedback)):
            graph.add_node(name, guard(name, operation))
        graph.add_edge(START, "startup")
        routes = {"startup": lambda s: "plan", "plan": lambda s: END if s["finished"] else "bind",
            # Pre hands an unconfirmed fact to Action with its unknown facts recorded; that
            # route is the Pre stage's own decision. Comparing only with "通过" skipped the
            # Action entirely for such a node, so the fact was never attempted and the run
            # could still report completion (live 2026-10-18: nodes 2 and 48 stopped at Pre,
            # and the two execCode goals were never exercised).
            "bind": lambda s: "pre",
            "pre": lambda s: "action" if s["current"]["pre"]["state"]["result"].get("route") == "action"
                             else "feedback",
            "action": lambda s: "post", "post": lambda s: "tunnels" if s["current"]["post"]["state"]["result"]["result"] == "通过" else "feedback",
            "tunnels": lambda s: "feedback", "feedback": lambda s: "plan"}
        for name, route in routes.items():
            graph.add_conditional_edges(name, lambda s, route=route: END if s.get("failure") else route(s))
        return graph.compile(checkpointer=saver, interrupt_after=interrupt_after)

    def create(self, request, *, run_id=None):
        try:
            request = PipelineInput.model_validate(request).model_dump()
            document = request["document"]
            context = PlannerInput.model_validate(build_input(document,
                {n["id"]: {"terminal_record": None} for n in document["nodes"]}, [])).model_dump()
        except (ValueError, KeyError, TypeError) as exc:
            raise PipelineFailure("参数没给到", str(exc)) from exc
        run_id = run_id or str(uuid4())
        config = self.config_for(run_id)
        run_id = config["configurable"]["thread_id"].removeprefix("pipeline:")
        with self.store.lock(config["configurable"]["thread_id"]), self.store.checkpointer() as saver:
            graph = self._graph(saver)
            snapshot = graph.get_state(config)
            if snapshot.values:
                if saved_state(snapshot)["input"] != request:
                    raise PipelineFailure("参数没给到", "Pipeline input changed")
            else:
                graph.update_state(config, {"run_id": run_id, "input": request,
                    "planner_context": context, "current": {}, "rounds": [], "tunnel_results": [],
                    "prepared_endpoints": [], "failure": None, "finished": False}, as_node=START)
        return self.inspect(run_id)

    def inspect(self, run_id):
        with self.store.checkpointer() as saver:
            snapshot = self._graph(saver).get_state(self.config_for(run_id))
            state = saved_state(snapshot)
            if not state:
                raise PipelineFailure("参数没给到", "pipeline_run_not_found")
            return {"id": run_id, "status": "failed" if state["failure"] else
                    "completed" if state["finished"] else "interrupted",
                    "next_steps": list(snapshot.next), "state": state}

    def resume(self, run_id, *, confirm_environment=False, interrupt_after=None):
        config = self.config_for(run_id)
        with self.store.lock(config["configurable"]["thread_id"]), self.store.checkpointer() as saver:
            graph = self._graph(saver, confirm_environment=confirm_environment, interrupt_after=interrupt_after)
            state = saved_state(graph.get_state(config))
            if not state:
                raise PipelineFailure("参数没给到", "pipeline_run_not_found")
            if (state.get("failure") or {}).get("detail") == "post_passed_session_not_ready":
                result = self.post.resume(run_id)
                current = deepcopy(state["current"])
                key = current["node_id"] + ":" + current["action_id"]
                current["post"] = result["post_results"][key]
                current["session"] = result["session_results"].get(key)
                graph.update_state(config, {"current": current,
                    "failure": None if current["post"].get("nodeComplete") else state["failure"]}, as_node="post")
                state = saved_state(graph.get_state(config))
            if not state["failure"] and not state["finished"]:
                for values in graph.stream(None, self.config_for(run_id, len(state["input"]["entries"])),
                                           stream_mode="values", durability="sync"):
                    if self.evidence:
                        self.evidence(values)
        return self.inspect(run_id)
