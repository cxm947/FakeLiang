"""Production Action entry and durable, run-scoped Action -> Post handoff."""

from copy import deepcopy

from src.agents.executor import ActionAgent
from src.agents.executor.workflow import MAX_STEPS, ActionWorkflow, initial_state
from src.agents.pre_verifier.context import HostEnvironment


def action_state(document, node_id, *, skills=(), execution=None, environment=None,
                 max_steps=None):
    """Extract one graph action and its output facts, excluding prerequisites."""
    nodes = document["nodes"]
    ids = [node["id"] for node in nodes]
    if len(ids) != len(set(ids)) or node_id not in ids:
        raise ValueError("Expected a unique action node id")
    node = next(node for node in nodes if node["id"] == node_id)
    if node_id in document.get("final_goal", []) or not node.get("rule_desc"):
        raise ValueError("Expected an executable graph action")
    state = initial_state(node, node["dependencies"]["children"], skills,
                          max_steps=max_steps or MAX_STEPS)
    environment = dict(environment or {})
    # Resolved deployment files are exposed as a flat name → execution-point path
    # map; they are not host environment records and never merge into them.
    materials = deepcopy(environment.pop("materials", {}) or {})
    # A run's hand-over for this attempt: the runtime's handles stay under one key,
    # the finished commands reach the model under the names its card declares.
    delivery = {name: deepcopy(value) for name, value in environment.items()
                if name.startswith("delivery") or name == "must_deliver_session"}
    environment = {name: value for name, value in environment.items() if name not in delivery}
    environment = {name: HostEnvironment.model_validate(value).model_dump(exclude_none=True)
                   for name, value in environment.items()}
    hosts = {host["host"]: host["ips"] for host in document.get("hosts", [])}
    names = {item[key] for item in [node, *node["dependencies"]["children"]]
             for key in ("host", "source_host", "target_host") if item.get(key)}
    state["context"]["hosts"] = {}
    for name in sorted(names):
        if not hosts.get(name):
            raise ValueError(f"Missing address for host {name}")
        state["context"]["hosts"][name] = {"ips": deepcopy(hosts[name]),
                                           **deepcopy(environment.get(name, {}))}
    # Deployment files are pushed per run; the model only ever sees resolved
    # execution-point paths, never inventing one.
    state["context"]["materials"] = materials
    state["context"].update(delivery)
    if execution is not None:
        state["context"]["execution"] = deepcopy(execution)
    return state


def build_action_workflow(*, model, execute, checkpointer, structured_method=None,
                          prompt=None, interrupt_after=None):
    agent = ActionAgent(model, structured_method=structured_method, document=prompt)
    return ActionWorkflow(agent.generate, execute, agent.assess,
                          checkpointer=checkpointer, interrupt_after=interrupt_after)


def run(document, node_id, *, model, execute, checkpointer, thread_id,
        skills=(), execution=None, environment=None, structured_method=None):
    """Generate, dispatch, observe and assess an action with durable checkpoints."""
    workflow = build_action_workflow(model=model, execute=execute, checkpointer=checkpointer,
                                     structured_method=structured_method)
    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": 200,
              "metadata": {"agv_kind": "action"}}
    return workflow.start(action_state(document, node_id, skills=skills, execution=execution,
                                       environment=environment), config)


def post_state(document, node_id, *, index=None, tool_definitions=(), **handoff):
    """Freeze the Post input without reading or changing Action/Pre behavior."""
    from src.agents.post_verifier.context import build_context
    from src.agents.post_verifier.workflow import initial_state as initial_post_state
    return initial_post_state(build_context(document, node_id, **handoff), index, tool_definitions)


def build_post_workflow(*, model=None, gateway=None, checkpointer, structured_method=None,
                        interrupt_after=None, generate=None, assess=None):
    from src.agents.post_verifier.workflow import build_post
    return build_post(model, gateway, checkpointer=checkpointer,
                      structured_method=structured_method, interrupt_after=interrupt_after,
                      generate=generate, assess=assess)


class PostStageRunner:
    """Accumulate references for an entire run, then schedule each Post task.

    The handoff and Post invocation are separate graph nodes. With sync durability,
    no child Post can start until the updated inventory has reached the official
    checkpoint. An explicitly supplied closeout runs after Post through the one
    SessionCloseout entry. Existing Action entry points remain unchanged.
    """

    def __init__(self, store, post_service, *, session_closeout=None, checkpoint_scope=None):
        self.store, self.post_service = store, post_service
        self.session_closeout = session_closeout
        self.checkpoint_scope = checkpoint_scope

    @staticmethod
    def config_for(run_id):
        from uuid import UUID
        return {"configurable": {"thread_id": "pipeline-post:" + str(UUID(run_id))},
                "metadata": {"agv_kind": "pipeline-post"}, "recursion_limit": 100}

    def _config_for(self, run_id):
        from uuid import UUID
        config = self.config_for(run_id)
        if self.checkpoint_scope is not None:
            config["configurable"]["thread_id"] += ":" + str(UUID(self.checkpoint_scope))
        return config

    def _graph(self, saver, *, interrupt_after=None):
        from typing import TypedDict
        from langgraph.graph import START, END, StateGraph

        class RunPostState(TypedDict):
            run_id: str
            carrier_inventory: dict
            handoffs: list
            current: dict
            post_results: dict
            session_results: dict

        def accept_handoff(state):
            from src.agents.post_verifier.context import merge_inventory
            current = deepcopy(state["current"])
            inventory = merge_inventory(state.get("carrier_inventory", {}), current["new_carriers"])
            current["context"]["carrier_inventory"] = deepcopy(inventory)
            row = {"node_id": current["node_id"], "attempt_id": current["attempt_id"],
                   "post_thread_id": current["post_thread_id"],
                   "current_carrier_ref": current["context"].get("current_carrier_ref"),
                   "inventory_refs": sorted(inventory), "action_route": "post",
                   "action_output": current["action_output"],
                   "closeout_request": current.get("closeout_request")}
            return {"carrier_inventory": inventory, "current": current,
                    "handoffs": [*state.get("handoffs", []), row]}

        def post_stage(state):
            current = state["current"]
            from uuid import UUID, uuid5
            child_views = {}
            contexts = current.get("child_contexts") or {"single": current["context"]}
            for child_id, context in contexts.items():
                thread_id = (str(uuid5(UUID(current["post_thread_id"]), child_id))
                             if child_id != "single" else current["post_thread_id"])
                self.post_service._create_context(context, thread_id=thread_id,
                    post_output_directory=current.get("post_output_directory"))
                child_views[child_id] = self.post_service.resume(thread_id)
            view = deepcopy(next(iter(child_views.values())))
            if len(child_views) > 1:
                results = [(v["state"].get("result") or {}).get("result") for v in child_views.values()]
                verdict = "通过" if all(r == "通过" for r in results) else "不通过" if "不通过" in results else "未知"
                view["state"]["result"] = {**(view["state"].get("result") or {}), "result": verdict}
                view["child_results"] = child_views
            return {"post_results": {**state.get("post_results", {}),
                    current["node_id"] + ":" + current["attempt_id"]: view},
                    "current": {**current, "completed": bool(view["state"].get("result"))}}

        def closeout(state):
            from src.session.session_migration import CloseoutFailure
            current = state["current"]
            key = current["node_id"] + ":" + current["attempt_id"]
            view = state["post_results"][key]
            requests = current.get("closeout_requests") or {}
            passed = (view["state"].get("result") or {}).get("result") == "通过"
            outcomes, records = {}, {}
            canonical = {}
            for child_id, request in sorted(requests.items()):
                child_view = view.get("child_results", {}).get(child_id, view)
                child_passed = (child_view["state"].get("result") or {}).get("result") == "通过"
                if not child_passed:
                    outcomes[child_id] = {"postPassed": False, "sessionReady": False, "nodeComplete": False}
                    continue
                import json
                identity = json.dumps({key: request.get(key, []) for key in (
                    "source_provider", "source_reference", "host", "privilege", "identity_aliases")}, sort_keys=True)
                if identity in canonical:
                    prior = canonical[identity]
                    outcomes[child_id] = deepcopy(outcomes[prior])
                    if prior in records:
                        records[child_id] = records[prior]
                    continue
                canonical[identity] = child_id
                try:
                    record = self.session_closeout.finish(child_view, request)
                    self.session_closeout.registry.commit()
                    self.session_closeout.confirm_registration(request, record)
                    records[child_id] = record.model_dump(mode="json")
                    outcomes[child_id] = {"postPassed": True, "sessionReady": True, "nodeComplete": True}
                except CloseoutFailure as exc:
                    outcomes[child_id] = {"postPassed": True, "sessionReady": False,
                                          "nodeComplete": False, "failure": exc.code}
                except Exception as exc:
                    saved = self.session_closeout.inspect(request)
                    outcomes[child_id] = {"postPassed": True, "sessionReady": saved.get("sessionReady", False),
                        "nodeComplete": False, "failure": "registration_failed:" + type(exc).__name__}
            ready = all(v["sessionReady"] for v in outcomes.values()) if requests else True
            complete = passed and all(v["nodeComplete"] for v in outcomes.values())
            view = {**view, "postPassed": passed, "sessionReady": ready, "nodeComplete": complete,
                    "session_outcomes": outcomes}
            sessions = state.get("session_results", {})
            if records:
                sessions = {**sessions, key: next(iter(records.values())) if len(records) == 1 else records}
            return {"session_results": sessions,
                    "post_results": {**state["post_results"], key: view}}

        graph = StateGraph(RunPostState)
        graph.add_node("accept_handoff", accept_handoff)
        graph.add_node("post", post_stage)
        graph.add_node("closeout", closeout)
        graph.add_edge(START, "accept_handoff")
        graph.add_edge("accept_handoff", "post")
        graph.add_edge("post", "closeout")
        graph.add_edge("closeout", END)
        return graph.compile(checkpointer=saver, interrupt_after=interrupt_after)

    def accept_action(self, run_id, document, node_id, action_output, *, environment=None,
                      proposition=None, source_attempt=1, post_output_directory=None,
                      interrupt_after=None):
        from uuid import UUID, uuid5
        from src.agents.post_verifier.context import build_context
        from src.session.planner_service import saved_state
        from src.session.planner_store import RunConflict
        from src.session.session_closeout import CloseoutRequest
        from src.session.carrier import CarrierExport, CarrierReference
        from src.agents.post_verifier.context import merge_inventory

        action = action_output.get("state", action_output)
        if (action.get("result") or {}).get("route") != "post":
            raise ValueError("Post handoff requires Action route=post")
        if str(action.get("context", {}).get("node", {}).get("id")) != str(node_id):
            raise ValueError("Action output belongs to a different graph node")
        attempt_id = action.get("run", {}).get("id")
        if not attempt_id:
            raise ValueError("Post handoff requires the source Action attempt id")
        run_id, node_id, attempt_id = str(UUID(run_id)), str(node_id), str(attempt_id)
        new_carriers = action.get("carrier_inventory", {})
        current_carrier_ref = action.get("current_carrier_ref")
        from src.session.carrier import child_candidates
        outputs = next(n for n in document["nodes"] if str(n["id"]) == node_id)["dependencies"]["children"]
        candidates = child_candidates(action, outputs)
        closeout_requests = {}
        for child_id, value in candidates.items():
            exported = CarrierExport.model_validate(value)
            carrier = exported.carrier
            recorded = CarrierReference.model_validate(new_carriers.get(carrier.ref))
            if (recorded != carrier or (carrier.source_node_id, carrier.source_attempt_id) != (node_id, attempt_id)):
                raise ValueError("Carrier export does not match Action handoff")
            if self.session_closeout is None:
                raise ValueError("Session closeout is not configured")
            closeout_requests[child_id] = CloseoutRequest(run_id=run_id,
                operation_id="closeout:" + attempt_id + (":" + child_id if len(candidates) > 1 else ""),
                host=carrier.target_host, privilege=exported.privilege, source_node_id=node_id,
                identity_aliases=exported.identity_aliases,
                observed_address=carrier.address, source_attempt=source_attempt, source_attempt_id=attempt_id,
                child_id=child_id, source_type=carrier.kind, source_provider=carrier.owner,
                source_reference=exported.reference, channel=exported.channel).model_dump()
        if not candidates and (current_carrier_ref is not None or new_carriers):
            raise ValueError("Action carrier requires its owner-issued session candidate")
        closeout_request = next(iter(closeout_requests.values()), None)
        config = self._config_for(run_id)
        with self.store.lock(config["configurable"]["thread_id"]), self.store.checkpointer() as saver:
            graph = self._graph(saver, interrupt_after=interrupt_after)
            snapshot = graph.get_state(config)
            state = saved_state(snapshot)
            key = node_id + ":" + attempt_id
            if key in state.get("post_results", {}):
                previous = next(row for row in state["handoffs"]
                                if row["node_id"] == node_id and row["attempt_id"] == attempt_id)
                if (previous.get("closeout_request") != closeout_request or
                        previous.get("action_output") != action):
                    raise RunConflict("Post handoff exists with different Action input")
                if snapshot.next:
                    raise RunConflict("Resume the pending Post closeout")
                return state
            if snapshot.next:
                raise RunConflict("Resume the pending Post handoff before submitting another node")
            inventory = merge_inventory(state.get("carrier_inventory", {}), new_carriers)
            context = build_context(document, node_id, environment, action_state=action,
                carrier_inventory=inventory, current_carrier_ref=current_carrier_ref,
                proposition=proposition,
                run_id=run_id, attempt_id=attempt_id)
            child_contexts = {str(child["id"]): build_context(document, node_id, environment,
                action_state=action, carrier_inventory=inventory, current_carrier_ref=current_carrier_ref,
                proposition=proposition, run_id=run_id, attempt_id=attempt_id, child_id=str(child["id"]))
                for child in outputs} if len(outputs) > 1 else {}
            current = {"node_id": node_id, "attempt_id": attempt_id,
                "post_thread_id": str(uuid5(UUID(run_id), "post:" + key)),
                "context": context, "new_carriers": deepcopy(new_carriers or {}),
                "action_output": deepcopy(action),
                "closeout_request": closeout_request, "closeout_requests": closeout_requests,
                "child_contexts": child_contexts,
                "post_output_directory": str(post_output_directory) if post_output_directory else None,
                "completed": False}
            return graph.invoke({"run_id": run_id, "current": current,
                "carrier_inventory": state.get("carrier_inventory", {}),
                "session_results": state.get("session_results", {}),
                "handoffs": state.get("handoffs", []), "post_results": state.get("post_results", {})},
                config, durability="sync")

    def inspect(self, run_id):
        from src.session.planner_service import saved_state
        with self.store.checkpointer() as saver:
            snapshot = self._graph(saver).get_state(self._config_for(run_id))
            return {"state": saved_state(snapshot), "next_steps": list(snapshot.next),
                    "checkpoint_id": snapshot.config["configurable"].get("checkpoint_id") if snapshot.config else None}

    def resume(self, run_id):
        from src.session.planner_service import saved_state
        config = self._config_for(run_id)
        with self.store.lock(config["configurable"]["thread_id"]), self.store.checkpointer() as saver:
            graph = self._graph(saver)
            snapshot = graph.get_state(config)
            if not snapshot.values:
                raise KeyError(run_id)
            state = saved_state(snapshot)
            current = state.get("current", {})
            key = current.get("node_id", "") + ":" + current.get("attempt_id", "")
            outcome = state.get("post_results", {}).get(key, {})
            if not snapshot.next and outcome.get("postPassed") and not outcome.get("nodeComplete"):
                graph.update_state(config, {}, as_node="post")
                snapshot = graph.get_state(config)
            return graph.invoke(None, config, durability="sync") if snapshot.next else saved_state(snapshot)
