"""Injected Action loop; no model provider or live execution channel is wired.

Callbacks receive a frozen context and return the schemas in schema.py.
Use start/resume rather than invoking the underlying graph directly: resume
guards a possibly dispatched request against replay. The owner supplies the
official checkpointer and serializes operations for each thread, as Planner does.
"""

from copy import deepcopy
import os
from time import monotonic
from typing import TypedDict

from langgraph.graph import StateGraph, START, END
from pydantic import ValidationError

from src.session.planner_service import saved_state, update_run
from src.session.carrier import CarrierExport, child_candidates
from src.graph.predicates import parse_parameters
from .schema import (ActionExecutionRequest, ExecutionRequest, StepAssessment,
                     ActionObservation)
from .tool_contracts import (CONTROL_PLANE_FACE, CONTROL_SIDE_TOOLS, ActionRequest,
                             normalize_action_request)

#: Wall-clock instrumentation is opt-in: evidence changes only when a run asks for it.
TRACE = os.environ.get("AGV_TRACE", "").strip().lower() not in {"", "0", "false", "no"}

#: Step budget for one action; a bounded main flow replaces unbounded step loops.
MAX_STEPS = 24


class ActionState(TypedDict):
    context: dict
    skills: list[dict]
    step: int
    attempt: int
    max_steps: int
    current: dict
    history: list[dict]
    result: dict | None
    run: dict
    carrier_inventory: dict
    current_carrier_ref: str | None
    session_candidate: dict | None
    session_candidates: dict


def initial_state(node, children, skills=(), *, max_steps=MAX_STEPS):
    """Caller extracts this action and children; Pre and parents are excluded."""
    node = {k: deepcopy(v) for k, v in node.items() if k != "dependencies"}
    return {"context": {"node": node, "children": deepcopy(children)},
            "skills": deepcopy(list(skills)), "step": 1, "attempt": 0,
            "max_steps": int(max_steps),
            "current": {}, "history": [], "result": None,
            "carrier_inventory": {}, "current_carrier_ref": None, "session_candidate": None,
            "session_candidates": {}}


class ActionWorkflow:
    def __init__(self, generate=None, execute=None, assess=None, *, checkpointer, interrupt_after=None):
        if checkpointer is None:
            raise ValueError("Action requires an official checkpointer")

        def visible_skills(state):
            """Runtime-only hand-over declarations never enter the model payload.

            The card body already tells the model what to do; ``entry_setup`` and
            ``delivery`` are read by the deployment after the Action. Sending them to the
            model invited it to re-run the runtime's own key installation.
            """
            return [{key: value for key, value in card.items()
                     if key not in {"entry_setup", "delivery"}}
                    for card in state["skills"]]

        def payload(state):
            return deepcopy({"context": state["context"], "skills": visible_skills(state),
                             "step": state["step"], "history": state["history"],
                             "current": state["current"]})

        def prepare(state):
            return {"attempt": 0,
                    "current": {"step": state["step"], "attempt": 0,
                                "judgments": [], "request": None, "observation": None}}

        def generation(state):
            # A model may write a structured step wrapped in a cmd shape; unfold that here so
            # every later check sees the request the card actually asked for.
            started = monotonic()
            raw = normalize_action_request(generate(payload(state)))
            current = deepcopy(state["current"])
            try:
                # The Action stage accepts its own wider contract: the same cmd/code/tool
                # shapes plus the structured tools a card may name directly.
                current["request"] = ActionRequest.model_validate(raw).model_dump()
                # `request` is the dispatcher's legacy view. Keep the model's canonical
                # contract alongside it so evidence names the shape the card taught,
                # without forcing every stored receipt to change at once.
                if isinstance(raw, dict) and "arguments" in raw:
                    try:
                        current["request_contract"] = (
                            ActionExecutionRequest.model_validate(raw).model_dump())
                    except (ValidationError, TypeError):
                        pass
                binding = state["context"].get("execution", {})
                # The runtime's material directory lives on the control plane, never on the
                # target session. A command that inspects it from the session is a wrong-face
                # step: the fetch service is started with the control tool, and the card's
                # paths are values the runtime already supplies (live 2026-10-18, node 7:
                # `ls /tmp/agv-materials` ran on web1 and proved nothing).
                plan = state["context"].get("delivery_plan") or {}
                control_path = str(plan.get("stager_path") or "")
                if (current["request"]["via"] == "session"
                        and current["request"]["tool"] in {"cmd", "code"}
                        and control_path
                        and control_path in str(current["request"]["content"])):
                    current["error"] = (
                        "This path belongs to the control plane, not the target session. "
                        "Start the fetch service with tool=control name=serve_file via=kali "
                        "using the delivery_work_dir and delivery_fetch_port values; do not "
                        "inspect the runtime's material directory from the session.")
                    current["invalid_request"] = raw
                    if TRACE:
                        current["timings"] = {**(current.get("timings") or {}),
                                              "generate": round(monotonic() - started, 3)}
                    return {"current": current}
                # A control-side tool (payload build, file service, peer service) runs on the
                # runtime's own side and has no target face to freeze.
                if (binding.get("session") and current["request"]["via"] != binding["via"]
                        and current["request"]["tool"] not in CONTROL_SIDE_TOOLS):
                    current["error"] = (
                        "Execution request must use the frozen execution entry (this node's face "
                        "is " + str(binding.get("via")) + "); control-plane steps (build the "
                        "delivery artifact, serve a file, arm the listener) use the control "
                        "tool with via=" + CONTROL_PLANE_FACE)
            except (ValidationError, TypeError) as exc:
                # A bare "does not match" tells the model nothing it can act on, so it
                # repeats the same shape (live 2026-10-18, node 26: three identical
                # tool="tool" name="stage_file" requests). Name the accepted values, keep
                # the validator's own field message, and translate the common misuse.
                raw_tool = str(raw.get("tool") or "") if isinstance(raw, dict) else ""
                raw_name = str(raw.get("name") or "") if isinstance(raw, dict) else ""
                hint = ""
                if raw_tool == "tool" and raw_name in {"stage_file", "run_command", "run_script",
                                                       "http_request", "session_command",
                                                       "msf_job", "serve_file",
                                                       "remote_process"}:
                    hint = (" A tool name in `name` is not a tool: use tool=stage for a file "
                            "write, tool=cmd for a command, tool=code for a script, and "
                            "tool=control for serve_file/remote_process.")
                current["error"] = (
                    "Request does not match the Action tool contract. Accepted tool values: "
                    "cmd, code, tool, http, stage, msf, control, session. "
                    + str(exc)[:300] + hint)
                current["invalid_request"] = raw
            if TRACE:
                current["timings"] = {**(current.get("timings") or {}),
                                      "generate": round(monotonic() - started, 3)}
            return {"current": current}

        def execution(state):
            current = deepcopy(state["current"])
            started = monotonic()
            try:
                observation = ActionObservation.model_validate(execute(deepcopy(current["request"]))).model_dump(exclude_none=True)
            except Exception as exc:
                # Dispatch may already have happened. Never retry from this error.
                # The runtime's own named failure carries why it failed; keep it, so a
                # structured tool that could not run is diagnosable from the evidence.
                response = {"error_type": type(exc).__name__}
                if getattr(exc, "category", None):
                    response["category"] = exc.category
                if getattr(exc, "detail", None):
                    response["detail"] = exc.detail
                observation = {"effect_known": False, "receipt_confirmed": False,
                               "command_succeeded": None, "response": response}
            # One tool call's wall time, kept in the evidence: model time and execution time
            # must be measured, never inferred from file mtimes (bridge review sm412).
            if TRACE:
                observation["elapsed_s"] = round(monotonic() - started, 3)
            current["observation"] = observation
            return {"current": current}

        def judgment(state):
            started = monotonic()
            raw = assess(payload(state))
            current = deepcopy(state["current"])
            record = {"output": raw, "error": None}
            try:
                current["assessment"] = StepAssessment.model_validate(raw).model_dump()
            except (ValidationError, TypeError):
                record["error"] = "Assessment does not match StepAssessment; correct it using the saved observation"
            current["judgments"].append(record)
            if TRACE:
                current["timings"] = {**(current.get("timings") or {}),
                                      "assess": round(monotonic() - started, 3)}
            return {"current": current}

        def export_carrier(state):
            """Metadata handoff cannot invalidate an already committed execution.

            Legacy executors may return their owner receipt inline. The optional
            callback separates fallible channel resolution from command dispatch.
            It may resolve a reference, but must never execute or create a channel.
            """
            current = deepcopy(state["current"])
            exporter = getattr(execute, "export_carrier", None)
            if (not callable(exporter) or current["observation"].get("exported_carrier")
                    or current["observation"].get("exported_carriers")):
                return {}
            try:
                value = exporter(deepcopy(current["observation"]))
                if value is None:
                    return {}
                if isinstance(value, dict) and "carrier" not in value:
                    candidates = child_candidates({"session_candidates": value}, state["context"]["children"])
                    for candidate in candidates.values():
                        carrier = candidate["carrier"]
                        if (carrier["source_node_id"], carrier["source_attempt_id"]) != (
                                state["context"]["node"]["id"], state.get("run", {}).get("id")):
                            raise ValueError("Candidate source mismatch")
                    current["observation"]["exported_carriers"] = candidates
                    current["carrier_export"] = {"status": "exported", "children": sorted(candidates)}
                    return {"current": current}
                exported = CarrierExport.model_validate(value).model_dump()
                carrier = exported["carrier"]
                keys = {tuple(parse_parameters(child["description"])[k] for k in ("host", "user"))
                        for child in state["context"]["children"]
                        if child["description"].partition("(")[0].strip() == "execCode"}
                if ((carrier["target_host"], exported["privilege"]) not in keys
                        or (carrier["source_node_id"], carrier["source_attempt_id"]) != (
                            state["context"]["node"]["id"], state.get("run", {}).get("id"))
                        or carrier["ref"] in state.get("carrier_inventory", {})
                        and state["carrier_inventory"][carrier["ref"]] != carrier):
                    raise ValueError("Carrier export does not match the frozen Action")
                current["observation"]["exported_carrier"] = exported
                current["carrier_export"] = {"status": "exported", "ref": carrier["ref"]}
            except Exception as exc:
                from langgraph.errors import GraphInterrupt
                if isinstance(exc, GraphInterrupt):
                    raise
                # Never persist arbitrary owner exception text (possibly secret),
                # nor fold a metadata failure into effect_known=false.
                # An exception that declares its own category keeps it; PipelineFailure
                # subclasses ValueError, so type inspection alone would mislabel it.
                declared = getattr(exc, "category", None)
                if declared == "参数没给到":
                    invalid = True
                elif declared == "会话没接上":
                    invalid = False
                else:
                    invalid = isinstance(exc, (ValueError, TypeError, KeyError))
                current["carrier_export"] = {"status": "failed", "failure": {
                    "category": "参数没给到" if invalid else "会话没接上",
                    "detail": "action_carrier_export_invalid" if invalid else "action_carrier_channel_unavailable"}}
            return {"current": current}

        def settle(state):
            current = state["current"]
            history = [*state["history"], deepcopy(current)]
            assessment = current.get("assessment")
            result = None
            step = state["step"]
            carrier_failure = current.get("carrier_export", {}).get("failure")
            if carrier_failure:
                result = {"status": "paused", "route": None, "reason": carrier_failure["detail"],
                          "failure": deepcopy(carrier_failure)}
            elif assessment and assessment["result"] == "passed":
                if assessment["action_complete"]:
                    result = {"status": "awaiting_post", "route": "post", "reason": assessment["reason"]}
                elif step >= state.get("max_steps", MAX_STEPS):
                    # A step budget bounds the main flow: a method that keeps reporting
                    # "passed but unfinished" for this long hands its evidence to Post
                    # instead of repeating steps indefinitely.
                    result = {"status": "failed", "route": "post",
                              "reason": "步骤预算耗尽，未在预算内完成；交 Post 复核",
                              "failure": {"category": "技能卡写得不好",
                                          "detail": "action_step_budget_exhausted"}}
                else:
                    step += 1
            elif assessment and assessment["result"] == "unknown":
                result = {"status": "paused", "route": None, "reason": assessment["reason"]}
            elif step >= state.get("max_steps", MAX_STEPS):
                # One model turn is one action block. A failed turn is the model's
                # feedback for the next turn; only the total turn budget ends the loop.
                result = {"status": "failed", "route": "post",
                          "reason": "回合预算耗尽，未在预算内完成；交 Post 复核",
                          "failure": {"category": "技能卡写得不好",
                                      "detail": "action_turn_budget_exhausted"}}
            else:
                step += 1
            inventory = deepcopy(state.get("carrier_inventory", {}))
            exported = (current.get("observation") or {}).get("exported_carrier")
            additions = {}
            multiple = (current.get("observation") or {}).get("exported_carriers")
            if exported or multiple:
                updates = child_candidates({"session_candidate": exported, "session_candidates": multiple},
                                           state["context"]["children"])
                candidates = {**child_candidates(state, state["context"]["children"]), **updates}
                for value in candidates.values():
                    carrier = value["carrier"]
                    if (carrier["source_node_id"], carrier["source_attempt_id"]) != (
                            state["context"]["node"]["id"], state.get("run", {}).get("id")):
                        raise ValueError("Candidate source mismatch")
                    if carrier["ref"] in inventory and inventory[carrier["ref"]] != carrier:
                        raise ValueError("Carrier reference cannot be rebound")
                    inventory[carrier["ref"]] = carrier
                legacy = CarrierExport.model_validate(exported).model_dump() if exported and not multiple else None
                additions = {"carrier_inventory": inventory, "session_candidates": candidates,
                             "session_candidate": legacy,
                             "current_carrier_ref": legacy["carrier"]["ref"] if legacy else None}
            return {"history": history, "step": step, "attempt": 0, "result": result, **additions}

        def pause(state):
            return {"result": {"status": "paused", "route": None,
                               "reason": "Execution effect or assessment remains unconfirmed; reconcile before continuing"}}

        graph = StateGraph(ActionState)
        for name, fn in (("prepare", prepare), ("generate", generation), ("execute", execution),
                         ("assess", judgment), ("export_carrier", export_carrier), ("settle", settle), ("pause", pause)):
            graph.add_node(name, fn)
        graph.add_edge(START, "prepare")
        graph.add_edge("prepare", "generate")
        graph.add_conditional_edges("generate", lambda s: "settle" if s["current"].get("error") else "execute")
        # A confirmed receipt is enough to ask the model what it means, even when the
        # command's own exit status is a failure. Legacy observations without the new
        # field keep the old reading.
        # Both readings must agree: an owner that explicitly downgrades the aggregate
        # (an asynchronous effect it cannot confirm) keeps the pause, even when the
        # inner dispatch produced a receipt.
        graph.add_conditional_edges("execute", lambda s: "assess"
            if (s["current"]["observation"].get("effect_known")
                and s["current"]["observation"].get("receipt_confirmed", True))
            else "pause")
        # A carrier is only resolved when the Action claims its goal is reached.
        # Failed or incomplete steps keep their receipt, then retry or hand off;
        # a metadata failure must never turn an ordinary step into a pause.
        def after_assessment(state):
            assessment = state["current"].get("assessment")
            if assessment is None:
                return "assess" if len(state["current"]["judgments"]) < 3 else "pause"
            if assessment["result"] == "unknown":
                return "pause"
            if assessment["result"] == "passed" and assessment["action_complete"]:
                return "export_carrier"
            return "settle"

        graph.add_conditional_edges("assess", after_assessment)
        graph.add_edge("export_carrier", "settle")
        graph.add_conditional_edges("settle", lambda s: END if s["result"] else "prepare")
        graph.add_edge("pause", END)
        self._graph = graph.compile(checkpointer=checkpointer, interrupt_after=interrupt_after)

    def start(self, state, config):
        if self._graph.get_state(config).values:
            raise ValueError("Action thread already exists; resume it or use a new id")
        return self._graph.invoke(deepcopy(state), config, durability="sync")

    def initialize(self, state, config):
        """Save a new task without invoking a model or dispatch callback."""
        if self._graph.get_state(config).values:
            raise ValueError("Action thread already exists; resume it or use a new id")
        self._graph.update_state(config, deepcopy(state), as_node=START)
        return self.snapshot(config)

    def update_run(self, config, run):
        """Persist lifecycle metadata while preserving durable pending writes."""
        update_run(self._graph, config, self.snapshot(config), {"run": deepcopy(run)})

    def snapshot(self, config):
        return self._graph.get_state(config)

    def resume(self, config, *, observation=None):
        snapshot = self.snapshot(config)
        state = saved_state(snapshot)
        if not state:
            raise KeyError("Action thread not found")
        if state.get("result") and state["result"]["status"] != "paused":
            return state
        pending_execution = "execute" in snapshot.next and not state["current"].get("observation")
        paused = state.get("result", {}) and state["result"]["status"] == "paused"
        if pending_execution or paused:
            if observation is None:
                if not paused:
                    update_run(self._graph, config, snapshot, {"result": {
                        "status": "paused", "route": None, "reason": "Request may have executed; provide reconciled observation"}})
                return saved_state(self.snapshot(config))
            verified = ActionObservation.model_validate(observation).model_dump(exclude_none=True)
            if not verified["effect_known"]:
                raise ValueError("Reconciliation requires a known effect")
            current = deepcopy(state["current"])
            current.setdefault("reconciliations", []).append({
                "previous_observation": current.get("observation"),
                "previous_assessment": current.get("assessment"),
                "previous_carrier_export": deepcopy(current.get("carrier_export")),
                "previous_judgments": deepcopy(current["judgments"]),
                "observation": verified})
            current.update(observation=verified, judgments=[])
            current.pop("assessment", None)
            current.pop("carrier_export", None)
            self._graph.update_state(config, {"current": current, "result": None}, as_node="execute")
        elif observation is not None:
            raise ValueError("Only an unconfirmed execution can be reconciled")
        else:
            # Complete a durable pending node write before resuming its successor.
            if any(isinstance(t.result, dict) for t in snapshot.tasks):
                update_run(self._graph, config, snapshot, {})
        return self._graph.invoke(None, config, durability="sync")
