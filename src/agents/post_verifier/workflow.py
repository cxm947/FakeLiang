"""Checkpointed generate → observe → assess Post, without command replay."""

from copy import deepcopy
from hashlib import sha256
import json
from secrets import token_hex
from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import ValidationError

from src.agents.prompting import load_prompt
from src.session.binding import same_subject
from src.session.planner_service import saved_state, update_run
from .agent import PostAgent, PROMPT_PATH
from .context import validate_inventory
from .retrieval import PostSkillIndex
from .schema import Assessment, ExecutionRequest, Observation


class PostState(TypedDict):
    context: dict
    carrier_inventory: dict
    current_carrier_ref: str | None
    skills: list[dict]
    tools: list[dict]
    documents: dict
    current: dict
    operations: dict
    records: list[dict]
    result: dict | None
    run: dict


def initial_state(context, index=None, tool_definitions=()):
    context = deepcopy(context)
    return {"context": context,
            "carrier_inventory": validate_inventory(context.get("carrier_inventory")),
            "current_carrier_ref": context.get("current_carrier_ref"),
            "skills": (index or PostSkillIndex()).search(context),
            "tools": deepcopy(list(tool_definitions)),
            "documents": {name: load_prompt(PROMPT_PATH.with_name(f"{name}.yaml"))
                          for name in ("generate", "assess")},
            "current": {}, "operations": {}, "records": [], "result": None}


def operation_id(context, thread_id):
    identity = {key: context.get(key) for key in
                ("run_id", "attempt_id", "graph_hash", "proposition", "current_carrier_ref", "child_id")}
    identity.update(node_id=context["node"]["id"], thread_id=str(thread_id), phase="post", version=1)
    return "post-" + sha256(json.dumps(identity, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _closed(observation, current=None, context=None, carrier_ref=None):
    response = observation.get("response", {})
    return (response.get("carrier_state") == "closed" and response.get("closure_confirmed") is True
            and current is not None and context is not None and carrier_ref is not None
            and response.get("operation_id") == current["operation_id"]
            and response.get("target_host") == context["target_host"]
            and response.get("carrier_ref") == carrier_ref)


def _stdout(response):
    """Only actual output fields count; request strings and nonce metadata do not."""
    output = [response[key] for key in ("stdout", "output") if isinstance(response.get(key), str)]
    nested = response.get("response")
    if isinstance(nested, dict):
        output.extend(_stdout(nested))
    return output


def evidence_error(state):
    current, context = state["current"], state["context"]
    observation = current.get("observation")
    if observation is None:
        return "没有已保存的观测结果"
    response = observation["response"]
    if not observation["effect_known"]:
        detail = response.get("error_code", response.get("error_type", response.get("reason", "unknown_effect")))
        return f"观测未取得可确认结果：{detail}；目标 {context['target_host']}"
    if response.get("is_error") or response.get("transport_error"):
        return "执行器报告观测传输错误，不能据此断定目标命题失败"
    if response.get("operation_id") != current["operation_id"]:
        return "观测返回不能绑定本次 operation_id"
    if response.get("target_host") != context["target_host"]:
        return "观测返回不能绑定要求的目标主机"
    if context["proposition"] == "channel_liveness" and (
            response.get("carrier_ref") != state["current_carrier_ref"]):
        return "观测返回不能绑定本次要求的执行载体"
    request_tool = str((current.get("request") or {}).get("tool") or "")
    control_request = request_tool in {"control", "msf", "credential_test"}
    if context["evidence_policy"]["require_nonce"] and not control_request:
        marker = "AGV_POST_NONCE=" + current["nonce"]
        lines = [line.strip() for output in _stdout(response) for line in output.splitlines()]
        if response.get("nonce_observed") != current["nonce"] or marker not in lines:
            return "实际输出缺少本次完整随机 nonce 标记，不能证明新鲜观测"
    return None


def _assessment(context, result, reason):
    return {"node_id": str(context["node"]["id"]), "result": result, "reason": reason}


def _review(context):
    """Final graph facts may review their parent's evidence, never claim new IO."""
    if context["proposition"] == "channel_liveness":
        return _assessment(context, "未知", "历史证据复核不能证明原载体当前持续可用；该命题需要活体观测"), []
    acceptable = set(context.get("upstream_node_ids", []))
    matches = []
    for item in context.get("prior_post_results", []):
        state = item.get("state", item)
        result = state.get("result") or {}
        if not isinstance(result, dict) or str(result.get("node_id")) not in acceptable:
            continue
        if result.get("result") not in {"通过", "不通过", "未知"}:
            continue
        valid_live = False
        if result.get("evidence_mode") == "live_observation" and state.get("current", {}).get("observation"):
            try:
                valid_live = evidence_error(state) is None
            except (KeyError, TypeError):
                pass
        matches.append({"node_id": result["node_id"], "result": result["result"],
                        "reason": result.get("reason"), "operation_id": result.get("operation_id"),
                        "observation": deepcopy(state.get("current", {}).get("observation")),
                        "evidence_mode": result.get("evidence_mode"), "valid_live_evidence": valid_live})
    passed = [item for item in matches if item["result"] == "通过" and item["observation"]
              and item["valid_live_evidence"] and item["observation"].get("effect_known") and
              item["observation"].get("response", {}).get("target_host") == context["target_host"]]
    if passed:
        value, reason = "通过", "复核上游已保存的 Post 通过证据；未执行新的活体观测"
    elif matches and all(item["result"] == "不通过" for item in matches):
        value, reason = "不通过", "上游 Post 已明确不通过，目标输出未获通过证据；仅作证据复核"
    else:
        value, reason = "未知", "没有可归属于该终点上游且足以支持目标事实的 Post 证据；未执行活体观测"
    return _assessment(context, value, reason), matches


class PostWorkflow:
    def __init__(self, model=None, gateway=None, *, checkpointer, structured_method=None,
                 interrupt_after=None, generate=None, assess=None):
        if checkpointer is None:
            raise ValueError("Post requires an official checkpointer")
        self.gateway = gateway
        agent = PostAgent(model, structured_method=structured_method) if model else None
        generate = generate or (agent.generate if agent else None)
        assess = assess or (agent.assess if agent else None)

        def payload(state):
            value = deepcopy({key: state[key] for key in
                              ("context", "carrier_inventory", "current_carrier_ref", "skills", "tools", "current")})
            if gateway is not None and hasattr(gateway, "execution_context"):
                value["execution"] = gateway.execution_context(value["context"])
            return value

        def prepare(state, config):
            context = state["context"]
            current = {"operation_id": operation_id(context, config["configurable"]["thread_id"]),
                       "nonce": token_hex(16), "request": None, "observation": None,
                       "judgments": [], "evidence_mode": context["evidence_policy"]["mode"]}
            # A node whose bound session is another machine (a pivot) cannot observe its own
            # target: running the probe locally would describe the pivot, not the subject. In
            # that case the Action's own receipt is the evidence, and the card says how to
            # read it (live 2026-10-18: node 2, where the writeup proves the state with the
            # next psexec step rather than a read-back).
            execution = context.get("execution") or {}
            target = context.get("target_host")
            target_addresses = ((context.get("hosts") or {}).get(target) or {}).get("ips") or []
            observes = same_subject(execution, target, target_addresses)
            if (not observes and not state.get("current_carrier_ref")
                    and context.get("proposition") == "target_state"
                    # Without an Action receipt there is nothing to read; the ordinary
                    # observation path must still run and record why it could not.
                    and context.get("action_evidence")):
                current["skip_observation"] = True
                current["evidence_mode"] = "action_receipt"
                # Deterministic verdict for the hand-over case: the write ran (its receipt
                # exists and the Action stage accepted it) and the effect is proven by the
                # dependent execCode node. Leaving this to the model made the same receipt
                # alternate between 通过 and 未知 (live 2026-10-18, runs final-03/05).
                evidence = context.get("action_evidence") or []
                routed = str((context.get("action_result") or {}).get("status") or "")
                if evidence and routed == "awaiting_post":
                    current["assessment"] = _assessment(
                        context, "\u901a\u8fc7",
                        "\u5199\u64cd\u4f5c\u5df2\u6267\u884c\u5e76\u53d6\u5f97\u56de\u6267\uff1b"
                        "\u72b6\u6001\u7531\u540e\u7eed execCode \u8282\u70b9\u9a8c\u8bc1")
                else:
                    current["assessment"] = _assessment(
                        context, "\u672a\u77e5", "\u6ca1\u6709\u53ef\u7528\u7684 Action \u56de\u6267")
            if current["evidence_mode"] == "evidence_review":
                current["assessment"], current["reviewed_evidence"] = _review(context)
            elif context["requires_carrier"] and not state["current_carrier_ref"]:
                current["assessment"] = _assessment(context, "不通过",
                    "Action 未交付图中 execCode 输出要求的可执行载体：" + context["no_carrier_reason"])
            elif state["current_carrier_ref"] and state["current_carrier_ref"] not in state["carrier_inventory"]:
                current["assessment"] = _assessment(context, "未知", "本次载体引用在 run 级清单中丢失，无法解析")
            elif state["current_carrier_ref"] and state["carrier_inventory"][state["current_carrier_ref"]]["target_host"] != context["target_host"]:
                current["assessment"] = _assessment(context, "未知", "本次载体绑定的主机与图要求的目标不一致")
            elif state["current_carrier_ref"] and (
                    state["carrier_inventory"][state["current_carrier_ref"]]["kind"] == "unknown"):
                current["assessment"] = _assessment(context, "未知", "candidate_type_unknown")
            elif context["proposition"] == "channel_liveness" and not state["current_carrier_ref"]:
                current["assessment"] = _assessment(context, "未知", "原通道持续可用命题缺少原载体引用")
            elif context.get("carrier_export"):
                candidate = context["carrier_export"]
                if candidate["carrier"]["kind"] == "unknown":
                    current["assessment"] = _assessment(context, "未知", "candidate_type_unknown")
                elif candidate.get("reference") is None:
                    current["assessment"] = _assessment(context, "未知", "candidate_reference_missing")
            return {"current": current}

        def generation(state):
            current = deepcopy(state["current"])
            if generate is None:
                current["assessment"] = _assessment(state["context"], "未知", "Post 请求生成器未配置")
            else:
                raw = generate(payload(state))
                current["generation"] = {"output": raw}
                try:
                    current["request"] = ExecutionRequest.model_validate(raw).model_dump()
                except (ValidationError, TypeError):
                    current["assessment"] = _assessment(state["context"], "未知", "Post 请求不符合执行器格式，未下发")
            return {"current": current}

        def dispatch_intent(state):
            current = state["current"]
            operations = deepcopy(state["operations"])
            operations.setdefault(current["operation_id"], {"status": "prepared", "nonce": current["nonce"],
                "request": deepcopy(current["request"]), "observation": None})
            return {"operations": operations}

        def execute(state):
            current = deepcopy(state["current"])
            existing = state["operations"].get(current["operation_id"], {}).get("observation")
            if existing is not None:
                observation = existing
            else:
                try:
                    if gateway is None:
                        raise RuntimeError("Post executor is not configured")
                    execution_context = deepcopy(state["context"])
                    execution_context.update(carrier_inventory=deepcopy(state["carrier_inventory"]),
                                             current_carrier_ref=state["current_carrier_ref"])
                    observation = Observation.model_validate(gateway.observe(
                        deepcopy(current["request"]), execution_context,
                        operation_id=current["operation_id"],
                        nonce=current["nonce"])).model_dump(exclude_none=True)
                except Exception as exc:
                    # Interrupts must reach LangGraph; resume then reconciles this operation.
                    from langgraph.errors import GraphInterrupt
                    if isinstance(exc, GraphInterrupt):
                        raise
                    response = {"error_type": type(exc).__name__}
                    if getattr(exc, "category", None):
                        response["category"] = exc.category
                    if getattr(exc, "detail", None):
                        response["detail"] = exc.detail
                    elif str(exc).strip():
                        # A bare type name cannot be diagnosed; the dispatcher's own
                        # messages carry contract errors such as a missing credential ref.
                        response["message"] = str(exc)[:300]
                    observation = {"effect_known": False, "response": response}
            current["observation"] = deepcopy(observation)
            operations = deepcopy(state["operations"])
            operations[current["operation_id"]].update(status="observed", observation=deepcopy(observation))
            inventory = deepcopy(state["carrier_inventory"])
            if state["current_carrier_ref"] in inventory and _closed(
                    observation, current, state["context"], state["current_carrier_ref"]):
                inventory[state["current_carrier_ref"]]["lifecycle"] = "closed"
            return {"current": current, "operations": operations, "carrier_inventory": inventory}

        def judgment(state):
            current, context = deepcopy(state["current"]), state["context"]
            if (current.get("observation") is not None
                    and _closed(current["observation"], current, context,
                                state["current_carrier_ref"])
                    and context["proposition"] == "channel_liveness"):
                current["assessment"] = _assessment(context, "不通过", "载体 owner 已明确确认原载体关闭")
            elif not current.get("skip_observation") and (error := evidence_error(state)):
                current["assessment"] = _assessment(context, "未知", error)
            elif assess is None:
                current["assessment"] = _assessment(context, "未知", "已取得观测，但 Post 证据判断器未配置")
            else:
                raw = assess(payload(state))
                record = {"output": deepcopy(raw), "error": None}
                try:
                    result = Assessment.model_validate(raw).model_dump()
                    if result["node_id"] != str(context["node"]["id"]):
                        raise ValueError("Post assessment belongs to another node")
                    current["assessment"] = result
                except (ValueError, TypeError):
                    record["error"] = "Post 判断格式或节点归属不正确；仅修正判断，不重复观测"
                current["judgments"].append(record)
                if "assessment" not in current and len(current["judgments"]) >= 3:
                    current["assessment"] = _assessment(context, "未知", record["error"])
            return {"current": current}

        def finish(state):
            current, context = state["current"], state["context"]
            result = {**current["assessment"], "status": "completed", "route": "planner",
                "operation_id": current["operation_id"], "evidence_mode": current["evidence_mode"],
                "proposition": context["proposition"], "requires_carrier": context["requires_carrier"],
                "current_carrier_ref": state["current_carrier_ref"],
                "observed": current.get("observation") is not None,
                "carrier_source": ("不需要" if not state["current_carrier_ref"] and not context["requires_carrier"]
                    else "未交付" if not state["current_carrier_ref"] else
                    "本节点产生" if state["carrier_inventory"].get(state["current_carrier_ref"], {}).get("source_node_id") == context["node"]["id"]
                    else "上游继承")}
            record = {**deepcopy(result), "observation": deepcopy(current.get("observation")),
                      "reviewed_evidence": deepcopy(current.get("reviewed_evidence", [])),
                      "model_judgments": deepcopy(current["judgments"])}
            return {"result": result, "records": [record]}

        graph = StateGraph(PostState)
        for name, function in (("prepare", prepare), ("generate", generation),
                ("dispatch_intent", dispatch_intent), ("execute", execute), ("assess", judgment), ("finish", finish)):
            graph.add_node(name, function)
        graph.add_edge(START, "prepare")
        graph.add_conditional_edges("prepare", lambda state: "finish" if state["current"].get("assessment") else "generate")
        graph.add_conditional_edges("generate", lambda state: (
            "finish" if state["current"].get("assessment")
            else "assess" if state["current"].get("skip_observation")
            else "dispatch_intent"))
        graph.add_edge("dispatch_intent", "execute")
        graph.add_edge("execute", "assess")
        graph.add_conditional_edges("assess", lambda state: "finish" if state["current"].get("assessment") else "assess")
        graph.add_edge("finish", END)
        self._graph = graph.compile(checkpointer=checkpointer, interrupt_after=interrupt_after)

    def snapshot(self, config):
        return self._graph.get_state(config)

    get_state = snapshot

    def update_run(self, config, run):
        update_run(self._graph, config, self.snapshot(config), {"run": deepcopy(run)})

    def initialize(self, state, config):
        if self.snapshot(config).values:
            raise ValueError("Post thread already exists; resume it or use a new id")
        self._graph.update_state(config, deepcopy(state), as_node=START)
        return self.snapshot(config)

    def start(self, state, config):
        if self.snapshot(config).values:
            raise ValueError("Post thread already exists; resume it or use a new id")
        return self._graph.invoke(deepcopy(state), config, durability="sync")

    def resume(self, config, *, observation=None):
        snapshot = self.snapshot(config)
        state = saved_state(snapshot)
        if not state:
            raise KeyError("Post thread not found")
        if state.get("result"):
            if observation is not None:
                raise ValueError("Completed Post cannot be rewritten; start a new explicit observation")
            return state
        current = deepcopy(state["current"])
        uncertain_dispatch = "execute" in snapshot.next and current.get("observation") is None
        if uncertain_dispatch:
            recovered = observation
            if recovered is None and self.gateway is not None and hasattr(self.gateway, "lookup_observation"):
                try:
                    recovered = self.gateway.lookup_observation(current["operation_id"])
                except Exception:
                    recovered = None
            recovered = (Observation.model_validate(recovered).model_dump(exclude_none=True)
                         if recovered is not None else
                         {"effect_known": False, "response": {"error_code": "dispatch_unconfirmed_after_resume",
                          "reason": "稳定操作标识已有下发意图，但执行器无可确认结果；未重复下发"}})
            current["observation"] = recovered
            current["recovery"] = "saved_executor_result" if recovered["effect_known"] else "no_replay_unknown"
            operations = deepcopy(state["operations"])
            operations[current["operation_id"]].update(status="observed", observation=deepcopy(recovered))
            inventory = deepcopy(state["carrier_inventory"])
            if state["current_carrier_ref"] in inventory and _closed(
                    recovered, current, state["context"], state["current_carrier_ref"]):
                inventory[state["current_carrier_ref"]]["lifecycle"] = "closed"
            self._graph.update_state(config, {"current": current, "operations": operations,
                                              "carrier_inventory": inventory}, as_node="execute")
        elif observation is not None:
            raise ValueError("Only an interrupted observation can be reconciled")
        elif any(isinstance(task.result, dict) for task in snapshot.tasks):
            update_run(self._graph, config, snapshot, {})
        return self._graph.invoke(None, config, durability="sync")

    def invoke(self, state, config, *, durability="sync"):
        if durability != "sync":
            raise ValueError("Post requires synchronous checkpoint durability")
        return self.start(state, config) if state is not None else self.resume(config)


def build_post(model=None, gateway=None, *, checkpointer, structured_method=None,
               interrupt_after=None, generate=None, assess=None):
    return PostWorkflow(model, gateway, checkpointer=checkpointer, structured_method=structured_method,
                        interrupt_after=interrupt_after, generate=generate, assess=assess)
