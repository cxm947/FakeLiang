"""A checkpointable per-LEAF generate → execute → assess loop."""

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, TypedDict

from langchain_core.messages import AIMessage, HumanMessage, messages_from_dict, messages_to_dict
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, START, END

from src.agents.prompting import load_prompt
from .schema import Assessment, StageExecutionRequest
from .mcp_client import command_for
from .context import needs_target_access

PROMPTS = Path(__file__).with_name("prompts")


class PreState(TypedDict):
    context: dict
    skills: dict
    tools: list[dict]
    documents: dict
    position: int
    current: dict
    attempts: list[dict]
    records: list[dict]
    messages: list[dict]
    result: dict | None
    run: dict


def initial_state(context, index, tool_definitions):
    return {"context": deepcopy(context),
            "skills": {leaf["id"]: index.search(leaf) for leaf in context["leaves"]},
            "tools": deepcopy(tool_definitions),
            "documents": {name: load_prompt(PROMPTS / f"{name}.yaml") for name in ("generate", "assess")},
            "position": 0, "current": {}, "attempts": [], "records": [], "messages": [], "result": None}


def _messages(document, payload):
    prompt = ChatPromptTemplate.from_messages([
        ("system", document["system_template"]), ("human", document["user_template"])
    ], template_format="jinja2")
    return prompt.invoke({"input_json": json.dumps(payload, ensure_ascii=False, indent=2)}).to_messages()


def _invoke(runnable, messages, schema):
    if runnable is None:
        raise RuntimeError("A model is required to execute Pre")
    try:
        response = runnable.invoke(messages_from_dict(messages))
    except Exception as exc:
        # Interrupt and preserve the request; no provider credentials/body in the checkpoint.
        raise RuntimeError(f"Model call interrupted: {type(exc).__name__}") from None
    raw = response.get("raw")
    record = {"raw": {"content": raw.content, "tool_calls": raw.tool_calls,
                      "invalid_tool_calls": raw.invalid_tool_calls} if raw else None,
              "usage": getattr(raw, "usage_metadata", None), "parsed": None, "error": None}
    try:
        if response.get("parsing_error"):
            raise ValueError("Response does not match the JSON output schema")
        parsed = response.get("parsed")
        if raw is not None:
            if raw.invalid_tool_calls or len(raw.tool_calls) > 1:
                raise ValueError("Expected one well-formed output")
            if not raw.tool_calls:
                parsed = json.loads(raw.content)
        record["parsed"] = schema.model_validate(parsed).model_dump()
    except (ValueError, TypeError) as exc:
        record["error"] = str(exc)
    return record


def build_pre(model=None, gateway=None, *, checkpointer=None, structured_method=None, interrupt_after=None):
    options = {"include_raw": True}
    if structured_method:
        options["method"] = structured_method
    generate = (model.with_structured_output(StageExecutionRequest.model_json_schema(), **options)
                if model else None)
    assess = model.with_structured_output(Assessment.model_json_schema(), **options) if model else None

    def leaf(state):
        return state["context"]["leaves"][state["position"]]

    def select(state):
        if state["position"] >= len(state["context"]["leaves"]):
            return {"current": {"stage": "done"}}
        item = leaf(state)
        policy = item["policy"]
        current = {"stage": "generate", "fact_id": item["id"]}
        if policy != "check":
            current.update(stage="record", assessment={"fact_id": item["id"],
                "result": "通过" if policy == "assumed" else "未检查" if policy == "excluded" else "未知",
                "reason": {"assumed": "按约定成立，未实测", "excluded": "不在 Pre 检查范围",
                           "unsupported": "当前 Pre 不支持该检查条件"}[policy]})
        elif not state["skills"].get(item["id"]):
            current.update(stage="record", assessment={"fact_id": item["id"], "result": "未知",
                                                       "reason": "没有适用的 Pre 技能"})
        elif needs_target_access(item) and not item["hosts"].get(item["parameters"]["host"], {}).get("access"):
            current.update(stage="record", assessment={"fact_id": item["id"], "result": "未知",
                "reason": "缺少该目标已有访问方式，无法检查目标内部状态；未建立新连接或假查 Kali 本机"})
        return {"current": current, "attempts": []}

    def prepare(state):
        item = leaf(state)
        payload = {"node": state["context"]["node"], "leaf": item,
                   "skills": [{k: v for k, v in c.items() if k != "score"}
                              for c in state["skills"][item["id"]]], "tools": state["tools"]}
        if state["context"].get("execution"):
            payload["execution"] = deepcopy(state["context"]["execution"])
        elif gateway is not None and hasattr(gateway, "execution_context"):
            payload["execution"] = gateway.execution_context(item)
        messages = _messages(state["documents"]["generate"], payload)
        for previous in state["attempts"]:
            # Replay the business output, not LangChain's raw-message envelope.
            # Otherwise the model can imitate content/tool_calls instead of the request schema.
            response = previous.get("request")
            if response is None:
                response = (previous.get("generation", {}).get("raw") or {}).get("content", "")
            messages.append(AIMessage(content=response if isinstance(response, str)
                                      else json.dumps(response, ensure_ascii=False)))
            messages.append(HumanMessage(content=json.dumps({
                "execution_return": previous.get("observation"), "output_error": previous.get("error"),
                "assessment": previous.get("assessment"), "assessment_error": previous.get("judgment", {}).get("error")
            }, ensure_ascii=False)))
        if state["attempts"]:
            messages.append(HumanMessage(content=f"本 LEAF 仍未知。请依据上面记录改进检查；剩余尝试 {3-len(state['attempts'])} 次。"))
        current = {"fact_id": item["id"], "attempt": len(state["attempts"]) + 1,
                   "generate_messages": messages_to_dict(messages)}
        return {"current": current, "messages": messages_to_dict(messages)}

    def call_generate(state):
        response = _invoke(generate, state["messages"], StageExecutionRequest)
        current = {**state["current"], "generation": response, "request": response["parsed"], "error": response["error"]}
        if current["request"] is not None:
            binding = state["context"].get("execution")
            declared_face = (current["request"].get("target")
                             or current["request"].get("via"))
            if binding and declared_face != binding["via"]:
                current["error"] = "Execution request must use the frozen execution entry"
            command = command_for(current["request"])
            if any(p.get("request") and command_for(p["request"]) == command for p in state["attempts"]):
                current["error"] = "与本 LEAF 先前未查清的执行内容完全相同，未重复执行；请修正方法或参数。"
        return {"current": current}

    def execute(state):
        current = deepcopy(state["current"])
        try:
            if gateway is None:
                raise RuntimeError("Execution session is not connected")
            observation = (gateway.execute_for(current["request"], leaf(state)) if hasattr(gateway, "execute_for")
                           else gateway.execute(current["request"]))
        except Exception as exc:
            # Keep the runtime's own named failure: without it a failed check is only
            # "PipelineFailure" and nothing can be diagnosed (observed live 2026-10-16,
            # run pipeline-live-20261016-36/rounds/006).
            observation = {"is_error": True, "error": type(exc).__name__, "response": None}
            if getattr(exc, "category", None):
                observation["category"] = exc.category
            if getattr(exc, "detail", None):
                observation["detail"] = exc.detail
        current["observation"] = observation
        return {"current": current}

    def prepare_assess(state):
        current = deepcopy(state["current"])
        messages = _messages(state["documents"]["assess"], {
            "node": state["context"]["node"], "leaf": leaf(state),
            "skills": [{k: v for k, v in card.items() if k != "score"}
                       for card in state["skills"][leaf(state)["id"]]],
            "request": current["request"], "observation": current["observation"]})
        current["assess_messages"] = messages_to_dict(messages)
        return {"current": current, "messages": messages_to_dict(messages)}

    def call_assess(state):
        response = _invoke(assess, state["messages"], Assessment)
        current = {**state["current"], "judgment": response}
        assessment = response["parsed"]
        error = response["error"]
        if assessment is not None and assessment["fact_id"] != leaf(state)["id"]:
            error = "判断返回了其他 LEAF 的编号"
        if current["observation"].get("is_error"):
            error = "MCP 调用未取得可靠结果；工具错误不能证明目标条件满足或不满足"
        if error:
            assessment = {"fact_id": leaf(state)["id"], "result": "未知", "reason": error}
            current["judgment"]["error"] = error
        current["assessment"] = assessment
        return {"current": current}

    def finish_attempt(state):
        current = deepcopy(state["current"])
        if current.get("error"):
            current["assessment"] = {"fact_id": leaf(state)["id"], "result": "未知", "reason": current["error"]}
        return {"current": current, "attempts": [*state["attempts"], current]}

    def record_leaf(state):
        row = {**state["current"]["assessment"], "policy": leaf(state)["policy"],
               "attempts": state["attempts"], "observed": bool(state["attempts"])
               and any(a.get("observation") for a in state["attempts"])}
        records = [*state["records"], row]
        position = state["position"] + 1
        if row["result"] == "不通过":
            records += [{"fact_id": item["id"], "result": "未检查", "reason": "先前 LEAF 明确失败，提前停止",
                         "policy": item["policy"], "attempts": [], "observed": False}
                        for item in state["context"]["leaves"][position:]]
            position = len(state["context"]["leaves"])
        return {"records": records, "position": position}

    def finish(state):
        values = [r["result"] for r in state["records"]]
        result = "不通过" if "不通过" in values else "未知" if "未知" in values else "通过"
        return {"result": {"node_id": state["context"]["node"]["id"], "result": result,
                "route": "post" if result == "不通过" else "action",
                "unknown_facts": [r["fact_id"] for r in state["records"] if r["result"] == "未知"],
                "reason": "明确前提失败，停止" if result == "不通过" else
                          "存在未知项，按约定放行" if result == "未知" else "Pre 检查完成",
                "execution_started": False}}

    graph = StateGraph(PreState)
    for name, fn in (("select", select), ("prepare", prepare), ("generate", call_generate),
                     ("execute", execute), ("prepare_assess", prepare_assess), ("assess", call_assess),
                     ("finish_attempt", finish_attempt), ("record_leaf", record_leaf), ("finish", finish)):
        graph.add_node(name, fn)
    graph.add_edge(START, "select")
    graph.add_conditional_edges("select", lambda s: s["current"]["stage"],
                                {"done": "finish", "record": "record_leaf", "generate": "prepare"})
    graph.add_edge("prepare", "generate")
    graph.add_conditional_edges("generate", lambda s: "invalid" if s["current"]["error"] else "valid",
                                {"invalid": "finish_attempt", "valid": "execute"})
    graph.add_edge("execute", "prepare_assess")
    graph.add_edge("prepare_assess", "assess")
    graph.add_edge("assess", "finish_attempt")
    graph.add_conditional_edges("finish_attempt", lambda s:
        "retry" if s["current"]["assessment"]["result"] == "未知" and len(s["attempts"]) < 3 else "record",
        {"retry": "prepare", "record": "record_leaf"})
    graph.add_edge("record_leaf", "select")
    graph.add_edge("finish", END)
    return graph.compile(checkpointer=checkpointer, interrupt_after=interrupt_after)
