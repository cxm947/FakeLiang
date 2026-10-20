"""Stateless model decisions with a compiled LangGraph correction loop."""

from copy import deepcopy
import json
from pathlib import Path
from datetime import datetime, timezone
from time import perf_counter
from typing import TypedDict, Any

from langchain_core.messages import HumanMessage
from langchain_core.messages import messages_from_dict
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, START, END
from pydantic import ValidationError

from src.agents.prompting import load_prompt, render_messages
from .schema import PlannerInput, PlannerDecision
from .validation import INVALID, check_decision

PROMPT_PATH = Path(__file__).with_name("prompts") / "planner.yaml"


class PlannerExhausted(RuntimeError):
    def __init__(self, attempts):
        super().__init__("Planner 首次调用及两次纠错均未通过")
        self.attempts = attempts


class PlannerBudgetExceeded(RuntimeError):
    """The caller's run budget expired before another model request."""


class ModelCallInterrupted(RuntimeError):
    """A transport error without provider bodies or credentials in storage."""


class PlannerState(TypedDict):
    context: dict
    attempts: list[dict]
    response: Any
    error: dict | None
    decision: dict | None
    request_messages: list[dict]
    run: dict
    calls: list[dict]


def load_messages(**variables):
    return render_messages(load_prompt(PROMPT_PATH), **variables)


def load_planner_prompt():
    return load_prompt(PROMPT_PATH)["system_template"]


def build_input(graph, node_states, post_records):
    previous_results = [
        {"node_id": node["id"], "结果": node_states[str(node["id"])]["result"]}
        for node in graph["nodes"]
        if node_states[str(node["id"])]["terminal_record"] is not None
    ]
    previous_id = post_records[-1]["node_id"] if post_records else None
    last_result = next((row for row in previous_results if row["node_id"] == previous_id), None)
    return deepcopy({
        "graph": {"nodes": [{"id": n["id"], "type": n["type"]} for n in graph["nodes"]
                              if n["id"] not in graph["final_goal"]],
                  "edges": [{"src": e["src"], "dst": e["dst"]} for e in graph["edges"]],
                  "final_goal": graph["final_goal"]},
        "previous_results": previous_results, "last_result": last_result,
    })


def _raw(response):
    raw = response.get("raw")
    if raw is None:
        return None
    return {"content": raw.content, "tool_calls": raw.tool_calls,
            "invalid_tool_calls": raw.invalid_tool_calls}


def _pack(response):
    """Only JSON data crosses a durable checkpoint, never parser exceptions."""
    parsed = response.get("parsed")
    raw = response.get("raw")
    return {"parsed": parsed.model_dump() if isinstance(parsed, PlannerDecision) else parsed,
            "raw": _raw(response),
            "parsing_error": str(response["parsing_error"]) if response.get("parsing_error") else None,
            "usage": getattr(raw, "usage_metadata", None)}


def build_planner(model, *, admitted=(), structured_method=None, attempt_log=None, before_attempt=None,
                  checkpointer=None, document=None):
    """Use one model invocation per attempt; no algorithmic fallback."""
    options = {"include_raw": True}
    if structured_method is not None:
        options["method"] = structured_method
    # Send the generated schema rather than the class: native SDK eager
    # Pydantic parsing can raise before include_raw captures a malformed reply.
    # The strict Pydantic boundary below owns validation in both provider modes.
    structured = (model.with_structured_output(PlannerDecision.model_json_schema(), **options)
                  if model is not None else None)
    document = document or load_prompt(PROMPT_PATH)
    prompt = ChatPromptTemplate.from_messages([
        ("system", document["system_template"]),
        ("human", document["user_template"]),
    ], template_format="jinja2")
    admitted = frozenset(admitted)

    def prepare(state):
        messages = prompt.invoke({"input_json": json.dumps(state["context"], ensure_ascii=False, indent=2)}).to_messages()
        if state["attempts"]:
            previous = state["attempts"][-1]
            correction = {"retry": len(state["attempts"]), "max_retries": 2,
                          "previous_response": previous["response"], "error": previous["error"]}
            messages.append(HumanMessage(content=json.dumps(correction, ensure_ascii=False)))
        # Transport/configuration errors propagate; they are not model decisions.
        request_messages = [{"role": "user" if message.type == "human" else message.type,
                             "content": message.content} for message in messages]
        result = {"request_messages": request_messages}
        if "run" in state:
            result["calls"] = [*state.get("calls", []), {
                "attempt": len(state["attempts"]) + 1,
                "request_messages": request_messages,
                "prepared_at": datetime.now(timezone.utc).isoformat(),
                "status": "prepared", "response": None}]
        return result

    def call_model(state):
        if before_attempt is not None:
            before_attempt()
        messages = messages_from_dict([
            {"type": "human" if m["role"] == "user" else m["role"],
             "data": {"content": m["content"]}} for m in state["request_messages"]])
        start = perf_counter()
        try:
            if structured is None:
                raise RuntimeError("A model is required to execute this graph")
            response = _pack(structured.invoke(messages))
        except Exception as exc:
            if "run" in state:
                raise ModelCallInterrupted(type(exc).__name__) from None
            raise
        result = {"response": response}
        if "run" in state:
            calls = deepcopy(state["calls"])
            calls[-1].update(status="responded", response=response,
                elapsed_seconds=perf_counter() - start,
                finished_at=datetime.now(timezone.utc).isoformat())
            result["calls"] = calls
        return result

    def validate(state):
        response = state["response"]
        error, decision = None, None
        try:
            parsed = response.get("parsed")
            raw = response.get("raw")
            if raw is not None and len(raw["tool_calls"]) > 1:
                raise ValueError("每次只能返回一个选择，不能包含多个结构化调用。")
            if raw is not None and raw["invalid_tool_calls"]:
                raise ValueError("结构化调用参数不是合法 JSON。")
            if response.get("parsing_error") is not None or parsed is None:
                detail = str(response.get("parsing_error") or "响应为空或无法按输出契约解析。")
                raise ValueError(detail)
            if raw is not None and not raw["tool_calls"] and isinstance(raw["content"], str):
                # LangChain's JSON parser permits partial JSON for streaming;
                # a final decision must instead be a complete JSON document.
                parsed = json.loads(raw["content"])
            decision = PlannerDecision.model_validate(
                parsed.model_dump() if isinstance(parsed, PlannerDecision) else parsed)
            error = check_decision(PlannerInput.model_validate(state["context"]), decision, admitted)
        except (ValidationError, ValueError, TypeError) as exc:
            error = {"category": INVALID, "detail": str(exc)}
        record = {"attempt": len(state["attempts"]) + 1, "response": response.get("raw"),
                  "request_messages": state["request_messages"],
                  "decision": decision.model_dump() if decision else None, "error": error}
        if attempt_log is not None:
            attempt_log.append(deepcopy(record))
        return {"attempts": [*state["attempts"], record], "error": error,
                "decision": decision.model_dump() if decision and error is None else None}

    graph = StateGraph(PlannerState)
    graph.add_node("prepare", prepare)
    graph.add_node("call_model", call_model)
    graph.add_node("validate", validate)
    graph.add_edge(START, "prepare")
    graph.add_edge("prepare", "call_model")
    graph.add_edge("call_model", "validate")
    graph.add_conditional_edges("validate", lambda state:
        "retry" if state["error"] is not None and len(state["attempts"]) < 3 else "done",
        {"retry": "prepare", "done": END})
    return graph.compile(checkpointer=checkpointer)


def planner(context, *, model=None, admitted=(), trace=None, structured_method=None, before_attempt=None):
    validated = PlannerInput.model_validate(context).model_dump()
    if model is None:
        from src.agents._model.client import create_chat_model, load_model_config
        config = load_model_config()
        model = create_chat_model(config)
        if structured_method is None:
            structured_method = config.structured_method
    result = build_planner(model, admitted=admitted, structured_method=structured_method,
                          attempt_log=trace, before_attempt=before_attempt).invoke(
        {"context": validated, "attempts": [], "response": None, "error": None, "decision": None,
         "request_messages": []},
        config={"recursion_limit": 20})
    if result["error"] is not None:
        raise PlannerExhausted(result["attempts"])
    return result["decision"]
