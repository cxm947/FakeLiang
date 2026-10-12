"""YAML/Jinja assembly without model construction or dispatch."""
import json
from importlib.resources import files

import yaml
from jinja2 import Environment, StrictUndefined, meta
from jsonschema import Draft202012Validator

SCOPE = ("run_id", "node_id", "attempt_id", "agent_role")
ENV = Environment(undefined=StrictUndefined, autoescape=False,
                  keep_trailing_newline=True)
SCHEMA = {
    "type": "object",
    "properties": {"version": {"const": 1},
                   "template": {"type": "string"}},
    "required": ["version", "template"],
    "additionalProperties": False,
}


def fragment(package, resource):
    name = resource.rsplit("/", 1)[-1].removesuffix(".txt") + ".yaml"
    raw = files(package).joinpath("templates", name).read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    Draft202012Validator(SCHEMA).validate(data)
    return data["template"]


def check_scope(scope, memory, local_inputs):
    if set(scope) != set(SCOPE):
        raise ValueError("MEMORY_SCOPE_INVALID")
    if any(not isinstance(scope[k], str) or not scope[k] for k in SCOPE):
        raise ValueError("MEMORY_SCOPE_INVALID")
    if memory.get("scope") != scope or local_inputs.get("scope") != scope:
        raise ValueError("MEMORY_SCOPE_MISMATCH")


def recent_pairs(recent):
    from langchain_core.messages import AIMessage, ToolMessage, convert_to_messages
    messages = convert_to_messages(recent)
    pending, seen = set(), set()
    for message in messages:
        if isinstance(message, AIMessage):
            if pending or message.invalid_tool_calls or not message.tool_calls:
                raise ValueError("HISTORY_PAIR_INVALID")
            ids = [call.get("id") for call in message.tool_calls]
            if any(not isinstance(x, str) or not x for x in ids):
                raise ValueError("HISTORY_PAIR_INVALID")
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise ValueError("HISTORY_PAIR_INVALID")
            pending = set(ids)
            seen.update(ids)
        elif isinstance(message, ToolMessage):
            if message.tool_call_id not in pending:
                raise ValueError("HISTORY_PAIR_INVALID")
            pending.remove(message.tool_call_id)
        else:
            raise ValueError("HISTORY_ROLE_INVALID")
    if pending:
        raise ValueError("HISTORY_PAIR_INCOMPLETE")
    return messages


def assemble(request):
    from langchain_core.messages import (
        SystemMessage, HumanMessage, convert_to_openai_messages,
    )
    scope = request["scope"]
    memory, local = request["memory"], request["local_inputs"]
    check_scope(scope, memory, local)
    resources = {
        "executor": ("agents.executor", "system.txt"),
        "planner": ("agents.planner", "walk_system.txt"),
        "verifier": ("agents.verifier", "runtime_system.txt"),
    }
    role = scope["agent_role"].split(".", 1)[0]
    if role not in resources:
        raise ValueError("PROMPT_ROLE_INVALID")
    package, source = resources[role]
    raw = files(package).joinpath("templates", "assembly.yaml").read_text(
        encoding="utf-8")
    config = yaml.safe_load(raw)
    expected = {"version", "protocol", "variables",
                "system_template", "user_template"}
    if set(config) != expected or config["version"] != 1:
        raise ValueError("PROMPT_CONFIG_INVALID")
    if config["protocol"] != "legacy-json":
        raise ValueError("PROMPT_PROTOCOL_INVALID")
    values = {
        "base_system": fragment(package, "templates/" + source),
        "skill_text": request.get("skill_text", ""),
        "local_inputs_json": json.dumps(local, ensure_ascii=False, sort_keys=True),
        "history_summary_json": json.dumps(memory.get("summary", {}),
                                          ensure_ascii=False, sort_keys=True),
    }
    used = set()
    for key in ("system_template", "user_template"):
        used |= meta.find_undeclared_variables(ENV.parse(config[key]))
    if set(config["variables"]) != used or used != set(values):
        raise ValueError("PROMPT_VARIABLES_INVALID")
    messages = [
        SystemMessage(content=ENV.from_string(config["system_template"]).render(values)),
        HumanMessage(content=ENV.from_string(config["user_template"]).render(values)),
        *recent_pairs(memory.get("recent_messages", [])),
    ]
    if request.get("tools"):
        raise ValueError("BATCH1_TOOLS_NOT_ENABLED")
    return {"protocol": "legacy-json",
            "messages": convert_to_openai_messages(messages), "tools": []}
