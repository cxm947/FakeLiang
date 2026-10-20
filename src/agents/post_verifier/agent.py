"""节点结果验证角色。"""

from copy import deepcopy
from pathlib import Path
import json

from src.orchestration.validation import _belongs, _identity, _node_record, _observation
from src.agents.prompting import load_prompt, render_messages
from src.orchestration.model import PASS, UNKNOWN

PROMPT_PATH = Path(__file__).with_name("prompts") / "post_verifier.yaml"


def load_messages(payload=None, *, phase=None, document=None, **variables):
    """Keep the offline regression renderer; live Post has distinct phases."""
    if phase is None:
        return render_messages(load_prompt(PROMPT_PATH), **variables)
    if phase not in {"generate", "assess"}:
        raise ValueError("Post phase must be generate or assess")
    path = PROMPT_PATH.with_name(f"{phase}.yaml")
    return render_messages(document if document is not None else load_prompt(path),
                           input_json=json.dumps(payload, ensure_ascii=False, indent=2))


class PostAgent:
    """Model judgments consume saved evidence; they never own execution."""

    def __init__(self, model, *, structured_method=None, documents=None):
        from .schema import Assessment, ExecutionRequest
        options = {"include_raw": True}
        if structured_method:
            options["method"] = structured_method
        self.documents = deepcopy(documents or {
            name: load_prompt(PROMPT_PATH.with_name(f"{name}.yaml"))
            for name in ("generate", "assess")})
        self.runnables = {phase: model.with_structured_output(schema.model_json_schema(), **options)
                          for phase, schema in {"generate": ExecutionRequest, "assess": Assessment}.items()}

    def _call(self, phase, payload):
        response = self.runnables[phase].invoke(load_messages(
            payload, phase=phase, document=self.documents[phase]))
        raw = response.get("raw")
        if response.get("parsing_error") or raw is not None and (
                raw.invalid_tool_calls or len(raw.tool_calls) > 1):
            return raw.content if raw is not None else None
        if raw is not None and not raw.tool_calls:
            try:
                return json.loads(raw.content)
            except (ValueError, TypeError):
                return raw.content
        return response.get("parsed")

    def generate(self, payload):
        return self._call("generate", payload)

    def assess(self, payload):
        return self._call("assess", payload)


def post(context):
    base = {"facts": [], "evidence": [], "result": UNKNOWN, "reason": "验证未知"}
    if context["pre"]["result"] != PASS:
        return {**base, "result": context["pre"]["result"],
                "reason": context["pre"]["reason"], "evidence": deepcopy(context["pre"]["evidence"])}
    if context.get("timed_out"):
        return {**base, "reason": "验证到限"}
    raw = context["raw"]
    versions = context["fact_versions"]
    if (not _node_record(raw, context["node_id"], "AND", ("ended",))
            or not _observation(raw.get("evidence")) or not _belongs(raw, context, versions)):
        return {**base, "reason": "依据验证未知"}
    expected = context["outputs"]
    record = context.get("record")
    if len(expected) != 1:
        return base
    fid = expected[0]
    if (not _node_record(record, fid, "OR")
            or record.get("evidence") != f"nodes/{context['node_id']}/action"
            or context["known"].get(fid) is not True or fid not in versions
            or not _belongs(record, context, versions[fid])):
        return {**base, "reason": "依据验证未知"}
    value = record["result"]
    identity = _identity(context, fid, versions)
    basis = {"observed": record["返回的结果"], "reference": record["evidence"],
             "验证该节点的skill": record["验证该节点的skill"]}
    action_basis = {"observed": raw["返回的结果"], "evidence": raw["evidence"],
                    "验证该节点的skill": raw["验证该节点的skill"]}
    confirmed = {"fact_id": fid, "result": value, "valid": True, **deepcopy(basis),
                 "evidence": [action_basis, deepcopy(basis)], **identity}
    evidence = {"fact_id": fid, "result": value, "evidence": deepcopy(basis), **identity}
    return {"result": value, "reason": "验证" + value, "facts": [confirmed], "evidence": [evidence]}
