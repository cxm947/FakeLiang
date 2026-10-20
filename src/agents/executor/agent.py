"""Two-phase Action model adapter for ActionWorkflow callbacks."""

from copy import deepcopy
import json
from pathlib import Path

from src.agents.prompting import load_prompt, render_messages
from .schema import ActionExecutionRequest, StepAssessment

PROMPT_PATH = Path(__file__).with_name("prompts") / "executor.yaml"
SCHEMAS = {"generate": ActionExecutionRequest, "assess": StepAssessment}


def load_messages(payload, *, phase, document=None):
    if phase not in SCHEMAS:
        raise ValueError("Action phase must be generate or assess")
    return render_messages(document if document is not None else load_prompt(PROMPT_PATH),
        phase=phase, input_json=json.dumps(payload, ensure_ascii=False, indent=2),
        output_schema=json.dumps(SCHEMAS[phase].model_json_schema(), ensure_ascii=False),
        # The tool list is rendered from the same registry the dispatcher uses, so a tool
        # that exists there always appears in the prompt with its own argument schema.
        tool_manifest=_tool_manifest())


def _tool_manifest() -> str:
    # Imported here: the tools package reaches the orchestration layer, which imports this
    # module, so a top-level import would be circular.
    from src.tools.dispatch import default_registry
    from src.tools.manifest import render_manifest_text
    return render_manifest_text(default_registry())


class ActionAgent:
    """Inject generate/assess into the loop; execution remains a separate callback.

    Invalid model output is returned to the workflow for bounded correction.
    Provider exceptions propagate so a saved execution result is not replayed.
    """

    def __init__(self, model, *, structured_method=None, document=None):
        self.document = deepcopy(document if document is not None else load_prompt(PROMPT_PATH))
        options = {"include_raw": True}
        if structured_method is not None:
            options["method"] = structured_method
        self.runnables = {phase: model.with_structured_output(schema.model_json_schema(), **options)
                          for phase, schema in SCHEMAS.items()}

    def _call(self, phase, payload):
        response = self.runnables[phase].invoke(load_messages(payload, phase=phase, document=self.document))
        raw = response.get("raw")
        if (response.get("parsing_error") or
                raw is not None and (raw.invalid_tool_calls or len(raw.tool_calls) > 1)):
            # Preserve invalid content, not the model-message envelope or provider error.
            return raw.content if raw is not None else None
        return response.get("parsed")

    def generate(self, payload):
        return self._call("generate", payload)

    def assess(self, payload):
        return self._call("assess", payload)


def action(payload, *, phase, model, structured_method=None):
    """One explicit model phase. Reuse ActionAgent for a multi-step workflow."""
    if phase not in SCHEMAS:
        raise ValueError("Action phase must be generate or assess")
    agent = ActionAgent(model, structured_method=structured_method)
    return getattr(agent, phase)(payload)
