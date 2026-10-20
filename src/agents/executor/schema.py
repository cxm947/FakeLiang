"""Action card and callback contracts. No execution methods live here."""

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
import yaml

from src.agents.pre_verifier.retrieval import Card
from src.agents.pre_verifier.schema import ExecutionRequest
from src.session.carrier import CarrierExport
from src.tools.schemas import (HttpRequestArgs, MsfJobArgs, RemoteProcessArgs,
                               CredentialTestArgs, RunCommandArgs, RunScriptArgs, ServeFileArgs,
                               SessionCommandArgs, StageFileArgs)


TOOL_ARGUMENTS = {
    "run_command": RunCommandArgs,
    "run_script": RunScriptArgs,
    "http_request": HttpRequestArgs,
    "stage_file": StageFileArgs,
    "session_command": SessionCommandArgs,
    "msf_job": MsfJobArgs,
    "credential_test": CredentialTestArgs,
    "serve_file": ServeFileArgs,
    "remote_process": RemoteProcessArgs,
}


class ActionExecutionRequest(BaseModel):
    """The Action stage's own request shape: the one the prompt and the cards describe.

    The Pre stage keeps its legacy four fields. Making Action reuse that schema while the
    prompt asked for ``tool/target/arguments`` let the model mix both shapes
    (``{"tool":"tool","name":"stage_file"}``), which the dispatcher then rejected
    (live 2026-10-18, node 26). One stage, one shape, and the arguments are validated
    against the same typed models the registry uses.
    """

    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)
    tool: Literal["run_command", "run_script", "http_request", "stage_file",
                  "session_command", "msf_job", "credential_test", "serve_file",
                  "remote_process"]
    target: Literal["kali", "session"]
    arguments: dict = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def accept_legacy(cls, data):
        """Translate a legacy four-field request into this shape.

        The fixtures and older recordings still speak ``tool/name/via/content``; accepting
        them here keeps one advertised shape without invalidating stored evidence. A
        structured ``content`` under the argv tool is left for the validator to reject.
        """
        if not isinstance(data, dict) or "arguments" in data:
            return data
        if str(data.get("tool") or "") == "tool" and isinstance(data.get("content"), dict):
            return data
        from src.tools.adapt import from_legacy
        try:
            request = from_legacy(data)
        except Exception:
            return data
        return {"tool": request.tool, "target": request.target,
                "arguments": request.arguments}

    @model_validator(mode="after")
    def arguments_match_tool(self):
        TOOL_ARGUMENTS[self.tool].model_validate(self.arguments)
        return self


class SkillSections(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)
    applicable_scenarios: str = Field(min_length=1)
    parameters: str = Field(min_length=1)
    steps: str = Field(min_length=1)
    completion_evidence: str = Field(min_length=1)
    failure_conditions: str = Field(min_length=1)


class DeliveryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)
    username: str = Field(min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    authorize_command: str = Field(min_length=1)


class DeliveryPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    kind: str = Field(min_length=1)
    format: str = Field(min_length=1)
    path: str = Field(min_length=1)


class DeliveryCapacity(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    max_bytes: int = Field(gt=0)
    source: str = Field(min_length=1)


class DeliveryCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    capacity: DeliveryCapacity
    shell_ready: bool


class DeliverySpec(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    transport: Literal["scp", "http"]
    entry: DeliveryEntry
    payload: DeliveryPayload
    capabilities: DeliveryCapabilities | None = None


class EntrySetup(BaseModel):
    """How the runtime establishes the channel this Action produces.

    The card declares the target-side authorization shape; the runtime supplies the run
    key and the public key. The model neither sees the key nor composes this command.
    """

    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)
    provider: Literal["ssh", "webshell"]
    username: str = Field(default="root", min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    #: SSH only: placeholders may use {public_key}, {public_key_file}, {key_path},
    #: {target_host}, {username}, {marker}.
    authorize_command: str = ""
    #: WebShell only: a concrete endpoint, or a template using {target_host}, {marker}.
    url_template: str = ""


class ActionSkillHeader(Card):
    delivery: DeliverySpec | None = None
    entry_setup: EntrySetup | None = None
    #: Where the channel this node produces comes from. ``runtime`` asks the deployment
    #: for the prepared listener and artifact; ``card`` means the card's own ``entry_setup``
    #: builds it after the Action; ``session`` reuses the attempt's registered session.
    #: Declaring it in the card keeps the runtime free of service-name tables.
    handover: Literal["runtime", "card", "session"] | None = None
    #: Deployment materials this card needs at the execution point, resolved by name
    #: against the run's pushed materials before the model sees the card.
    materials: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def card_handover_needs_an_entry_setup(self):
        """A card-owned channel must actually declare how it is established."""
        if self.handover == "card" and self.entry_setup is None:
            raise ValueError("handover=card requires entry_setup")
        return self
    #: Graph identifiers this card serves (service names and vulnerability ids taken from
    #: the input graph). Used to check applicability and to read a card's resource
    #: declaration -- never to pick a method on the runtime's behalf.
    serves: list[str] = Field(default_factory=list)


class ActionSkillCard(ActionSkillHeader):
    """Pre-style frontmatter followed by five concise Markdown sections."""

    sections: SkillSections

    @classmethod
    def from_markdown(cls, text):
        parts = text.split("---", 2)
        if len(parts) != 3 or parts[0].strip():
            raise ValueError("Missing skill YAML frontmatter")
        headings = {"适用场景": "applicable_scenarios", "参数": "parameters",
                    "步骤": "steps", "完成依据": "completion_evidence",
                    "失败条件": "failure_conditions"}
        blocks = re.split(r"^##\s+(.+?)\s*$", parts[2], flags=re.MULTILINE)
        sections = {}
        for title, content in zip(blocks[1::2], blocks[2::2]):
            field = headings.get(title.strip())
            if field:
                if field in sections:
                    raise ValueError("Duplicate skill section")
                sections[field] = content.strip()
        return cls.model_validate({**yaml.safe_load(parts[1]), "sections": sections})


class StepAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True, str_strip_whitespace=True)
    result: Literal["passed", "failed", "unknown"]
    action_complete: bool
    reason: str = Field(min_length=1)

    @model_validator(mode="after")
    def completion_requires_pass(self):
        if self.action_complete and self.result != "passed":
            raise ValueError("Only a passed step can complete the action")
        return self


class Observation(BaseModel):
    """Transport uncertainty is different from a completed command's failure."""

    model_config = ConfigDict(extra="forbid", strict=True)
    response: dict
    effect_known: bool
    #: New consumers read these; stored legacy observations simply omit them.
    receipt_confirmed: bool | None = None
    command_succeeded: bool | None = None


class ActionObservation(Observation):
    exported_carrier: CarrierExport | None = None
    exported_carriers: dict[str, CarrierExport] | None = None


__all__ = ["ActionSkillCard", "SkillSections", "ExecutionRequest", "StepAssessment", "Observation", "ActionObservation"]
