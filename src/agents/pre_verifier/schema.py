"""Small, strict model contracts for the two Pre phases."""

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.tools.schemas import (CredentialTestArgs, RunCommandArgs, RunScriptArgs,
                               SessionCommandArgs)


class StageExecutionRequest(BaseModel):
    """Pre/Post's request shape: the same ``{tool, target, arguments}`` as Action."""

    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)
    tool: Literal["run_command", "run_script", "session_command", "credential_test"]
    target: Literal["kali", "session"]
    arguments: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def arguments_match_tool(self):
        models = {"run_command": RunCommandArgs, "run_script": RunScriptArgs,
                  "session_command": SessionCommandArgs,
                  "credential_test": CredentialTestArgs}
        models[self.tool].model_validate(self.arguments)
        return self


class ExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    #: ``session`` is the bound channel's own console language (for example a migrated
    #: meterpreter's command set). ``cmd``/``code``/``tool`` keep their previous shape.
    tool: Literal["cmd", "code", "tool", "session"]
    name: str = Field(min_length=1, pattern=r"^[A-Za-z0-9_.+-]+$")
    #: ``kali`` is the run's own entry; ``session`` is the one channel this node is bound to.
    #: There is no third face: a request that cannot reach a registered session is refused.
    via: Literal["kali", "session"]
    content: str | list[str] | dict

    @model_validator(mode="before")
    @classmethod
    def accept_tool_contract(cls, data):
        from src.tools.adapt import to_legacy_request
        return to_legacy_request(data)

    @model_validator(mode="after")
    def content_matches_kind(self):
        if self.tool == "session":
            if not isinstance(self.content, dict) or not isinstance(
                    self.content.get("command"), str) or not self.content["command"].strip():
                raise ValueError("session content requires a nonempty command string")
            if "\n" in self.content["command"].strip():
                raise ValueError("a session console command is one line")
            return self
        if self.tool == "tool":
            if not isinstance(self.content, list):
                raise ValueError("tool content must be an argv array")
        elif not isinstance(self.content, str) or not self.content.strip():
            raise ValueError("cmd/code content must be nonempty text")
        if self.tool == "code" and self.name not in {"python3", "bash", "sh", "powershell"}:
            raise ValueError("Unsupported code interpreter")
        if "\x00" in self.content or any("\x00" in s for s in self.content):
            raise ValueError("NUL is not executable content")
        return self


class Assessment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    fact_id: str = Field(min_length=1)
    result: Literal["通过", "不通过", "未知"]
    reason: str | None

    @model_validator(mode="after")
    def explain_nonpass(self):
        if self.result != "通过" and (not self.reason or not self.reason.strip()):
            raise ValueError("Failure and unknown require a reason")
        return self
