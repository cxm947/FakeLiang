"""The model-facing tool request: one tool, one target, typed arguments."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tool: str = Field(min_length=1)
    target: Literal["kali", "session"]
    arguments: dict

