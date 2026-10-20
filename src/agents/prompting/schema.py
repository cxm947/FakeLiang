"""Versioned YAML contract, validated with Pydantic rather than coercion."""

from pydantic import BaseModel, ConfigDict, Field


class PromptDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: int = Field(ge=1, le=1)
    system_template: str
    user_template: str


def validate_prompt(document):
    """验证角色依据的版本与正文。"""
    PromptDocument.model_validate(document)
    return document
