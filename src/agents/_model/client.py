"""Provider configuration. Business retries belong to the Planner graph."""

import os
from pathlib import Path
from typing import Literal

import yaml
from langchain_deepseek import ChatDeepSeek
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, ConfigDict, Field, SecretStr

DEFAULT_CONFIG = Path(__file__).resolve().parents[3] / "configs" / "model.yaml"


class ModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    model: str = Field(min_length=1)
    provider: Literal["openai", "deepseek"] = "openai"
    base_url: str | None = None
    timeout: float = Field(default=30.0, gt=0)
    api_key_env: str = "OPENAI_API_KEY"
    api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)
    structured_method: Literal["json_mode", "json_schema", "function_calling"] | None = None
    reasoning_effort: Literal["low", "medium", "high"] | None = None
    thinking: Literal["enabled", "disabled"] | None = None
    max_tokens: int | None = Field(default=None, gt=0)
    temperature: float | None = Field(default=None, ge=0, le=2)


def load_model_config(path: Path | None = None):
    selected = Path(path) if path is not None else DEFAULT_CONFIG
    if path is not None or selected.exists():
        return ModelConfig.model_validate(yaml.safe_load(selected.read_text(encoding="utf-8")))
    name = os.environ.get("AGV_MODEL")
    if not name:
        raise ValueError("Configure configs/model.yaml or AGV_MODEL before calling a real model")
    return ModelConfig(model=name, base_url=os.environ.get("AGV_BASE_URL"))


def create_chat_model(config: ModelConfig | None = None):
    if config is None:
        config = load_model_config()
    options = {}
    if config.api_key is not None:
        options["api_key"] = config.api_key.get_secret_value()
    elif config.api_key_env != "OPENAI_API_KEY":
        key = os.environ.get(config.api_key_env)
        if not key:
            raise ValueError(f"Missing credential environment variable: {config.api_key_env}")
        options["api_key"] = key
    # DeepSeek's effort parameter can also enable thinking. Keep the explicit
    # disabled switch authoritative; retain the configured effort for enabled mode.
    if config.reasoning_effort is not None and not (
            config.provider == "deepseek" and config.thinking == "disabled"):
        options["reasoning_effort"] = config.reasoning_effort
    if config.thinking is not None:
        options["extra_body"] = {"thinking": {"type": config.thinking}}
    if config.max_tokens is not None:
        options["max_tokens"] = config.max_tokens
    if config.temperature is not None:
        options["temperature"] = config.temperature
    model_class = ChatDeepSeek if config.provider == "deepseek" else ChatOpenAI
    if config.base_url is not None:
        options["base_url"] = config.base_url
    return model_class(model=config.model, timeout=config.timeout, max_retries=0, **options)
