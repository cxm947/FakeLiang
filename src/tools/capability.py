"""Small tool/capability layer: typed arguments, registry, manifest."""

from dataclasses import dataclass, field
from typing import Protocol

from pydantic import BaseModel


@dataclass
class ToolResult:
    ok: bool
    output: str = ""
    data: dict = field(default_factory=dict)
    error: str | None = None


class Capability(Protocol):
    name: str
    description: str
    args_model: type[BaseModel]
    example: dict

    def execute(self, target: str, args: BaseModel, ctx) -> ToolResult: ...


class CapabilityRegistry:
    """One registry per stage; tool names are unique within it."""

    def __init__(self):
        self._tools: dict[str, Capability] = {}

    def register(self, tool: Capability):
        if tool.name in self._tools:
            raise ValueError("duplicate tool: " + tool.name)
        self._tools[tool.name] = tool
        return tool

    def get(self, name: str) -> Capability:
        try:
            return self._tools[name]
        except KeyError:
            raise KeyError("unknown tool: " + str(name)) from None

    def names(self) -> list[str]:
        return sorted(self._tools)

    def manifest(self) -> list[dict]:
        # The example is shown to the model as a complete request, so it carries the tool
        # field too; an example that cannot be validated teaches a wrong shape.
        return [{"name": tool.name, "description": tool.description,
                 "schema": tool.args_model.model_json_schema(),
                 "example": {"tool": tool.name, **tool.example}}
                for tool in self._tools.values()]

    def execute(self, name: str, target: str, arguments: dict, ctx) -> ToolResult:
        if target not in {"kali", "session"}:
            raise ValueError("target must be kali or session")
        tool = self.get(name)
        args = tool.args_model.model_validate(arguments or {})
        return tool.execute(target, args, ctx)
