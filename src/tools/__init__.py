"""Tool registry, typed arguments and prompt manifest."""

from .capability import CapabilityRegistry, ToolResult
from .tools import default_tools

__all__ = ["CapabilityRegistry", "ToolResult", "default_tools"]

