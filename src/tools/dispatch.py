"""One entry point for a tool request: validate, build context, execute."""

from .adapt import from_legacy
from .capability import CapabilityRegistry
from .context import ToolContext
from .request import ToolRequest
from .tools import default_tools


def default_registry() -> CapabilityRegistry:
    value = CapabilityRegistry()
    for tool in default_tools():
        value.register(tool)
    return value


def execute_request(request, *, binding, backend=None, transports=None,
                    control=None, end_marker="agv-call-end", registry=None):
    tool_request = (ToolRequest.model_validate(request) if "arguments" in request
                    else from_legacy(request))
    ctx = ToolContext(binding, backend=backend, transports=transports,
                      end_marker=end_marker, control=control)
    return (registry or default_registry()).execute(
        tool_request.tool, tool_request.target, tool_request.arguments, ctx)

