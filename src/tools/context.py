"""Tool execution context: resolves target to a provider and exposes control actions."""

from .providers.kali import KaliProvider
from .providers.resolve import provider_for


class ToolContext:
    def __init__(self, binding, *, backend=None, transports=None,
                 end_marker="agv-call-end", control=None):
        self.binding = (binding if isinstance(binding, dict)
                        else binding.model_dump(exclude_none=True))
        self.backend = backend
        self.transports = transports
        self.end_marker = end_marker
        self._control = control

    def provider_for(self, target: str):
        if target == "kali" or self.binding.get("binding_kind") == "controller_entry":
            return KaliProvider(self.binding, self.transports)
        return provider_for(self.binding, backend=self.backend,
                            transports=self.transports)

    def platform_for(self, target: str) -> str:
        if target == "kali":
            return "linux"
        return str(self.binding.get("platform") or "linux")

    def control(self, name: str, arguments: dict):
        if self._control is None:
            raise RuntimeError("no control action is wired")
        return self._control(name, arguments)
