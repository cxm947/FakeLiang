"""Provider contract shared by MSF, SSH and WebShell channels."""

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ProviderResult:
    ok: bool
    output: str = ""
    error_output: str = ""
    #: False when the surface answered but did not carry a string stdout field.
    output_reported: bool = True
    data: dict = field(default_factory=dict)
    error: str | None = None
    #: Transport facts are separate from ok: a command can be delivered and still be
    #: unconfirmed, and a failure is not automatically a timeout.
    timed_out: bool = False
    transport_error: bool = False
    #: Whether a terminal receipt came back for this write. A failed command can
    #: still be confirmed; an unanswered write cannot. ``None`` means the surface
    #: did not report it and ``ok`` is the legacy reading.
    receipt_confirmed: bool | None = None
    #: The command's own success flag when the surface reports one (process exit
    #: status, HTTP outcome the provider can interpret). ``None`` = unknown.
    command_succeeded: bool | None = None
    #: The surface's own exit status, when it reports one. The MCP bridge does;
    #: a meterpreter console does not.
    return_code: int | None = None


class ExecutionProvider(Protocol):
    name: str

    def execute(self, line: str, *, end_marker: str, timeout: float) -> ProviderResult: ...

    def console(self, command: str, *, timeout: float = 60.0) -> ProviderResult: ...

    def identity(self) -> dict: ...

    def close(self) -> None: ...
