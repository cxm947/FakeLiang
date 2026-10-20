"""Execution-session data contracts shared by Pre and Action; no transport data."""

from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


Nonempty = Annotated[str, Field(min_length=1)]
SessionStatus = Literal["active", "stale", "closed"]


class SessionReference(BaseModel):
    """Resolve once per node attempt and pass this same reference to Pre/Action.

    The instance and generation pin the carrier incarnation, even if the host's
    current session later changes. Resolving a reference does not open a channel.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    session_id: Nonempty
    instance_id: Nonempty
    generation: int = Field(ge=1, strict=True)


BindingKind = Literal["console_session", "controller_entry"]


class SessionRegistration(SessionReference):
    #: A console session is observed through the session backend; a controller entry is the
    #: run's own starting context and is confirmed by the owner, not by the session list.
    binding_kind: BindingKind = "console_session"
    run_id: Nonempty
    operation_id: Nonempty
    host: Nonempty
    privilege: Nonempty
    #: The address the console reported for this session when it was claimed; an
    #: observation, never a copy of the graph's expected address. Entry bindings
    #: have none.
    observed_address: str | None = None
    source_node_id: Nonempty
    source_attempt: int = Field(ge=1, strict=True)
    #: What serves this channel: msf / ssh / webshell. Defaults to msf for older records.
    provider: str | None = None
    ssh_key_path: str | None = None
    ssh_port: int | None = None
    webshell_url: str | None = None
    webshell_parameter: str | None = None


class ExecutionBinding(BaseModel):
    """One frozen input shared verbatim by Pre and Action for an attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    session: SessionReference
    #: ``kali`` is the run's starting entry; ``session`` is a registered channel. No other
    #: execution face exists, so a missing session is a refusal, not a fallback.
    via: Literal["kali", "session"]
    host: Nonempty
    #: Frozen addresses of ``host``. A console reports an address while the graph
    #: keeps the logical name, so identity checks accept either form.
    addresses: list[Nonempty] = Field(default_factory=list)
    identity: Nonempty
    platform: Literal["linux", "windows"]
    binding_kind: BindingKind = "console_session"
    tunnel_endpoints: list[dict] = Field(default_factory=list)
    #: What actually carries the command: meterpreter/shell for a console session, kali for
    #: the run's own entry. Optional so older frozen bindings remain valid.
    carrier: str | None = None
    #: The provider that owns the transport: msf / ssh / webshell / kali.
    provider: str | None = None
    ssh_key_path: str | None = None
    ssh_port: int | None = None
    webshell_url: str | None = None
    webshell_parameter: str | None = None


class SessionRecord(SessionRegistration):
    status: SessionStatus
    registered_at: AwareDatetime
    updated_at: AwareDatetime | None = None
    watch_reason: str | None = None

    def reference(self) -> SessionReference:
        return SessionReference(session_id=self.session_id, instance_id=self.instance_id,
                                generation=self.generation)


class SessionResolutionFailure(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    reason: Literal["node_not_found", "invalid_graph", "ancestor_not_found",
                    "ambiguous_ancestor", "session_not_found", "ambiguous_session",
                    "mixed_runs"]
    node_id: str


SessionResolution = SessionReference | SessionResolutionFailure
