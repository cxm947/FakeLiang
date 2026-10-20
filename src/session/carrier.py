"""Owner-issued carrier export shared by Action, Post and session closeout."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .execution_session import Nonempty, SessionReference
from .session_closeout import UnifiedChannel
from .session_migration import AuthorizedConnectionEntry, RemoteCommandEntry


class CarrierReference(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    ref: str = Field(min_length=1)
    kind: Literal["msf", "ssh", "web", "one_shot", "unknown"]
    owner: str = Field(min_length=1)
    handle: str = Field(min_length=1)
    target_host: str = Field(min_length=1)
    #: The address the owner observed for this carrier, when its channel reports one.
    #: It is an observation of the same resource, not a second identity of it.
    address: str | None = None
    source_node_id: str = Field(min_length=1)
    source_attempt_id: str | None = None
    generation: str | None = None
    #: The platform of the session behind this carrier, as its own channel reports it. A
    #: consumer that has to speak to the channel needs it: the node's execution face may sit
    #: on a different platform than the session (evidence: a Windows carrier was probed with
    #: POSIX statements from a Linux face, output/pipeline-live-20261016-53/rounds/003).
    platform: str = ""
    lifecycle: Literal["unknown", "available", "closed", "revoked", "expired"] = "unknown"


class CarrierExport(BaseModel):
    """Only an execution owner may issue this receipt, never a model verdict."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    carrier: CarrierReference
    privilege: Nonempty
    identity_aliases: list[Nonempty] = Field(default_factory=list)
    channel: Annotated[UnifiedChannel | RemoteCommandEntry | AuthorizedConnectionEntry,
                       Field(discriminator="kind")]
    # Provider and incarnation travel with S, including non-managed channels.
    reference: SessionReference | None = None

    @model_validator(mode="after")
    def pin_reference(self):
        if self.channel.reference is not None:
            if self.reference is not None and self.reference != self.channel.reference:
                raise ValueError("Candidate reference differs from channel")
            object.__setattr__(self, "reference", self.channel.reference)
        if self.channel.kind != "unified" and self.channel.provider is not None and (
                self.channel.provider != self.carrier.owner):
            raise ValueError("Candidate provider differs from channel")
        if self.reference is not None and self.carrier.generation is not None and (
                str(self.reference.generation) != self.carrier.generation):
            raise ValueError("Candidate generation differs from reference")
        return self


def child_candidates(state, outputs):
    """Normalize old single receipts and new per-child receipts without choosing a session."""
    from src.graph.predicates import parse_parameters
    facts = {str(f["id"]): f for f in outputs
             if str(f.get("description", "")).partition("(")[0].strip() == "execCode"}
    values = state.get("session_candidates") or {}
    if values and state.get("session_candidate") is not None:
        old = CarrierExport.model_validate(state["session_candidate"])
        if not any(CarrierExport.model_validate(value) == old for value in values.values()):
            raise ValueError("Candidate host and privilege or reference conflicts with child mapping")
    if not values and state.get("session_candidate") is not None:
        old = CarrierExport.model_validate(state["session_candidate"])
        values = {key: old for key, fact in facts.items()
                  if (parse_parameters(fact["description"])["host"],
                      parse_parameters(fact["description"])["user"]) ==
                     (old.carrier.target_host, old.privilege)}
        if not values:
            raise ValueError("Candidate does not match any execCode child")
    if set(values) - set(facts):
        raise ValueError("Candidate references a non-executable child")
    result = {}
    for key, value in values.items():
        candidate = CarrierExport.model_validate(value)
        params = parse_parameters(facts[key]["description"])
        if (candidate.carrier.target_host, candidate.privilege) != (params["host"], params["user"]):
            raise ValueError("Candidate target or privilege differs from child")
        result[key] = candidate.model_dump()
    return result
