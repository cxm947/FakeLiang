"""Tunnel contracts. TCP mappings cover exact IPv4 endpoints, never whole subnets."""

from ipaddress import IPv4Address
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from .execution_session import Nonempty, SessionReference

Port = Annotated[int, Field(ge=1, le=65535, strict=True)]
TunnelStatus = Literal["reserved", "starting", "active", "failed", "stale", "closed"]


class TunnelFailure(RuntimeError):
    pass


class TunnelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    run_id: Nonempty
    operation_id: Nonempty
    direction: Literal["access", "return"]
    pivot_host: Nonempty
    privilege: Nonempty
    session: SessionReference
    listen_host: IPv4Address
    target_host: IPv4Address
    target_port: Port
    source_node_id: Nonempty
    source_attempt: int = Field(ge=1, strict=True)

    @field_validator("listen_host", "target_host")
    @classmethod
    def concrete_address(cls, value):
        if value.is_unspecified or value.is_multicast or int(value) == 0xffffffff:
            raise ValueError("A concrete unicast IPv4 address is required")
        return value


class CleanupReceipt(BaseModel):
    """Owner attestation after checking this installation has stopped."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    run_id: Nonempty
    tunnel_id: Nonempty
    installation_id: Nonempty
    evidence: Nonempty
    cleaned_at: AwareDatetime


class TunnelRecord(TunnelRequest):
    tunnel_id: Nonempty
    installation_id: Nonempty
    local_port: Port
    status: TunnelStatus = "reserved"
    started: bool = False
    cleanup_receipt: CleanupReceipt | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime

    def request(self) -> TunnelRequest:
        return TunnelRequest.model_validate(self.model_dump(include=set(TunnelRequest.model_fields)))


class TunnelEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    tunnel_id: str
    host: IPv4Address
    port: Port
    target_host: IPv4Address
    target_port: Port
