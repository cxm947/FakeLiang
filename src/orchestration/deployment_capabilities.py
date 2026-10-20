"""Fail-fast declaration of the deployment the runtime is allowed to assume.

The declaration is not a second source of truth for targets: it is the boundary the
configuration must satisfy. A profile names the VMs, address ranges, controller paths,
port pool and lab lock; the live runtime refuses to start when the loaded request/lab
config disagrees. This is what prevents a copied config from silently pointing at a
different range or a stale snapshot.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.session.pipeline_service import PipelineFailure


class DeploymentCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    vms: list[str] = Field(min_length=1)
    cidrs: list[str] = Field(min_length=1)
    controller_paths: list[str] = Field(min_length=1)
    port_pool: dict = Field(default_factory=dict)
    locks: dict[str, str] = Field(default_factory=dict)

    @field_validator("cidrs")
    @classmethod
    def valid_cidrs(cls, values):
        for value in values:
            ip_network(value, strict=False)
        return values


def _inside(path: str, roots: list[str]) -> bool:
    value = str(path or "")
    return any(value == root or value.startswith(root.rstrip("/") + "/") for root in roots)


def validate_deployment_capabilities(profile, *, request, lab, materials,
                                     owner_options, port_start, port_end):
    """Refuse a run whose loaded config no longer matches its declared profile."""
    declared_vms = set(profile.vms)
    actual_vms = {str(row["vm"]) for row in lab.get("snapshots", [])}
    if declared_vms != actual_vms:
        raise PipelineFailure("?????", "deployment_capability_vms_mismatch")

    networks = [ip_network(value, strict=False) for value in profile.cidrs]
    for host in request.get("document", {}).get("hosts", []):
        for address in host.get("ips", []):
            if not any(ip_address(address) in network for network in networks):
                raise PipelineFailure("?????", "deployment_capability_cidr_mismatch")

    roots = [str(value).rstrip("/") for value in profile.controller_paths]
    for item in materials or []:
        if not _inside(str(item.get("remote_path") or ""), roots):
            raise PipelineFailure("?????", "deployment_capability_material_path_mismatch")
    delivery = (owner_options or {}).get("delivery") or {}
    for key in ("key_path", "stager_path"):
        value = str(delivery.get(key) or "")
        if value and not _inside(value, roots):
            raise PipelineFailure("?????", "deployment_capability_material_path_mismatch")

    pool = profile.port_pool or {}
    if pool.get("start") != port_start or pool.get("end") != port_end:
        raise PipelineFailure("?????", "deployment_capability_port_pool_mismatch")
    if profile.locks.get("lab") and profile.locks["lab"] != str(lab.get("lock") or ""):
        raise PipelineFailure("?????", "deployment_capability_lock_mismatch")
    return True


__all__ = ["DeploymentCapabilities", "validate_deployment_capabilities"]
