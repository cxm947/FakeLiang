"""One place that turns a registered session record plus a node entry into a binding.

Pre, Action and Post all receive the same frozen ``ExecutionBinding``. Two call sites
used to assemble it separately (the pipeline service and the single-node driver), which
let their optional fields, provider default and endpoint shape drift apart. This module
is the single builder; both call sites dump it with ``exclude_none=True`` so the frozen
input is identical in evidence and in the next stage.
"""

from __future__ import annotations

from .execution_session import ExecutionBinding, SessionRecord

#: Optional transport fields a provider-owned channel may carry.
PROVIDER_FIELDS = ("ssh_key_path", "ssh_port", "webshell_url", "webshell_parameter")


def provider_for_record(record):
    """The run's own entry is the kali provider; every other record names its provider."""
    if record.binding_kind == "controller_entry":
        return "kali"
    return str(record.provider or "msf")


def execution_binding(record, *, entry=None, addresses=(), endpoints=()) -> ExecutionBinding:
    """Build the one frozen binding every stage sees for this attempt.

    ``entry`` is the deployment's per-node declaration (``via`` / ``platform`` and any
    node-specific inputs). It may override the provider; it may not invent a session.
    """
    values = dict(entry or {})
    values.setdefault("provider", provider_for_record(record))
    for key in PROVIDER_FIELDS:
        value = getattr(record, key, None)
        if value is not None and not values.get(key):
            values[key] = value
    return ExecutionBinding(
        session=record.reference(),
        host=record.host,
        identity=record.privilege,
        addresses=sorted({str(value) for value in addresses if str(value).strip()}),
        binding_kind=record.binding_kind,
        tunnel_endpoints=list(endpoints or ()),
        **values)


def same_subject(binding, target, target_addresses=()):
    """Whether commands on this binding describe ``target`` itself.

    The graph keeps logical names while a console reports addresses, so identity is
    name-or-address, never a string comparison alone. A controller entry runs on the
    run's own control box and can observe the target through the declared read path.
    """
    values = binding or {}
    if str(values.get("binding_kind") or "") == "controller_entry":
        return True
    if str(values.get("host") or "") == str(target or ""):
        return True
    return bool({str(value) for value in values.get("addresses") or []}
                & {str(value) for value in target_addresses or []})


__all__ = ["PROVIDER_FIELDS", "execution_binding", "provider_for_record", "same_subject"]
