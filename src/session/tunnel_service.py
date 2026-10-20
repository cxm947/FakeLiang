"""The sole tunnel lifecycle entry, downstream of session migration/registration."""

from contextlib import contextmanager
from datetime import datetime, timezone
from ipaddress import IPv4Address
from uuid import uuid4

from pydantic import TypeAdapter

from .session_migration import PortPool
from .session_registry import SessionRegistry
from .tunnel import (CleanupReceipt, Port, TunnelEndpoint, TunnelFailure,
                     TunnelRecord, TunnelRequest)
from .tunnel_registry import TunnelRegistry
from .tunnel_system import SystemTunnelOwner


class TunnelService:
    def __init__(self, registry: TunnelRegistry, sessions: SessionRegistry,
                 ports: PortPool, owner: SystemTunnelOwner):
        self.registry, self.sessions, self.ports, self.owner = registry, sessions, ports, owner

    def _session(self, request):
        session = self.sessions.find(request.run_id, request.pivot_host, request.privilege)
        if session is None or session.reference() != request.session:
            raise TunnelFailure("migrated_session_required")

    @contextmanager
    def _locked(self, run_id, tunnel_id):
        record = self.registry.get(run_id, tunnel_id)
        with self.registry.lock(run_id, record.operation_id):
            yield self.registry.get(run_id, tunnel_id)

    def prepare(self, request: TunnelRequest) -> TunnelRecord:
        request = TunnelRequest.model_validate(request)
        with self.registry.lock(request.run_id, request.operation_id):
            old = self.registry.by_operation(request.run_id, request.operation_id)
            if old is not None:
                if old.request() != request:
                    raise TunnelFailure("tunnel_operation_conflict")
                return old
            self._session(request)
            with self.ports.reserve() as port:
                now = datetime.now(timezone.utc)
                return self.registry.insert(TunnelRecord(**request.model_dump(),
                    tunnel_id=uuid4().hex, installation_id=uuid4().hex, local_port=port,
                    created_at=now, updated_at=now))

    def build(self, run_id: str, tunnel_id: str) -> TunnelRecord:
        with self._locked(run_id, tunnel_id) as record:
            if record.status == "active":
                return record
            if record.status != "reserved":
                raise TunnelFailure("tunnel_launch_not_replayable")
            self._session(record)
            # Persist before calling the owner; even partial startup needs cleanup.
            record = self.registry.transition(record, "starting")
            try:
                self.owner.install(record)
            except Exception:
                self.registry.transition(record, "failed")
                raise
            return self.registry.transition(record, "active")

    def refresh(self, run_id: str, tunnel_id: str) -> TunnelRecord:
        with self._locked(run_id, tunnel_id) as record:
            if record.status == "active" and not self.owner.is_alive(record):
                return self.registry.transition(record, "stale")
            return record

    def covers(self, run_id: str, host: str, port: int | None = None) -> list[TunnelRecord]:
        """Exact IP/optional port, access direction only; recheck candidate listeners.

        Without port, a match means at least one service on that host is mapped.
        This does not claim arbitrary ports or end-to-end target availability.
        """
        address = IPv4Address(host)
        if port is not None:
            port = TypeAdapter(Port).validate_python(port)
        candidates = [r for r in self.registry.list_for_run(run_id)
                      if r.direction == "access" and r.status == "active"
                      and r.target_host == address and (port is None or r.target_port == port)]
        return [r for candidate in candidates
                if (r := self.refresh(run_id, candidate.tunnel_id)).status == "active"]

    def connect(self, run_id: str, tunnel_id: str, host: str, port: int) -> TunnelEndpoint:
        """Resolve an existing mapping for a normal TCP client; never install one."""
        address, port = IPv4Address(host), TypeAdapter(Port).validate_python(port)
        with self._locked(run_id, tunnel_id) as record:
            if (record.status != "active" or record.direction != "access" or
                    (record.target_host, record.target_port) != (address, port)):
                raise TunnelFailure("target_not_covered")
            if not self.owner.is_alive(record):
                self.registry.transition(record, "stale")
                raise TunnelFailure("tunnel_not_alive")
            return TunnelEndpoint(tunnel_id=record.tunnel_id, host=record.listen_host,
                port=record.local_port, target_host=address, target_port=port)

    def release(self, run_id: str, tunnel_id: str, *,
                receipt: CleanupReceipt | None = None) -> TunnelRecord:
        with self._locked(run_id, tunnel_id) as record:
            if record.status == "closed":
                return record
            if receipt is not None:
                receipt = CleanupReceipt.model_validate(receipt)
                if (receipt.run_id, receipt.tunnel_id, receipt.installation_id) != (
                        run_id, tunnel_id, record.installation_id):
                    raise TunnelFailure("cleanup_receipt_mismatch")
                if receipt.cleaned_at < record.created_at:
                    raise TunnelFailure("cleanup_receipt_predates_installation")
            if record.started and receipt is None:
                raise TunnelFailure("cleanup_receipt_required")
            return self.registry.transition(record, "closed", receipt=receipt)

    def cleanup(self, run_id: str, tunnel_id: str) -> TunnelRecord:
        """Stop the OS forwarder and persist its receipt before freeing the lease."""
        with self._locked(run_id, tunnel_id) as record:
            if record.status == "closed":
                return record
            receipt = self.owner.uninstall(record) if record.started else None
            # Avoid nested locks: use the same registry transition as release.
            return self.registry.transition(record, "closed", receipt=receipt)
