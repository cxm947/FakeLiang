"""Fixed migration sequence; transport and accepted channels belong to the owner.

No IO is performed on import. Owner implementations bind/reserve on __enter__,
release the temporary receiver on __exit__ (including partial startup), and keep
accepted sessions alive. The configured payload_ref identifies an immutable
owner-provided callback artifact, never model-generated commands.
"""

from contextlib import contextmanager, nullcontext
import json
import os
from pathlib import Path
from typing import ContextManager, Literal, Protocol

from filelock import FileLock
from pydantic import BaseModel, ConfigDict, Field

from .execution_session import Nonempty, SessionReference


class CloseoutFailure(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class RemoteCommandEntry(BaseModel):
    """Owner alias for an existing target-side command submission endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    kind: Literal["remote_command"] = "remote_command"
    owner: Nonempty
    handle: Nonempty
    reference: SessionReference | None = None
    provider: str | None = None
    #: Frozen execution binding for a non-console provider (ssh/webshell). The owner
    #: resolves this with the same provider dispatch every other stage uses; it is never
    #: derived from a model claim.
    binding: dict | None = None


class AuthorizedConnectionEntry(BaseModel):
    """Owner alias for a connection already authorized on the controller."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    kind: Literal["authorized_connection"] = "authorized_connection"
    owner: Nonempty
    handle: Nonempty
    reference: SessionReference | None = None
    provider: str | None = None
    binding: dict | None = None


MigrationEntry = RemoteCommandEntry | AuthorizedConnectionEntry


class CallbackPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    artifact_ref: Nonempty
    callback_host: Nonempty
    callback_port: int = Field(ge=1, le=65535, strict=True)
    run_id: Nonempty
    operation_id: Nonempty
    host: Nonempty
    privilege: Nonempty
    operation_generation: int = Field(default=1, ge=1, strict=True)
    target_addresses: tuple[str, ...] = ()


class CallbackReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    run_id: Nonempty
    operation_id: Nonempty
    host: Nonempty
    privilege: Nonempty
    reference: SessionReference
    operation_generation: int = Field(default=1, ge=1, strict=True)


class Receiver(Protocol):
    def start(self) -> None: ...
    def wait_ready(self, timeout: float) -> bool: ...
    def wait_callback(self, timeout: float) -> CallbackReceipt | None: ...


class MigrationOwner(Protocol):
    """One implementation resolves both aliases and delivers exactly once.

    reserve_receiver must atomically acquire the actual port and receiver; a
    preflight port probe is insufficient. deliver uploads and launches the fixed
    artifact, returning after launch, without waiting for session termination or
    internally retrying. Callback receipts attest the operation/target identity.
    Reservation exit closes only temporary resources, not the accepted channel.
    """

    def reserve_receiver(self, payload: CallbackPayload) -> ContextManager[Receiver]: ...
    def deliver(self, entry: MigrationEntry, payload: CallbackPayload,
                *, timeout: float) -> None: ...


class PortPool:
    """Controller-wide increasing port range, shared through one local directory.

    FileLock serializes processes; a durable cursor prevents reuse after crashes.
    Released ports are not recycled: exhaustion is explicit. All controller
    workers must use the same directory and range, independent of run/owner.
    """

    def __init__(self, directory: Path, start: int, end: int):
        if not (type(start) is int and type(end) is int and 1 <= start <= end <= 65535):
            raise ValueError("Invalid inclusive port range")
        self.directory, self.start, self.end = Path(directory), start, end

    @contextmanager
    def reserve(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / "ports.json"
        with FileLock(str(self.directory / "allocator.lock")):
            state = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {
                "start": self.start, "end": self.end, "next": self.start}
            if (state["start"], state["end"]) != (self.start, self.end):
                raise ValueError("Controller port range changed")
            port = state["next"]
            if type(port) is not int or not self.start <= port <= self.end + 1:
                raise ValueError("Invalid port cursor")
            if port > self.end:
                raise CloseoutFailure("port_range_exhausted")
            state["next"] = port + 1
            temporary = path.with_suffix(".tmp")
            with temporary.open("w", encoding="utf-8") as stream:
                json.dump(state, stream)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(path)
        with FileLock(str(self.directory / f"{port}.lock")):
            yield port

    def allocate(self):
        """Take the next port as a durable allocation (ports are never recycled).

        Hand-over for a long-lived Action cannot hold the per-port lease for the
        whole attempt; the cursor already prevents reuse, so the number stands.
        """
        with self.reserve() as port:
            return port


class MigrationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    callback_host: Nonempty
    payload_ref: Nonempty
    recipe: str = "fixed-callback/v1"
    source_types: tuple[str, ...] = ("ssh", "web", "one_shot")
    ready_timeout: float = Field(default=10, gt=0, allow_inf_nan=False)
    delivery_timeout: float = Field(default=30, gt=0, allow_inf_nan=False)
    callback_timeout: float = Field(default=30, gt=0, allow_inf_nan=False)


class SessionMigration:
    def __init__(self, owner: MigrationOwner, ports: PortPool, settings: MigrationSettings):
        self.owner, self.ports, self.settings = owner, ports, settings

    def supports(self, source_type):
        return self.settings.recipe == "fixed-callback/v1" and source_type in self.settings.source_types

    def prepare(self, request):
        return CallbackPayload(artifact_ref=self.settings.payload_ref,
            callback_host=self.settings.callback_host, callback_port=self.ports.allocate(),
            run_id=request.run_id, operation_id=request.operation_id,
            host=request.host, privilege=request.privilege,
            target_addresses=(request.observed_address,) if request.observed_address else ())

    def reconcile(self, request):
        lookup = getattr(self.owner, "lookup_migration", None)
        if not callable(lookup):
            return None
        receipts = lookup(run_id=request.run_id, operation_id=request.operation_id) or []
        matches = []
        for value in receipts:
            try:
                receipt = CallbackReceipt.model_validate(value)
            except (ValueError, TypeError):
                raise CloseoutFailure("callback_mismatch") from None
            if (receipt.run_id, receipt.operation_id, receipt.host, receipt.privilege, receipt.operation_generation) != (
                    request.run_id, request.operation_id, request.host, request.privilege, 1):
                raise CloseoutFailure("callback_mismatch")
            matches.append(receipt.reference)
        # Stable canonical destination; persisted before verification/registration.
        return min(matches, key=lambda r: (r.session_id, r.instance_id, r.generation)) if matches else None

    def migrate(self, entry: MigrationEntry, *, run_id: str, operation_id: str,
                host: str, privilege: str, payload: CallbackPayload | None = None) -> SessionReference:
        stage = "port_reservation_failed"
        try:
            with (nullcontext(payload.callback_port) if payload else self.ports.reserve()) as port:
                payload = payload or CallbackPayload(artifact_ref=self.settings.payload_ref,
                    callback_host=self.settings.callback_host, callback_port=port,
                    run_id=run_id, operation_id=operation_id, host=host, privilege=privilege)
                stage = "receiver_reservation_failed"
                with self.owner.reserve_receiver(payload) as receiver:
                    stage = "receiver_start_failed"
                    receiver.start()
                    stage = "receiver_not_ready"
                    if receiver.wait_ready(self.settings.ready_timeout) is not True:
                        raise CloseoutFailure(stage)
                    stage = "delivery_failed"
                    self.owner.deliver(entry, payload, timeout=self.settings.delivery_timeout)
                    stage = "callback_timeout"
                    receipt = receiver.wait_callback(self.settings.callback_timeout)
                    if receipt is None:
                        raise CloseoutFailure(stage)
                    stage = "callback_mismatch"
                    receipt = CallbackReceipt.model_validate(receipt)
                    if any(getattr(receipt, key) != getattr(payload, key) for key in
                           ("run_id", "operation_id", "host", "privilege", "operation_generation")):
                        raise CloseoutFailure(stage)
                    reference = receipt.reference
                    stage = "receiver_release_failed"
                stage = "port_release_failed"
            return reference
        except CloseoutFailure:
            raise
        except Exception as exc:
            raise CloseoutFailure(stage) from exc
