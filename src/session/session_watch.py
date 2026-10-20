"""One read-only liveness sweep; scheduling and connection ownership stay outside.

An observation concerns only the pinned carrier, never node/business success.
The caller must prepare registry watch storage and commit its transaction.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from uuid import uuid4

from .pipeline_service import PipelineFailure
from .session_backend import SessionBackend, SessionRequest
from .session_registry import SessionRegistry


@dataclass(frozen=True)
class WatchObservation:
    session_id: str
    host: str
    result: str
    reason: str


@dataclass(frozen=True)
class WatchSummary:
    run_id: str
    started_at: datetime
    finished_at: datetime
    rows: tuple[WatchObservation, ...]

    def to_dict(self) -> dict:
        result = asdict(self)
        result["started_at"] = self.started_at.isoformat()
        result["finished_at"] = self.finished_at.isoformat()
        result["rows"] = [asdict(row) for row in self.rows]
        return result


class SessionWatch:
    def __init__(self, registry: SessionRegistry, backend: SessionBackend,
                 run_id: str, *, timeout: float = 30):
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("session_watch_run_id_required")
        # Share the backend's finite, positive timeout validation before any IO.
        self.timeout = SessionRequest(command="echo", end_markers=("validate",),
                                      timeout=timeout).timeout
        self.registry, self.backend, self.run_id = registry, backend, run_id

    def sweep(self) -> WatchSummary:
        """Probe each active console row once, without retries or implicit rebinds.

        A fresh request-specific terminal marker confirms observability. Missing
        markers and exceptions mean stale, never closed/deleted. Controller entries
        are owner-confirmed starting contexts, not RPC sessions; leave them intact.
        Registry failures propagate instead of being mislabeled as probe failures.
        """
        started = datetime.now(timezone.utc)
        observations = []
        for row in self.registry.list_for_run(self.run_id):
            if row.status != "active":
                continue
            if row.binding_kind == "controller_entry":
                observations.append(WatchObservation(row.session_id, row.host,
                    "skipped", "controller_entry_requires_owner_observation"))
                continue
            if str(row.provider or "msf") != "msf":
                # SSH/WebShell have no MSF RPC row; Post observes them through the
                # provider binding. Probing them here would mark a valid channel stale.
                observations.append(WatchObservation(row.session_id, row.host,
                    "skipped", "provider_owned_requires_post_observation"))
                continue
            marker = "agv-watch-" + uuid4().hex
            request = SessionRequest(command="echo " + marker,
                                     end_markers=(marker,), timeout=self.timeout)
            try:
                # reference_for() could return a replacement instance; never adopt
                # one during a liveness check of the already registered instance.
                response = self.backend.execute(row.reference(), request)
                status, reason = (("active", "fresh_end_marker")
                    if response.operation_confirmed else ("stale", "end_marker_missing"))
            except PipelineFailure as exc:
                status, reason = "stale", exc.detail
            except TimeoutError:
                status, reason = "stale", "probe_timeout"
            except Exception as exc:
                # Exception messages can contain credentials or captured output.
                status, reason = "stale", "probe_exception:" + type(exc).__name__
            if not self.registry.record_watch(row, status=status, reason=reason):
                status, reason = "skipped", "registry_row_changed"
            observations.append(WatchObservation(row.session_id, row.host, status, reason))
        return WatchSummary(self.run_id, started, datetime.now(timezone.utc),
                            tuple(observations))
