"""Independent PostgreSQL tunnel table, with durable transitions before remote IO.

Use a dedicated autocommit psycopg connection exclusively for this registry.
No caller transaction may span a tunnel operation: a launch intent must survive
process death even when the operating-system installation outcome is unknown.
"""

from contextlib import contextmanager
from hashlib import sha256

from psycopg import Connection
from psycopg.pq import TransactionStatus
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .tunnel import CleanupReceipt, TunnelFailure, TunnelRecord


class TunnelRegistry:
    def __init__(self, connection: Connection):
        self.connection = connection

    def _durable(self):
        if (self.connection.autocommit is not True or
                self.connection.info.transaction_status != TransactionStatus.IDLE):
            raise TunnelFailure("tunnel_registry_requires_idle_autocommit")

    @contextmanager
    def lock(self, run_id: str, operation_id: str):
        self._durable()
        key = int.from_bytes(sha256((str(len(run_id)) + ":" + run_id + operation_id)
                                   .encode()).digest()[:8], "big", signed=True)
        with self.connection.cursor() as cur:
            cur.execute("SELECT pg_try_advisory_lock(%s)", (key,))
            if cur.fetchone()[0] is not True:
                raise TunnelFailure("tunnel_operation_busy")
            try:
                yield
            finally:
                cur.execute("SELECT pg_advisory_unlock(%s)", (key,))

    def setup(self) -> None:
        self._durable()
        with self.connection.transaction(), self.connection.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS execution_tunnels (
                    tunnel_id TEXT PRIMARY KEY,
                    installation_id TEXT NOT NULL UNIQUE,
                    run_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    direction TEXT NOT NULL CHECK (direction IN ('access', 'return')),
                    pivot_host TEXT NOT NULL,
                    privilege TEXT NOT NULL,
                    session JSONB NOT NULL,
                    listen_host TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    target_port INTEGER NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
                    local_port INTEGER NOT NULL CHECK (local_port BETWEEN 1 AND 65535),
                    source_node_id TEXT NOT NULL,
                    source_attempt INTEGER NOT NULL CHECK (source_attempt >= 1),
                    status TEXT NOT NULL CHECK
                        (status IN ('reserved', 'starting', 'active', 'failed', 'stale', 'closed')),
                    started BOOLEAN NOT NULL DEFAULT FALSE,
                    cleanup_receipt JSONB,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (run_id, operation_id),
                    CHECK (status NOT IN ('starting', 'active', 'failed', 'stale') OR started),
                    CHECK (status <> 'reserved' OR NOT started),
                    CHECK (status <> 'closed' OR NOT started OR cleanup_receipt IS NOT NULL)
                )
            """)
            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS execution_tunnels_port
                ON execution_tunnels (pivot_host, local_port) WHERE status <> 'closed'
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS execution_tunnels_coverage
                ON execution_tunnels (run_id, target_host, target_port)
                WHERE direction = 'access' AND status = 'active'
            """)

    def _one(self, sql, values):
        self._durable()
        with self.connection.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, values)
            row = cur.fetchone()
            return TunnelRecord.model_validate(row) if row else None

    def get(self, run_id: str, tunnel_id: str) -> TunnelRecord:
        row = self._one("SELECT * FROM execution_tunnels WHERE run_id = %s AND tunnel_id = %s",
                        (run_id, tunnel_id))
        if row is None:
            raise KeyError((run_id, tunnel_id))
        return row

    def by_operation(self, run_id: str, operation_id: str) -> TunnelRecord | None:
        return self._one("SELECT * FROM execution_tunnels WHERE run_id = %s AND operation_id = %s",
                         (run_id, operation_id))

    def insert(self, record: TunnelRecord) -> TunnelRecord:
        values = record.model_dump(mode="json")
        values["session"] = Jsonb(values["session"])
        values["cleanup_receipt"] = None
        # Keys come only from the fixed Pydantic schema; all values are parameters.
        columns = ", ".join(values)
        placeholders = ", ".join(f"%({key})s" for key in values)
        return self._one(f"INSERT INTO execution_tunnels ({columns}) VALUES ({placeholders}) RETURNING *",
                         values)

    def transition(self, record: TunnelRecord, status: str, *,
                   receipt: CleanupReceipt | None = None) -> TunnelRecord:
        allowed = {"reserved": {"starting", "closed"}, "starting": {"active", "failed", "closed"},
                   "active": {"stale", "closed"}, "failed": {"closed"}, "stale": {"closed"}}
        if status not in allowed.get(record.status, set()):
            raise TunnelFailure("invalid_tunnel_transition")
        if status == "closed" and record.started:
            if receipt is None or (receipt.run_id, receipt.tunnel_id, receipt.installation_id) != (
                    record.run_id, record.tunnel_id, record.installation_id):
                raise TunnelFailure("cleanup_receipt_required")
            if receipt.cleaned_at < record.created_at:
                raise TunnelFailure("cleanup_receipt_predates_installation")
        row = self._one("""
            UPDATE execution_tunnels SET status = %s, started = %s,
                cleanup_receipt = %s, updated_at = CURRENT_TIMESTAMP
            WHERE run_id = %s AND tunnel_id = %s AND status = %s RETURNING *
        """, (status, record.started or status == "starting",
              Jsonb(receipt.model_dump(mode="json")) if receipt else None,
              record.run_id, record.tunnel_id, record.status))
        if row is None:
            raise TunnelFailure("tunnel_state_changed")
        return row

    def list_for_run(self, run_id: str, *, current_only: bool = True) -> list[TunnelRecord]:
        self._durable()
        sql = "SELECT * FROM execution_tunnels WHERE run_id = %s"
        if current_only:
            sql += " AND status <> 'closed'"
        sql += " ORDER BY created_at, tunnel_id"
        with self.connection.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, (run_id,))
            return [TunnelRecord.model_validate(row) for row in cur.fetchall()]
