"""A single PostgreSQL table of execution references, separate from checkpoints.

    with psycopg.connect(dsn) as conn:
        registry = SessionRegistry(conn)
        registry.setup()

Connections belong to the caller, as with PostgresSaver. Each operation uses a
transaction (a savepoint inside a caller transaction); caller transactions must
be committed for durability. No connections are made on import/construction.
"""

from psycopg import Connection
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from pydantic import TypeAdapter

from .execution_session import (SessionRecord, SessionReference, SessionRegistration,
                                SessionStatus)


class SessionConflict(ValueError):
    """An operation ID was reused with different registration parameters."""


class SessionRegistry:
    def __init__(self, connection: Connection):
        self.connection = connection

    @staticmethod
    def _record(row) -> SessionRecord:
        # Optional observation fields accept both legacy and migrated SELECT * rows.
        return SessionRecord.model_validate(row)

    def commit(self) -> None:
        """Explicit caller commit before a downstream checkpoint reports success."""
        self.connection.commit()

    def setup(self) -> None:
        with self.connection.transaction(), self.connection.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS execution_sessions (
                    session_id TEXT NOT NULL CHECK (btrim(session_id) <> ''),
                    run_id TEXT NOT NULL CHECK (btrim(run_id) <> ''),
                    operation_id TEXT NOT NULL CHECK (btrim(operation_id) <> ''),
                    host TEXT NOT NULL CHECK (btrim(host) <> ''),
                    privilege TEXT NOT NULL CHECK (btrim(privilege) <> ''),
                    source_node_id TEXT NOT NULL CHECK (btrim(source_node_id) <> ''),
                    source_attempt INTEGER NOT NULL CHECK (source_attempt >= 1),
                    instance_id TEXT NOT NULL CHECK (btrim(instance_id) <> ''),
                    generation INTEGER NOT NULL CHECK (generation >= 1),
                    status TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'stale', 'closed')),
                    binding_kind TEXT NOT NULL DEFAULT 'console_session'
                        CHECK (binding_kind IN ('console_session', 'controller_entry')),
                    -- What actually carries commands for this record. A NULL provider
                    -- is a legacy row and means msf, exactly like node_live's default.
                    provider TEXT,
                    ssh_key_path TEXT,
                    ssh_port INTEGER,
                    webshell_url TEXT,
                    webshell_parameter TEXT,
                    observed_address TEXT,
                    registered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (run_id, operation_id),
                    -- Identity is scoped to one run: the same logical entry may be
                    -- registered again by the next run without colliding.
                    PRIMARY KEY (run_id, session_id)
                )
            """)
            cur.execute("""
                SELECT array_agg(a.attname ORDER BY a.attname)
                FROM pg_index i
                JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                WHERE i.indrelid = 'execution_sessions'::regclass AND i.indisprimary
            """)
            primary = cur.fetchone()
            columns = (primary or [None])[0] if not isinstance(primary, dict) else primary.get("array_agg")
            if sorted(columns or []) != ["run_id", "session_id"]:
                cur.execute("""
                    ALTER TABLE execution_sessions DROP CONSTRAINT IF EXISTS execution_sessions_pkey
                """)
                cur.execute("""
                    ALTER TABLE execution_sessions
                    ADD CONSTRAINT execution_sessions_pkey PRIMARY KEY (run_id, session_id)
                """)
            cur.execute("""
            ALTER TABLE execution_sessions
            ADD COLUMN IF NOT EXISTS binding_kind TEXT NOT NULL DEFAULT 'console_session'
            """)
            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS execution_sessions_active_key
                ON execution_sessions (run_id, host, privilege) WHERE status = 'active'
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS execution_sessions_source
                ON execution_sessions (run_id, source_node_id)
            """)
            self._setup_watch(cur)
            self._setup_address(cur)
            self._setup_provider(cur)

    @staticmethod
    def _setup_address(cur) -> None:
        #: What the console reported when the session was claimed; nullable because
        #: controller entries are not console sessions and legacy rows have none.
        cur.execute("""
            ALTER TABLE execution_sessions ADD COLUMN IF NOT EXISTS observed_address TEXT
        """)

    @staticmethod
    def _setup_provider(cur) -> None:
        """Persist the transport that owns a session, not only its identity.

        Without these columns a manually registered SSH/WebShell record reads back as
        provider=None (treated as msf by every caller), and the registration comparison
        rejects the input as a different operation.
        """
        cur.execute("""
            ALTER TABLE execution_sessions ADD COLUMN IF NOT EXISTS provider TEXT
        """)
        cur.execute("""
            ALTER TABLE execution_sessions ADD COLUMN IF NOT EXISTS ssh_key_path TEXT
        """)
        cur.execute("""
            ALTER TABLE execution_sessions ADD COLUMN IF NOT EXISTS ssh_port INTEGER
        """)
        cur.execute("""
            ALTER TABLE execution_sessions ADD COLUMN IF NOT EXISTS webshell_url TEXT
        """)
        cur.execute("""
            ALTER TABLE execution_sessions ADD COLUMN IF NOT EXISTS webshell_parameter TEXT
        """)

    @staticmethod
    def _setup_watch(cur) -> None:
        # Do not backfill old rows (including closed rows) or change existing
        # column defaults/constraints. NULL means no watch observation is recorded.
        cur.execute("""
            ALTER TABLE execution_sessions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ
        """)
        cur.execute("""
            ALTER TABLE execution_sessions ADD COLUMN IF NOT EXISTS watch_reason TEXT
        """)

    def setup_watch(self) -> None:
        """Add observation metadata to the existing registry table, idempotently."""
        with self.connection.transaction(), self.connection.cursor() as cur:
            self._setup_watch(cur)

    def register(self, registration: SessionRegistration) -> SessionRecord:
        """Retries return the existing record, preserving timestamp and status.

        (run_id, operation_id) identifies the operation. All immutable fields
        must match on retry. Primary-key/active-key collisions raise psycopg's
        UniqueViolation; explicitly retire an old active session before replacing
        it, optionally inside the same caller transaction.
        """
        values = registration.model_dump()
        with self.connection.transaction(), self.connection.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                INSERT INTO execution_sessions
                    (session_id, run_id, operation_id, host, privilege, source_node_id,
                     source_attempt, instance_id, generation, binding_kind, observed_address,
                     provider, ssh_key_path, ssh_port, webshell_url, webshell_parameter)
                VALUES (%(session_id)s, %(run_id)s, %(operation_id)s, %(host)s,
                        %(privilege)s, %(source_node_id)s, %(source_attempt)s,
                        %(instance_id)s, %(generation)s, %(binding_kind)s,
                        %(observed_address)s, %(provider)s, %(ssh_key_path)s,
                        %(ssh_port)s, %(webshell_url)s, %(webshell_parameter)s)
                ON CONFLICT (run_id, operation_id) DO UPDATE
                    SET operation_id = EXCLUDED.operation_id
                RETURNING *
            """, values)
            record = self._record(cur.fetchone())
            if any(self._same(record, key, value) is False for key, value in values.items()):
                raise SessionConflict("Operation ID already has a different registration")
            return record

    @staticmethod
    def _same(record, key, value) -> bool:
        """Compare a registration against a stored row.

        A legacy row has provider NULL, which every caller already reads as msf; an
        explicit ``provider="msf"`` must therefore be idempotent with it.
        """
        stored = getattr(record, key)
        if key == "provider":
            return (stored or "msf") == (value or "msf")
        return stored == value

    def register_exact(self, registration: SessionRegistration, *,
                       supersedes: SessionReference | None = None) -> SessionRecord:
        """An already registered M may be explicitly reused by another operation.

        Keep the first registration's provenance and lifecycle. A same-name new
        incarnation, different target/privilege, or unrelated active-key conflict
        remains a conflict. The failed insert's savepoint is rolled back before
        reading, so concurrent registrations use the database's unique constraints.

        ``supersedes`` names the transient carrier this migration replaces. Only when the
        active-key insert collides is that exact row closed and the insert retried; a
        different active row is still a conflict.
        """
        try:
            return self.register(registration)
        except UniqueViolation:
            with self.connection.transaction(), self.connection.cursor(row_factory=dict_row) as cur:
                cur.execute("""
                    SELECT * FROM execution_sessions WHERE run_id = %s AND session_id = %s
                """, (registration.run_id, registration.session_id))
                row = cur.fetchone()
            if row is None:
                if (supersedes is not None
                        and supersedes.session_id != registration.session_id):
                    with self.connection.transaction(), self.connection.cursor() as cur:
                        cur.execute("""
                            UPDATE execution_sessions
                            SET status = 'closed', updated_at = statement_timestamp()
                            WHERE run_id = %s AND session_id = %s AND status = 'active'
                        """, (registration.run_id, supersedes.session_id))
                    try:
                        return self.register(registration)
                    except UniqueViolation:
                        raise
                raise
            record = self._record(row)
            if any(self._same(record, key, getattr(registration, key)) is False for key in (
                    "run_id", "session_id", "instance_id", "generation", "host", "privilege",
                    "binding_kind", "provider", "ssh_key_path", "ssh_port",
                    "webshell_url", "webshell_parameter")):
                raise SessionConflict("Existing M has different identity or requirements") from None
            return record

    def find(self, run_id: str, host: str, privilege: str) -> SessionRecord | None:
        """Return the sole active console session for this run; never a controller entry.

        An execCode key must not resolve to the run's own starting entry even when the
        two happen to share a host/privilege pair.
        """
        with self.connection.transaction(), self.connection.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                SELECT * FROM execution_sessions
                WHERE run_id = %s AND host = %s AND privilege = %s AND status = 'active'
                  AND binding_kind = 'console_session'
            """, (run_id, host, privilege))
            row = cur.fetchone()
            return self._record(row) if row else None

    def update_status(self, run_id: str, session_id: str,
                      status: SessionStatus) -> SessionRecord:
        """Set lifecycle explicitly; closed is terminal and cannot be refreshed."""
        status = TypeAdapter(SessionStatus).validate_python(status)
        with self.connection.transaction(), self.connection.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                UPDATE execution_sessions SET status = %s, updated_at = statement_timestamp()
                WHERE run_id = %s AND session_id = %s AND status <> 'closed' RETURNING *
            """, (status, run_id, session_id))
            row = cur.fetchone()
            if row is None:
                # A closed row is returned unchanged; an absent row is an error.
                cur.execute("""
                    SELECT * FROM execution_sessions WHERE run_id = %s AND session_id = %s
                """, (run_id, session_id))
                row = cur.fetchone()
            if row is None:
                raise KeyError((run_id, session_id))
            return self._record(row)

    def record_watch(self, record: SessionRecord, *, status: SessionStatus, reason: str) -> bool:
        """Apply one observation only to the still-active, pinned console row.

        Persist the named reason for stale observations; a successful observation
        only refreshes updated_at. Unknown never means closed or deleted.
        False means the row changed during observation; there is no retry/rebind.
        """
        status = TypeAdapter(SessionStatus).validate_python(status)
        if status == "closed":
            raise ValueError("session_watch_cannot_close")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("session_watch_reason_required")
        if record.status != "active" or record.binding_kind != "console_session":
            return False
        with self.connection.transaction(), self.connection.cursor() as cur:
            cur.execute("""
                UPDATE execution_sessions SET status = %(status)s, updated_at = statement_timestamp(),
                    watch_reason = CASE WHEN %(status)s = 'stale' THEN %(reason)s ELSE watch_reason END
                WHERE run_id = %(run_id)s AND session_id = %(session_id)s
                    AND operation_id = %(operation_id)s AND instance_id = %(instance_id)s
                    AND generation = %(generation)s AND binding_kind = 'console_session'
                    AND status = 'active'
                RETURNING session_id
            """, {"status": status, "reason": reason,
                  "run_id": record.run_id, "session_id": record.session_id,
                  "operation_id": record.operation_id, "instance_id": record.instance_id,
                  "generation": record.generation})
            return cur.fetchone() is not None

    def find_entry(self, run_id: str, session_id: str) -> SessionRecord | None:
        """Return one active controller entry by its logical identity for this run."""
        with self.connection.transaction(), self.connection.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                SELECT * FROM execution_sessions
                WHERE run_id = %s AND session_id = %s AND status = 'active'
                  AND binding_kind = 'controller_entry'
            """, (run_id, session_id))
            row = cur.fetchone()
            return self._record(row) if row else None

    def list_for_run(self, run_id: str, *, node_id: str | None = None) -> list[SessionRecord]:
        """Snapshot all lifecycle states, optionally filtered by source node."""
        query = "SELECT * FROM execution_sessions WHERE run_id = %s"
        parameters = (run_id,)
        if node_id is not None:
            query += " AND source_node_id = %s"
            parameters += (node_id,)
        query += " ORDER BY registered_at, session_id"
        with self.connection.transaction(), self.connection.cursor(row_factory=dict_row) as cur:
            cur.execute(query, parameters)
            return [self._record(row) for row in cur.fetchall()]
