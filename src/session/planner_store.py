"""Official checkpoint storage only; no application tables or duplicate journal."""

from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import sqlite3

from filelock import FileLock, Timeout
from langgraph.checkpoint.sqlite import SqliteSaver


class RunBusy(RuntimeError):
    pass


class RunConflict(RuntimeError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


class PlannerStore:
    def __init__(self, url):
        self.sqlite_path = None
        if url.startswith("sqlite:///"):
            path = url.removeprefix("sqlite:///")
            if not path or path == ":memory:":
                raise ValueError("Recovery requires file-backed SQLite")
            self.sqlite_path = Path(path).resolve()
            self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        elif not url.startswith(("postgresql://", "postgresql+psycopg://")):
            raise ValueError("Use PostgreSQL or file-backed SQLite")
        self.dsn = url.replace("postgresql+psycopg://", "postgresql://", 1)

    def setup(self):
        with self.checkpointer() as saver:
            saver.setup()

    def close(self):
        # Connections are scoped to operations; no long-lived pool to close.
        pass

    @contextmanager
    def checkpointer(self):
        if self.sqlite_path:
            connection = sqlite3.connect(str(self.sqlite_path), check_same_thread=False)
            try:
                connection.execute("PRAGMA synchronous=FULL")
                yield SqliteSaver(connection)
            finally:
                connection.close()
        else:
            from langgraph.checkpoint.postgres import PostgresSaver
            with PostgresSaver.from_conn_string(self.dsn) as saver:
                yield saver

    @contextmanager
    def lock(self, run_id):
        """Process ownership, released after process/connection death."""
        if self.sqlite_path:
            directory = Path(str(self.sqlite_path) + ".locks")
            directory.mkdir(exist_ok=True)
            lock = FileLock(directory / (sha256(run_id.encode()).hexdigest() + ".lock"))
            try:
                lock.acquire(timeout=0)
            except Timeout:
                raise RunBusy("Task is already running") from None
            try:
                yield
            finally:
                lock.release()
        else:
            import psycopg
            number = int.from_bytes(sha256(run_id.encode()).digest()[:8], "big", signed=True)
            with psycopg.connect(self.dsn, autocommit=True) as conn:
                if not conn.execute("SELECT pg_try_advisory_lock(%s)", (number,)).fetchone()[0]:
                    raise RunBusy("Task is already running")
                try:
                    yield
                finally:
                    conn.execute("SELECT pg_advisory_unlock(%s)", (number,))

    def active(self, run_id):
        try:
            with self.lock(run_id):
                return False
        except RunBusy:
            return True

    def list_ids(self, limit=50):
        # ponytail: scan history for the small local task list. Add an indexed
        # read projection only when measured history volume requires it.
        with self.checkpointer() as saver:
            seen = set()
            for item in saver.list(None, filter={"agv_kind": "planner"}):
                run_id = item.config["configurable"]["thread_id"]
                if run_id not in seen:
                    seen.add(run_id)
                    yield run_id
                if len(seen) >= limit:
                    break
