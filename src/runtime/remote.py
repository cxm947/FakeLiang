"""Remote executor: run a fixed argv on the attack box (Kali) over SSH.

``runtime.runner.execute(..., executor=...)`` takes any ``(argv, timeout) -> ExecOutcome``
callable. This module supplies the SSH transport, so a skill keeps its fixed argv while the
command really executes from the Kali attack box - the vantage the graph describes - and every
call artefact still lands in the local run directory.

Connection details are runtime inputs (CLI / env), never catalog data:

    python scripts/run_skill_remote.py --skill pre.nmap_tcp_probe --input inputs.json \
        --run-dir output/runs/<run_id> --remote kali@192.168.52.128 --password kali

Failure semantics: a transport failure is **not** a target fact. It comes back as
``returncode=None`` plus an explanatory ``stderr``, which the runtime labels
``transport_error``; the adapter then has no evidence and the judge can only say ``uncertain``.
"""

from __future__ import annotations

import shlex
import socket
import warnings
from dataclasses import dataclass

# paramiko imports Blowfish at module import on this cryptography build; the deprecation
# notice would otherwise land in every run's stderr and pollute the call artefacts.
warnings.filterwarnings("ignore", message="Blowfish has been deprecated")

from .runner import ExecOutcome

DEFAULT_PORT = 22
TOOL_MISSING_EXIT = 127
CONNECT_TIMEOUT = 15.0


@dataclass
class RemoteTarget:
    """Where the executor runs the argv (``user@host:port``)."""

    host: str
    username: str | None = None
    port: int = DEFAULT_PORT

    def label(self) -> str:
        user = f"{self.username}@" if self.username else ""
        return f"{user}{self.host}" if self.port == DEFAULT_PORT else f"{user}{self.host}:{self.port}"


def parse_remote(value: str, *, default_port: int = DEFAULT_PORT) -> RemoteTarget:
    """Parse ``user@host`` / ``user@host:port`` / ``host`` / ``host:port``."""
    text = (value or "").strip()
    if not text:
        raise SystemExit("--remote needs host or user@host[:port]")
    username, _, rest = text.rpartition("@")
    host, _, port_text = rest.partition(":")
    if not host:
        raise SystemExit(f"--remote {value!r} has no host")
    port = default_port
    if port_text:
        if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
            raise SystemExit(f"--remote {value!r} has an invalid port")
        port = int(port_text)
    return RemoteTarget(host=host, username=username or None, port=port)


def command_line(argv) -> str:
    """Quote one argv for a POSIX shell (what actually runs on the remote host)."""
    return " ".join(shlex.quote(str(part)) for part in argv)


def _connect(target: RemoteTarget, password: str | None, key_filename: str | None):
    try:
        import paramiko
    except ImportError:  # pragma: no cover - environment dependent
        raise SystemExit("paramiko is required for --remote (pip install paramiko)")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        target.host,
        port=target.port,
        username=target.username,
        password=password,
        key_filename=key_filename,
        timeout=CONNECT_TIMEOUT,
        allow_agent=False,
        look_for_keys=bool(key_filename),
    )
    return client


class SshExecutor:
    """Executor callable that runs argv through one SSH session (reused across calls)."""

    def __init__(self, target: RemoteTarget, *, password: str | None = None,
                 key_filename: str | None = None, client_factory=None):
        self.target = target
        self.password = password
        self.key_filename = key_filename
        self._client_factory = client_factory or _connect
        self._client = None

    def connect(self):
        if self._client is None:
            self._client = self._client_factory(self.target, self.password, self.key_filename)
        return self._client

    def label(self) -> str:
        """Where this executor runs argv - recorded with every call (``call.json`` vantage).

        A one-hop run is still a *position*: the call record has to say where the argv ran,
        or a later reviewer cannot tell a probe run from the attack box from one run where
        the graph asked for - so every executor names itself, not only the chain.
        """
        return self.target.label()

    def close(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            try:
                client.close()
            except Exception:  # closing must never hide the real result
                pass

    def __call__(self, argv, timeout: float) -> ExecOutcome:
        command = command_line(argv)
        try:
            client = self.connect()
            _, stdout, stderr = client.exec_command(command, timeout=float(timeout))
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            code = stdout.channel.recv_exit_status()
        except socket.timeout:
            self.close()
            return ExecOutcome(None, "", "", timed_out=True)
        except Exception as error:
            self.close()
            return ExecOutcome(None, "", f"executor failed: {type(error).__name__}: {error}")
        if code == TOOL_MISSING_EXIT and not out.strip():
            # rc=127 with no bytes at all: the far shell never found the entry point. A command
            # the runtime wrapped itself (marker script) prints its marker lines first and keeps
            # the query's own probe rc, so a 127 that still has output is the call's own reading
            # and travels as its exit status (run114).
            return ExecOutcome(code, out, err,
                               tool_error=f"command not found on {self.target.label()}: {argv[0]}")
        return ExecOutcome(code, out, err)
