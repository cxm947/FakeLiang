"""Configured Metasploit RPC client. Import/construction never connects.

The RPC service owns session lifetimes; closing this client only releases its
console and authentication token. No shell process or VM transport is involved.
"""

from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
import re
from threading import RLock
from time import monotonic, sleep
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, SecretStr
import yaml

from .execution_session import SessionReference
from .pipeline_service import PipelineFailure


class BackendSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    host: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535, strict=True)
    username: SecretStr = Field(exclude=True, repr=False)
    password: SecretStr = Field(exclude=True, repr=False)
    ssl: bool = True
    timeout: float = Field(default=30, gt=0, allow_inf_nan=False)


class SessionMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)
    session_id: str
    instance_id: str
    type: str
    host: str
    platform: str
    callback_endpoint: str | None = None


class SessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    command: str = Field(min_length=1, repr=False)
    # Request-specific terminal output supplied by the skill/owner, never guessed.
    end_markers: tuple[str, ...] = Field(min_length=1)
    timeout: float = Field(default=30, gt=0, allow_inf_nan=False)


class SessionResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    operation_confirmed: bool
    output: str
    business_result: Literal["通过", "不通过"] | None = None


class SessionExecution(Protocol):
    """Execution contract; SessionBackend binds one request to one pinned session."""

    def execute(self, reference: SessionReference, request: SessionRequest) -> SessionResult: ...


def _client_class():
    """Keep the library's codec/managers, but bound HTTP and disable its retries."""
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        import requests
    except ImportError:
        raise PipelineFailure("参数没给到", "session_backend_dependency_missing") from None

    class BoundedClient(MsfRpcClient):
        deadline = None
        #: Read-only RPCs may be retried after a dropped connection: repeating them cannot
        #: change the target. Anything that writes into a session is never retried here.
        #: Reads may be retried after one dropped keep-alive; writes may not, because a
        #: duplicated write would run the command twice. A long-running target script
        #: spends its time in shell/meterpreter reads, and that is exactly where the peer
        #: service can close an idle HTTP connection (live 2026-10-19, node 19: a 120 s
        #: script lost `session.shell_read` and the node was reported unconfirmed).
        IDEMPOTENT = frozenset({"session.list", "job.list", "job.info", "core.version",
                                "core.module_stats", "console.read", "console.list",
                                "session.shell_read", "session.meterpreter_read"})

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # A target's own console output is not required to be UTF-8 (a Chinese Windows
            # answers in GBK), and a decode error must not be mistaken for an unusable
            # channel. Evidence: output/pipeline-live-20261016-56/rounds/006 came back
            # session_backend_rpc_unconfirmed on a UnicodeDecodeError from the Windows
            # channel.
            self.decode_error_handling = "replace"
            if not getattr(self, "encodings", None):
                self.encodings = ["utf-8"]
            # A Chinese Windows answers in GBK; try it after UTF-8 instead of turning every
            # line into replacement characters.
            if "gbk" not in self.encodings:
                self.encodings = [*self.encodings, "gbk"]

        def call(self, *args, **kwargs):
            method = str(args[0]) if args else ""
            try:
                result = super().call(*args, **kwargs)
            except Exception as exc:
                # A single dropped connection is not a failed observation: the peer service
                # occasionally closes one keep-alive request under load. Retrying a read-only
                # call keeps the node from being judged on a transport hiccup (live
                # 2026-10-18, node 44 pre: RuntimeError with the sessions list intact).
                import requests
                if method not in self.IDEMPOTENT or not isinstance(
                        exc, (requests.exceptions.ConnectionError,
                              requests.exceptions.Timeout)):
                    raise
                last = exc
                for delay in (1.0, 3.0, 5.0):
                    sleep(delay)
                    try:
                        result = super().call(*args, **kwargs)
                        break
                    except Exception as again:
                        last = again
                        if not isinstance(again, (requests.exceptions.ConnectionError,
                                                  requests.exceptions.Timeout)):
                            raise
                else:
                    # Keep the method and the last error text: "ConnectionError" alone does
                    # not say which RPC failed, and a random drop needs that evidence.
                    raise RuntimeError(str(method) + ":" + type(last).__name__
                                       + (":" + str(last)[:80] if str(last) else "")) from None
            if isinstance(result, dict) and (result.get("error") or result.get("result") == "failure"):
                # Keep the peer's own reason: a bare "rejected" hid a channel that was already
                # attached to an interactive console and a session that had just died.
                detail = str(result.get("error_message") or result.get("error") or
                             result.get("message") or "")[:200]
                raise RuntimeError("session_backend_rpc_rejected:" + detail)
            return result

        def post_request(self, url, payload):
            remaining = self.deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError()
            response = requests.post(url, data=payload, headers=self.headers,
                                     verify=self.ssl, timeout=remaining,
                                     allow_redirects=False)
            response.raise_for_status()
            return response

    return BoundedClient


class SessionBackend:
    def __init__(self, config: Mapping):
        try:
            self._settings = BackendSettings.model_validate(config)
            if (not self._settings.host.strip()
                    or not self._settings.username.get_secret_value().strip()
                    or not self._settings.password.get_secret_value()):
                raise ValueError()
        except Exception:
            raise PipelineFailure("参数没给到", "session_backend_config_invalid") from None
        self._client = self._console = None
        self._shells: set[str] = set()
        self._warmed: set[str] = set()
        self._lock = RLock()

    @classmethod
    def from_config(cls, path: str | Path) -> "SessionBackend":
        try:
            config = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except Exception:
            raise PipelineFailure("参数没给到", "session_backend_config_unavailable") from None
        return cls(config)

    @contextmanager
    def _operation(self, timeout=None):
        """Hold the lock and hand back the one deadline every call in this operation shares.

        The client enforces its own budget on each call, and a capture that computed its own
        deadline lived a moment longer, so a loop's last read was refused by the client's guard
        (live 2026-10-16 run pipeline-live-20261016-60/rounds/004). Yielding the same value
        removes the gap.
        """
        with self._lock:
            if self._client is None or self._console is None:
                raise PipelineFailure("参数没给到", "session_backend_not_ready")
            deadline = monotonic() + (timeout or self._settings.timeout)
            self._client.deadline = deadline
            try:
                yield deadline
            except PipelineFailure:
                raise
            except Exception as exc:
                # Library errors can include commands, output, tokens or credentials, so the
                # message never travels; the exception's own class name does. Without it a
                # budget timeout and a dead channel were indistinguishable, and a single hung
                # command was reported as an unusable channel (live 2026-10-16 run
                # pipeline-live-20261016-60/rounds/004: the receipt said session_backend_rpc_
                # unconfirmed while the real cause was our own TimeoutError).
                raise PipelineFailure("会话没接上",
                                      "session_backend_rpc_unconfirmed:"
                                      + type(exc).__name__
                                      + (":" + str(exc)[:120] if str(exc) else "")) from None

    #: A just-started RPC service answers on its port before it can serve a console. One
    #: transient rejection is retried inside the declared deadline instead of failing the
    #: whole run (observed live 2026-10-16: runs pipeline-live-20261016-20/-21 had the port
    #: ready and then failed seconds later, while the same client succeeded moments after).
    RETRY_INTERVAL = 2.0

    def connect(self) -> str:
        """Authenticate and create one console inside the declared deadline."""
        with self._lock:
            if self._console is not None:
                return str(self._console.cid)
            client_type = _client_class()
            settings = self._settings
            deadline = monotonic() + settings.timeout
            while True:
                try:
                    return self._connect_once(client_type, settings, deadline)
                except Exception:
                    try:
                        self.close()
                    except PipelineFailure:
                        pass
                    if monotonic() + self.RETRY_INTERVAL >= deadline:
                        raise PipelineFailure("会话没接上",
                                              "session_backend_connect_failed") from None
                    sleep(self.RETRY_INTERVAL)

    def _connect_once(self, client_type, settings, deadline) -> str:
        """One login + console attempt; the caller owns the retries and the budget."""
        # Non-None token defers library login until the deadline is set.
        self._client = client_type("", server=settings.host, port=settings.port,
                                   ssl=settings.ssl, token="")
        self._client.deadline = deadline
        # Use a temporary login token; library login creates a permanent one.
        auth = self._client.call("auth.login", [settings.username.get_secret_value(),
                                               settings.password.get_secret_value()])
        if auth.get("result") != "success" or not auth.get("token"):
            raise ValueError()
        self._client.token = auth["token"]
        self._console = self._client.consoles.console()
        if (type(self._console.cid) not in (str, int) or not str(self._console.cid).strip()):
            raise ValueError()
        return str(self._console.cid)

    def close(self) -> None:
        """Release only this console/token; never stop accepted sessions."""
        with self._lock:
            client, console = self._client, self._console
            self._client = self._console = None
            if client is None:
                return
            failed = False
            client.deadline = monotonic() + self._settings.timeout
            if console is not None:
                try:
                    console.destroy()
                except Exception:
                    failed = True
            if client.token:
                try:
                    client.logout()
                except Exception:
                    failed = True
            if failed:
                raise PipelineFailure("会话没接上", "session_backend_release_unconfirmed") from None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.close()
        except PipelineFailure:
            if exc_type is None:
                raise


    #: Read/write RPC per session type; a type outside this table has no channel.
    CHANNELS = {
        "meterpreter": ("session.meterpreter_write", "session.meterpreter_read"),
        "shell": ("session.shell_write", "session.shell_read"),
    }
    #: Never issue a read in the last sliver of the budget: the client refuses a call whose
    #: remaining time is already spent, and that refusal is not a channel failure.
    READ_MARGIN = 0.05
    SHELL_OPEN = "shell\n"
    SHELL_READY_MARKER = "agv-shell-ready"
    SHELL_OPEN_ATTEMPTS = 4
    SHELL_PROMPT_WAIT = 10.0
    READ_INTERVAL = 0.3
    #: Wait this long for the first output before declaring the command unconfirmed.
    FIRST_OUTPUT_WAIT = 10.0
    #: Once output has started, a quiet gap this long ends the capture for markerless
    #: console commands (for example an extension that prints a banner after a pause).
    QUIET_WINDOW = 5.0
    #: Normal console commands usually return one complete chunk; don't make every command
    #: pay the extension-loading window. 0.4s is enough to catch a trailing line break/chunk.
    FAST_QUIET_WINDOW = 0.4

    def _channel(self, metadata: SessionMetadata) -> tuple[str, str]:
        channels = self.CHANNELS.get(metadata.type)
        if channels is None:
            raise PipelineFailure("技能卡写得不好", "session_backend_channel_unsupported")
        return channels

    def _read(self, method: str, session_id: str) -> str:
        reply = self._client.call(method, [session_id])
        data = reply.get("data", "") if isinstance(reply, dict) else ""
        if not isinstance(data, str):
            raise PipelineFailure("会话没接上", "session_backend_read_invalid")
        return data

    def _meterpreter_single(self, session_id: str, command: str, *, settle: float = 1.2) -> str:
        """Run one meterpreter console command through RPC and return what it printed.

        `meterpreter_run_single` is the only non-interactive surface the peer service
        offers: it returns a status, and the console output is read back separately. It
        never attaches a channel, so it cannot fail the way `execute -i` did.
        """
        self._client.call("session.meterpreter_run_single", [str(session_id), str(command)])
        sleep(settle)
        try:
            reply = self._client.call("session.meterpreter_read", [str(session_id)])
        except Exception:
            return ""
        return str(reply.get("data") or "") if isinstance(reply, dict) else ""

    def _windows_command(self, metadata, request, deadline):
        """Run one Windows command line without an interactive channel.

        `execute -i` attaches the console to the process channel; through RPC that path
        answers only "Process/Channel created" and then fails in Rex's packing code (live
        2026-10-18, every command on nodes 5/19/44). The command therefore travels as a
        base64 batch file, its stdout/stderr go to one file, and the file is read back with
        the session's own `cat`. Nothing depends on console interactivity, quoting or an
        end marker inside the target's stream.
        """
        from secrets import token_hex

        nonce = token_hex(8)
        output = "C:\\Windows\\Temp\\agv_" + nonce + ".txt"
        # The argument string is parsed by meterpreter before cmd.exe sees it: a backslash
        # must be doubled or `C:\Windows\Temp` arrives as `C:WindowsTemp`, and an inner quote
        # must be escaped. `cmd.exe` is on PATH on the service's own environment; the full
        # PowerShell path is not always present (live 2026-10-18: every `-f powershell.exe`
        # answered "cannot find the file specified"), so the capture stays on cmd.
        inner = str(request.command).rstrip("\n").replace("\r\n", "\n").replace("\n", " & ")
        inner = inner.replace("\\", "\\\\").replace('"', '\\"')
        escaped = output.replace("\\", "\\\\")
        wrapped = ('execute -H -f cmd.exe -a "/c (' + inner + ') > ' + escaped
                   + ' 2>&1 & echo AGV_DONE >> ' + escaped + '"')
        self._meterpreter_single(metadata.session_id, wrapped, settle=1.5)
        captured = ""
        while monotonic() < deadline - self.READ_MARGIN:
            chunk = self._meterpreter_single(metadata.session_id, 'cat "' + escaped + '"',
                                             settle=0.8)
            if "AGV_DONE" in chunk:
                captured = chunk
                break
            if chunk.strip():
                captured = chunk
            remaining = deadline - monotonic()
            if remaining <= self.READ_MARGIN:
                break
            sleep(min(1.0, remaining))
        confirmed = "AGV_DONE" in captured
        lines = [line for line in captured.splitlines() if not line.startswith("AGV_DONE")]
        while lines and not lines[-1].strip():
            lines.pop()
        return SessionResult(operation_confirmed=confirmed,
                             output="\n".join(lines).strip())

    def _open_shell(self, metadata: SessionMetadata, write: str, read: str, budget: float) -> None:
        """A meterpreter channel reads text as its own commands, so open its shell first.

        Measured behaviour from the previous implementation: writing a command straight to a
        meterpreter session answers "Unknown command", while writing `shell` first and then the
        same text returns its output. Readiness is observed rather than timed, because the
        console prints a banner before it has finished switching into the channel.
        """
        if metadata.session_id in self._shells:
            return
        deadline = monotonic() + budget
        # `meterpreter_write` only feeds an already-interactive console; it does not open the
        # shell on an unattached session. `meterpreter_run_single("shell")` does (live probe
        # 2026-10-17: run_single("shell") produced the cmd prompt, write("shell") did not).
        self._client.call("session.meterpreter_run_single",
                          [metadata.session_id, self.SHELL_OPEN.strip()])
        # A fresh cmd.exe prints its banner after the RPC returns. A readiness marker written
        # before that prompt exists can be consumed by the old context, and the next command
        # is then lost (live 2026-10-17: `net user /domain` and `net use` produced only the
        # end marker). Wait for a prompt first.
        seen = ""
        prompt_deadline = min(deadline, monotonic() + self.SHELL_PROMPT_WAIT)
        while monotonic() < prompt_deadline - self.READ_MARGIN:
            chunk = self._read(read, metadata.session_id)
            seen += chunk
            if self._shell_prompt(seen):
                break
            if not chunk:
                sleep(min(self.READ_INTERVAL, max(0.0, prompt_deadline - monotonic())))
        # The marker goes out right away, unconditionally. Measured on a live Windows channel
        # (2026-10-17 run pipeline-live-20261017-02/rounds/003): writing `shell` on a session
        # that already sits in a shell answers `'shell' is not recognized ...` plus its prompt,
        # and a handshake that only asks for the marker after an *empty* read then waits for a
        # marker nobody sent -- the budget runs out and the channel is reported unconfirmed
        # while the same channel answers `echo agv-shell-ready` instantly when asked directly.
        self._client.call(write, [metadata.session_id, "echo " + self.SHELL_READY_MARKER + "\n"])
        seen, attempts = "", 0
        while monotonic() < deadline - self.READ_MARGIN:
            chunk = self._read(read, metadata.session_id)
            seen += chunk
            if any(line.strip() == self.SHELL_READY_MARKER for line in seen.splitlines()):
                self._shells.add(metadata.session_id)
                return
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            if not chunk and attempts < self.SHELL_OPEN_ATTEMPTS:
                attempts += 1
                self._client.call(write, [metadata.session_id,
                                          "echo " + self.SHELL_READY_MARKER + "\n"])
            elif not chunk:
                sleep(min(self.READ_INTERVAL, remaining))
        raise PipelineFailure("会话没接上", "session_backend_shell_channel_unconfirmed")

    @staticmethod
    def _shell_prompt(text: str) -> bool:
        """True when the captured tail is a real OS shell prompt, not meterpreter's."""
        for line in reversed(str(text).splitlines()):
            stripped = line.strip()
            if not stripped:
                continue
            # A Windows cmd prompt is a drive-letter path ending in '>'; the meterpreter
            # prompt ("meterpreter >") must not count, or the first command is written
            # before cmd.exe exists and is lost.
            if re.match(r"^[A-Za-z]:\\[^>]*>$", stripped):
                return True
            return stripped.endswith(("#", "$"))
        return False

    @staticmethod
    def _end_line(text: str, markers: tuple[str, ...]) -> int:
        """Last line starting with a declared end marker, or -1.

        Taking the last occurrence keeps a command echo that repeats the marker from cutting
        the capture short, so a marker must be printed as its own line.
        """
        found = -1
        for index, line in enumerate(text.splitlines()):
            stripped = line.strip()
            # The shell echoes the command that was written. When that command is the
            # marker probe (`echo agv-...`), the echoed line *ends* with the marker and
            # would otherwise confirm before the marker ever ran.
            echo_at = stripped.find("echo ")
            if echo_at >= 0 and any(
                    stripped[echo_at + 5:].strip().startswith(marker)
                    for marker in markers):
                continue
            # The marker normally starts its own line, but a channel that never printed a
            # trailing newline (a curl error code such as `000`) leaves it appended to the
            # last output. Accepting both keeps a complete receipt from being reported as a
            # timeout (live 2026-10-18, node 19: `000agv-call-end`).
            if any(stripped.startswith(marker) or stripped.endswith(marker)
                   for marker in markers):
                found = index
        return found

    def list_jobs(self) -> dict:
        """Peer-service jobs as a plain id -> description map.

        Exposed so an Action card can check what the peer service is running without the
        model composing raw RPC calls (and without credentials entering its transcript).
        """
        with self._operation():
            reply = self._client.call("job.list", [])
        return {str(key): str(value) for key, value in (reply or {}).items()}

    def run_module(self, module_type: str, name: str, options: dict, *, payload=None):
        """Start one peer-service module through the RPC module API.

        This is the deterministic alternative to typing `use/set/exploit` into the shared
        console: the RPC returns the job id the service actually created, so arming a
        handler does not depend on console echo or a busy prompt.
        """
        with self._operation():
            module = self._client.modules.use(str(module_type), str(name))
            for key, value in (options or {}).items():
                module[str(key)] = value
            return module.execute(payload=payload) if payload else module.execute()

    def job_info(self, job_id: str) -> dict:
        """One peer-service job's own record, including its datastore.

        The console text is a display detail: it can be split across reads or arrive a
        moment after the console reports idle. The job list and this record are the
        observable facts a caller reconciles against.
        """
        if not str(job_id or "").strip():
            raise PipelineFailure("参数没给到", "session_backend_job_id_required")
        with self._operation():
            reply = self._client.call("job.info", [str(job_id)])
        return reply if isinstance(reply, dict) else {}

    def stop_job(self, job_id: str) -> bool:
        """Stop one peer-service job by id; the peer service owns the job's lifetime."""
        if not str(job_id or "").strip():
            raise PipelineFailure("参数没给到", "session_backend_job_id_required")
        with self._operation():
            reply = self._client.call("job.stop", [str(job_id)])
        return bool(isinstance(reply, dict) and reply.get("result") == "success")

    def console(self, lines, *, timeout=30.0, await_markers=()):
        """Send console lines and return everything the console printed back.

        Handlers and other console-owned resources are armed here rather than through the
        module API, which does not expose payload options such as LHOST/LPORT.

        ``await_markers`` turns the read into a wait: a freshly created console answers the
        first read with its banner and ``busy=false``, which would otherwise end the capture
        before a module has printed anything (live 2026-10-18: the psexec module ran but its
        output was never collected). With markers the caller keeps reading until one of them
        appears or the budget runs out.
        """
        markers = tuple(str(value) for value in (await_markers or ()) if str(value))
        with self._operation(timeout):
            console = self._console
            # A console that is still running the previous command ignores new writes: the
            # lines are dropped and the call reports an empty result (live 2026-10-18, node
            # 48 bind after the psexec module left the console busy). Drain to idle first.
            idle_deadline = monotonic() + min(10.0, timeout)
            while True:
                try:
                    reply = console.read()
                except Exception:
                    break
                if not reply.get("busy") or monotonic() >= idle_deadline:
                    break
                sleep(0.2)
            for line in lines:
                console.write(str(line).rstrip("\n") + "\n")
            deadline = monotonic() + timeout
            text = ""
            while True:
                try:
                    reply = console.read()
                except Exception:
                    # A read that cannot complete ends this capture; whether the console
                    # actually came up is observed by the caller, not assumed here.
                    break
                text += str(reply.get("data") or "")
                remaining = deadline - monotonic()
                if markers:
                    if any(marker in text for marker in markers) or remaining <= 0:
                        break
                    sleep(min(0.25, remaining))
                    continue
                if remaining <= 0 or not reply.get("busy"):
                    break
                sleep(min(0.2, remaining))
            return text

    def execute(self, reference: SessionReference, request: SessionRequest) -> SessionResult:
        """Bind one request to a pinned session and return its raw capture.

        The channel follows the session's own type; a meterpreter channel has its shell opened
        and observed before the first request. Confirmation means the declared end marker was
        observed before the deadline -- never that the business condition holds -- and an
        unobserved result is reported as unconfirmed instead of being retried.
        """
        if not isinstance(reference, SessionReference) or not isinstance(request, SessionRequest):
            raise PipelineFailure("参数没给到", "session_backend_execute_input_invalid")
        with self._operation(request.timeout) as deadline:
            metadata = self._get(reference.session_id, reference.instance_id)
            write, read = self._channel(metadata)
            if metadata.type == "meterpreter" and metadata.platform == "windows":
                # A Windows channel has one non-interactive path: write a batch file, run it,
                # read the capture file. See `_windows_command`.
                return self._windows_command(metadata, request, deadline)
            # One channel for every meterpreter session: open its shell once and write each
            # command line, waiting for the declared end marker. The earlier Windows special
            # case used `execute -i`, which attaches the console to an interactive channel:
            # it answered only "Process/Channel created", then every later call died with a
            # Rex packing error (live 2026-10-18, node 44 pre and nodes 5/19 on PC1), so the
            # observation was never the command's output. `shell_write`/`shell_read` is the
            # documented RPC surface for the session's own shell and is what the POSIX path
            # already used.
            if metadata.type == "meterpreter" and metadata.platform != "windows":
                # POSIX meterpreter: carry the whole command as base64 and pipe it into
                # /bin/sh. Quoting never reaches Rex, so a Python one-liner with nested
                # quotes runs instead of becoming "Unmatched quote" (live 2026-10-17).
                session_api = getattr(getattr(self._client, "sessions", None), "session", None)
                if callable(session_api):
                    import base64
                    session = session_api(str(metadata.session_id))
                    blob = base64.b64encode(request.command.encode("utf-8")).decode("ascii")
                    wrapped = ('execute -f /bin/sh -a "-c \'echo ' + blob
                               + ' | base64 -d | /bin/sh\'" -i')
                    result = self._meterpreter_command(
                        session, wrapped, deadline, request.end_markers)
                    end = self._end_line(result.output, request.end_markers)
                    lines = result.output.splitlines()
                    return SessionResult(operation_confirmed=end >= 0,
                                         output="\n".join(lines[:end] if end >= 0
                                                          else lines).strip())
                self._open_shell(metadata, write, read, deadline - monotonic())
                deadline = monotonic() + request.timeout
                self._client.deadline = deadline
            if metadata.type == "meterpreter":
                # Windows meterpreter reaches cmd.exe the same way POSIX reaches /bin/sh:
                # one shell channel, opened once and observed by its readiness marker.
                self._open_shell(metadata, write, read, deadline - monotonic())
                deadline = monotonic() + request.timeout
                self._client.deadline = deadline
            # A meterpreter/shell channel consumes one line per write. Sending the command
            # and its end marker as one multi-line write leaves the marker in the input
            # buffer: the output arrives, but the marker is never executed, so a perfectly
            # good observation is reported unconfirmed. Write each line separately.
            for line in request.command.rstrip("\n").splitlines():
                self._client.call(write, [metadata.session_id, line + "\n"])
            captured = ""
            first_output_deadline = min(deadline, monotonic() + self.FIRST_OUTPUT_WAIT)
            last_output = None
            while True:
                # The budget is checked before every read, with a margin: a read issued at the
                # boundary is refused by the client's own guard and used to be reported as an
                # unusable channel instead of "no confirmable effect" (live 2026-10-16 run
                # pipeline-live-20261016-60/rounds/004 step 1 attempt 2).
                remaining = deadline - monotonic()
                if remaining <= self.READ_MARGIN:
                    break
                try:
                    chunk = self._read(read, metadata.session_id)
                except PipelineFailure as exc:
                    detail = str(getattr(exc, "detail", exc))
                    # A dropped keep-alive is a transport event, not an observation. The
                    # peer service keeps the target shell alive; reconnect and keep reading
                    # until this operation's own deadline, without replaying the command.
                    if "rpc_unconfirmed" not in detail or remaining <= 1.0:
                        raise
                    sleep(0.5)
                    continue
                if chunk:
                    captured += chunk
                    last_output = monotonic()
                if self._end_line(captured, request.end_markers) >= 0:
                    break
                now = monotonic()
                # The marker remains the completion signal. If nothing at all arrived in
                # the first-output window, stop waiting; never turn a silent command into
                # an indefinite hold.
                if last_output is None and now >= first_output_deadline:
                    break
                remaining = deadline - monotonic()
                if remaining > self.READ_MARGIN:
                    sleep(min(self.READ_INTERVAL, remaining))
            end = self._end_line(captured, request.end_markers)
            lines = captured.splitlines()
            output = "\n".join(lines[:end] if end >= 0 else lines).strip()
            return SessionResult(operation_confirmed=end >= 0, output=output)

    #: A console command declares no end marker: the capture ends after QUIET_WINDOW seconds
    #: without new output, and never waits longer than FIRST_OUTPUT_WAIT for the first byte.
    CONSOLE_TIMEOUT = 60.0
    #: A meterpreter command is delivered on the session's own stream, not through the
    #: console. Its read stream has no busy flag, so completion is "output arrived, then
    #: stayed quiet". `load kiwi` prints `Loading extension kiwi...`, pauses, then prints the
    #: banner, which is why the window is three seconds rather than a token gap.
    #: A one-shot `execute -i` prints "Process/Channel created" immediately, then the real
    #: command runs. A 3s quiet window can end before a 3-packet ping returns its result
    #: (live 2026-10-17: node 44 pre saw only the process line). Six seconds covers the
    #: command's own bounded wait plus the marker.
    METERPRETER_QUIET = 6.0
    METERPRETER_FIRST_OUTPUT = 15.0

    def console_command(self, reference: SessionReference, command: str, *,
                        timeout: float = CONSOLE_TIMEOUT) -> SessionResult:
        """Send one command to the session's own console layer and wait for its completion flag.

        The shell layer and the console layer are different input streams. ``execute`` opens a
        sub-shell on a meterpreter session and keeps writing there, so a command that belongs to
        the session's own command set can never reach it through that path: live 2026-10-16 run
        pipeline-live-20261016-60 asked for console commands and had every write answered by
        cmd.exe ("'sysinfo' is not recognized as an internal or external command").

        The MSF console itself reports command completion through ``busy=false``. Use that
        protocol flag instead of guessing with a quiet window: enter the session, write the
        command, drain the console until it is idle, then background the session. A command
        that never reaches idle before the budget is unconfirmed, not a guessed result.
        """
        if not isinstance(reference, SessionReference):
            raise PipelineFailure("参数没给到", "session_backend_execute_input_invalid")
        text = str(command or "").strip("\n")
        if not text.strip():
            raise PipelineFailure("参数没给到", "session_backend_command_required")
        with self._operation(timeout) as deadline:
            metadata = self._get(reference.session_id, reference.instance_id)
            console = self._console
            session_api = getattr(getattr(self._client, "sessions", None), "session", None)
            if metadata.type == "meterpreter" and callable(session_api):
                # `sessions -i` keeps the console busy while the session is interactive, so
                # the console's own flag can never report completion (live 2026-10-17,
                # node 5 pre: three console commands each waited the full 60s and returned
                # no output). The session stream has the command's output; use it directly.
                return self._meterpreter_command(session_api(str(metadata.session_id)),
                                                 text, deadline)

            def drain():
                """Read until the console says it is idle; returns (text, idle)."""
                captured = ""
                while True:
                    remaining = deadline - monotonic()
                    if remaining <= self.READ_MARGIN:
                        return captured, False
                    try:
                        reply = console.read()
                    except Exception:
                        return captured, False
                    captured += str(reply.get("data") or "")
                    if not reply.get("busy"):
                        return captured, True
                    sleep(min(0.05, remaining))

            # Enter the session's own command context, run the command, then leave it. The
            # console's busy flag covers both the session switch and the command itself.
            console.write("sessions -i " + str(metadata.session_id) + "\n")
            _, ready = drain()
            if not ready:
                return SessionResult(operation_confirmed=False, output="")
            console.write(text + "\n")
            output, complete = drain()
            console.write("background\n")
            drain()
            return SessionResult(operation_confirmed=bool(complete and output.strip()),
                                 output=output.strip())

    def _meterpreter_command(self, session, command, deadline, end_markers=()) -> SessionResult:
        """One meterpreter command on the session's own read/write stream."""
        try:
            session.read()  # drop whatever an earlier request left buffered
        except Exception:
            pass
        # `meterpreter_run_single` is the RPC that executes one command on an unattached
        # session; `meterpreter_write` only feeds an interactive console and produced no
        # output here (live probe 2026-10-17: write -> empty, runsingle -> getuid output).
        immediate = str(session.runsingle(command) or "")
        captured, started = immediate, monotonic()
        last = started if immediate.strip() else None
        retries = 0
        while True:
            remaining = deadline - monotonic()
            if remaining <= self.READ_MARGIN:
                break
            try:
                chunk = session.read()
            except Exception as exc:
                # The read stream can lose one keep-alive under load while the meterpreter
                # session stays alive. Retry the read (never the command) a bounded number
                # of times; a persistent error still ends the capture as unconfirmed.
                name = type(exc).__name__
                if (retries < 3 and remaining > 1.0
                        and ("Connection" in name or "Timeout" in name
                             or "rpc_unconfirmed" in str(exc))):
                    retries += 1
                    sleep(0.5)
                    continue
                break
            now = monotonic()
            if chunk:
                captured += str(chunk)
                last = now
                # The command already carries its own end marker. Waiting the full quiet
                # window after it only adds latency (6 s on every POSIX meterpreter step).
                if end_markers and self._end_line(captured, end_markers) >= 0:
                    break
            elif last is None:
                if now - started >= self.METERPRETER_FIRST_OUTPUT:
                    break
            elif now - last >= self.METERPRETER_QUIET:
                break
            sleep(min(0.1, remaining))
        return SessionResult(operation_confirmed=bool(captured.strip()),
                             output=captured.strip())

    def _listing(self) -> dict[str, SessionMetadata]:
        # A dropped keep-alive under load is not a missing session. Re-read with backoff
        # before reporting the channel unusable: the peer service recovers within seconds
        # and a bind step must not fail on one lost request (live 2026-10-18, node 22 bind).
        rows = None
        last = None
        # A long run can lose the RPC connection for several seconds (a lab network or
        # service blip). One node must not fail on that: give the peer service about a
        # minute to come back before reporting the channel unusable.
        delays = (2.0, 4.0, 8.0, 12.0, 16.0)
        for attempt in range(len(delays) + 1):
            try:
                rows = self._client.sessions.list
                break
            except Exception as exc:
                last = exc
                if attempt == len(delays):
                    raise PipelineFailure(
                        "会话没接上",
                        "session_backend_rpc_unconfirmed:" + type(exc).__name__) from None
                sleep(delays[attempt])
        if rows is None:
            raise PipelineFailure("会话没接上", "session_backend_rpc_unconfirmed:"
                                  + type(last).__name__)
        result = {}
        for sid, row in rows.items():
            # uuid identifies this session incarnation; exploit_uuid does not.
            if any(not isinstance(row.get(key), str) or not row[key].strip()
                   for key in ("uuid", "type", "session_host", "platform")):
                raise PipelineFailure("会话没接上", "session_backend_metadata_incomplete")
            result[str(sid)] = SessionMetadata(session_id=str(sid), instance_id=row["uuid"],
                type=row["type"], host=row["session_host"], platform=row["platform"],
                callback_endpoint=row.get("tunnel_local"))
        return result

    def list_sessions(self) -> dict[str, SessionMetadata]:
        with self._operation():
            return self._listing()

    def _get(self, session_id, instance_id=None):
        if not isinstance(session_id, str) or not session_id.strip():
            raise PipelineFailure("参数没给到", "session_backend_session_id_required")
        metadata = self._listing().get(session_id)
        if metadata is None:
            raise PipelineFailure("会话没接上", "session_backend_session_missing")
        if instance_id is not None and metadata.instance_id != instance_id:
            raise PipelineFailure("会话没接上", "session_backend_instance_changed")
        return metadata

    def get_session(self, session_id: str, *, instance_id: str | None = None) -> SessionMetadata:
        with self._operation():
            return self._get(session_id, instance_id)

    def get_instance_id(self, session_id: str) -> str:
        return self.get_session(session_id).instance_id

    def reference_for(self, session_id: str, *, previous: SessionReference | None = None) -> SessionReference:
        """The sole handoff to the existing migration/closeout reference contract.

        previous must come from durable owner/registry state, not a process cache.
        This creates no registry entry and never silently updates a pinned request.
        """
        metadata = self.get_session(session_id)
        if previous and (previous.session_id, previous.instance_id) == (session_id, metadata.instance_id):
            return previous
        return SessionReference(session_id=session_id, instance_id=metadata.instance_id,
                                generation=previous.generation + 1 if previous else 1)
