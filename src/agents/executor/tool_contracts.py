"""Action tool contracts: the request shapes the Action stage accepts.

The Pre stage keeps its own small contract (``cmd`` / ``code`` / ``tool``); the Action
stage needs a wider but still strict one, so that a card can name a tool that really
exists -- an HTTP request, a staged file, or one RPC action on the peer service --
instead of describing commands the runtime would have to compose for it.

``cmd`` / ``code`` / ``tool`` keep their previous shape and meaning. The added tools are:

* ``http``  -- one HTTP request issued from the execution point;
* ``stage`` -- write one text file at an execution-point path;
* ``msf``   -- one observation on the peer service the runtime is already connected to
  (list or stop a job). Arming a listener is not a card action: the runtime builds the
  artifact and arms the handler as one step.
* ``control`` -- one action on the control box itself: serve a file to a target that pulls
  it, available from a node whose frozen execution entry is somewhere else entirely.
* ``session`` -- one command on the **session's own console layer** of the channel this node's
  attempt is already bound to. ``cmd``/``code`` write to a shell opened on that channel, which
  is a different input stream, so a command that belongs to the session's command set cannot be
  reached that way.

Nothing here decides whether a request is a good idea: contracts only fix the shape, the
transport, and what a receipt must contain.
"""

import json
import shlex
import subprocess
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

#: Actions the peer-service tool exposes. Deliberately small: observe, stop. The listener
#: belongs to the runtime, which builds the artifact and arms the handler together.
PEER_ACTIONS = ("job_list", "job_stop")


class HttpRequestContent(BaseModel):
    """One HTTP request, addressed by the model, issued from the execution point."""

    model_config = ConfigDict(extra="forbid", strict=True)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    url: str = Field(min_length=1)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    multipart: dict[str, str] = Field(default_factory=dict)
    """Form fields for a multipart upload; a value may be a local file path prefixed
    with ``@`` to send that file, exactly as the execution point's client reads it."""


class StageContent(BaseModel):
    """Write one text file at an execution-point path."""

    model_config = ConfigDict(extra="forbid", strict=True)
    path: str = Field(min_length=1, pattern=r"^/")
    text: str = Field(min_length=1)


class PeerServiceContent(BaseModel):
    """One action on the peer service the runtime already holds a connection to."""

    model_config = ConfigDict(extra="forbid", strict=True)
    action: Literal["job_list", "job_stop"]
    job_id: str = Field(default="", pattern=r"^[0-9]*$")

    @model_validator(mode="after")
    def action_arguments(self):
        if self.action == "job_stop" and not self.job_id.strip():
            raise ValueError("job_stop needs a job id")
        return self


class ControlContent(BaseModel):
    """One action on the control box: the runtime's own side of the run.

    A node whose frozen execution entry is the target still needs a fetch service started
    somewhere the runtime owns; that is not a target action. The payload itself is built by
    the runtime before the Action starts, together with the handler that receives it.
    """

    model_config = ConfigDict(extra="forbid", strict=True)
    action: Literal["serve_file", "remote_process", "credential_test"]
    directory: str = Field(default="", pattern=r"^(/[A-Za-z0-9_./-]*)?$")
    port: int | None = Field(default=None, ge=1, le=65535)
    host: str = Field(default="", max_length=255)
    command: str = Field(default="", max_length=8192)
    #: Opaque reference; the owner resolves it. A secret is never accepted here.
    credential_ref: str = Field(default="", max_length=255)
    #: Credential-test scanner; separate from the remote-execution ``method`` above.
    test_method: Literal["smb", "ldap", "winrm", "kerberos"] = "smb"
    timeout: int = Field(default=60, ge=1, le=300)
    method: Literal["wmic", "psexec", "msf_psexec", "wmiexec", "smb_copy",
                    "schtasks", "sc", "smbexec"] = "wmic"
    local_path: str = Field(default="", max_length=1024)
    remote_path: str = Field(default="", max_length=1024)

    @model_validator(mode="after")
    def action_arguments(self):
        if self.action == "serve_file":
            if not (self.directory and self.port):
                raise ValueError("serve_file needs directory and port")
        elif self.action == "remote_process":
            if not self.host.strip():
                raise ValueError("remote_process needs host")
            # Native-upload psexec runs the runtime's own payload as the service binary;
            # there is no command line for the model to compose at that step.
            if self.method != "msf_psexec" and not self.command.strip():
                raise ValueError("remote_process needs host and command")
        return self


class SessionConsoleContent(BaseModel):
    """One command handed to the session's own console layer.

    Deliberately one line and no completion marker: a console command has no reliable end
    signal, so the channel reports what it observed instead of waiting for one. The card says
    which command set this node's channel speaks; the contract only fixes the shape.
    """

    model_config = ConfigDict(extra="forbid", strict=True)
    command: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def one_console_line(self):
        if "\n" in self.command.strip():
            raise ValueError("a console command is one line")
        return self


CONTENT_MODELS = {"http": HttpRequestContent, "stage": StageContent,
                  "msf": PeerServiceContent, "control": ControlContent,
                  "session": SessionConsoleContent}

#: Tools whose content is a structured object rather than free-form command text.
STRUCTURED_TOOLS = tuple(CONTENT_MODELS)

#: Tools that run on the runtime's own side (the control box or the peer service). A node
#: whose frozen execution entry is the target still needs these, so they are exempt from the
#: frozen-entry check and never run a command on the target.
CONTROL_SIDE_TOOLS = ("msf", "control")

#: The control plane's execution face. A control-plane action is not exempt from freezing:
#: it freezes **this** face as its own, which is why it can be issued from any node.
CONTROL_PLANE_FACE = "kali"

#: Action names that identify the tool a flattened request meant.
ACTION_TO_TOOL = {name: "msf" for name in PEER_ACTIONS}
ACTION_TO_TOOL.update({"serve_file": "control", "remote_process": "control"})

#: How a declared interpreter is invoked. A request names the interpreter in ``name`` and
#: writes its own syntax in ``content``; the runtime -- not the model -- builds the command line
#: that actually reaches the execution face. Live 2026-10-16: the Pre model emitted
#: ``{"tool":"cmd","name":"powershell","content":"Get-Process -Name 'lsass' ..."}`` and the guest
#: returned the real query (ProcessName lsass / Id 504 / carrier vmware_tools), while the same
#: content sent verbatim without the wrapper is a cmd error.
INTERPRETER_INVOCATIONS = {
    #: Older shells take a command line as it is: cmd, sh and bash are the platform's own
    #: shells, so a step naming one of them is already a command line. A language runtime is
    #: different -- it needs its own flag before the body, which is what this table adds.
    "powershell": "powershell -NoProfile -Command",
    "powershell.exe": "powershell -NoProfile -Command",
    "pwsh": "pwsh -NoProfile -Command",
    "python": "python -c",
    "python3": "python3 -c",
}


def interpreter_command(name, content, *, platform):
    """Build the command line for one request: declared interpreter + its own syntax.

    ``content`` is what the model wrote for that interpreter, so it is quoted as one argument
    instead of being rewritten. Naming the platform's own shell (cmd on Windows, sh/bash on
    POSIX) leaves the line as-is.
    """
    text = str(content)
    key = str(name or "").strip()
    invocation = INTERPRETER_INVOCATIONS.get(key.lower())
    if invocation is None:
        return text
    # A step may already spell the whole command line (name=python3, content="python3 /tmp/x.py").
    # Wrapping that again would run the line as a program body, so the declared program at the
    # head of the content means "already built": pass it through untouched.
    head = text.strip().split(" ", 1)[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    if head.removesuffix(".exe") == key.lower().removesuffix(".exe"):
        return text
    # Only the quote itself is escaped: the content is the interpreter's own syntax and must
    # not be rewritten (a path's backslashes belong to the interpreter, not to this builder).
    quoted = '"' + text.replace('"', '\\"') + '"'
    return invocation + " " + quoted


def _ps_quote(value) -> str:
    """One PowerShell literal; the surrounding line is built by the runtime."""
    return "'" + str(value).replace("'", "''") + "'"


def tool_command(name, argv, *, platform):
    """One program plus argv, in the platform's own command-line grammar.

    On Windows the line goes through ``cmd /c``: a meterpreter ``shell`` channel is cmd.exe,
    while a PowerShell channel parses the same ``cmd /c`` line. ``subprocess.list2cmdline``
    owns the quoting rules instead of this module inventing them.
    """
    values = [str(name), *(str(value) for value in argv)]
    if str(platform).lower() == "windows":
        return "cmd /c " + subprocess.list2cmdline(values)
    return shlex.join(values)


def code_command(name, content, *, platform):
    """One script body, executed by the interpreter the model named.

    ``cmd`` names a command line and passes through; ``code`` names a program *and* a body,
    so a shell body gets its ``-c`` and a language body gets the invocation that runs it.
    """
    key = str(name or "").strip().lower()
    text = str(content)
    if key in {"bash", "sh"}:
        if str(platform).lower() == "windows":
            return key + ' -c "' + text.replace('"', '\\"') + '"'
        return key + " -c " + shlex.quote(text)
    if key in {"python", "python3", "powershell", "powershell.exe", "pwsh"}:
        return interpreter_command(key, text, platform=platform)
    raise ValueError("Unsupported code interpreter")


def command_line(step, *, platform):
    """The one place a ``cmd`` / ``code`` / ``tool`` request becomes a command line."""
    if step.tool == "tool":
        return tool_command(step.name, step.content, platform=platform)
    if step.tool == "code":
        return code_command(step.name, step.content, platform=platform)
    return interpreter_command(step.name, step.content, platform=platform)


def normalize_action_request(request):
    """Unfold the two shapes a model actually writes for a structured step.

    Cards show the request object; a model sometimes wraps it in a ``cmd`` step, either by
    pasting the whole object as the command text or by naming the action in ``content``.
    Both carry an unambiguous intent, so they are unfolded here rather than failing the run
    (evidence: output/pipeline-live-20261016-27 round 003, …-31 rounds 003 and 005).
    """
    if not isinstance(request, dict):
        return request
    tool, content = request.get("tool"), request.get("content")
    if tool == "cmd" and isinstance(content, str) and content.strip().startswith("{"):
        try:
            inner = json.loads(content)
        except ValueError:
            return request
        if isinstance(inner, dict) and (inner.get("content") or inner.get("arguments")):
            # The card shows the `{tool, target, arguments}` shape; a model sometimes pastes
            # that object as the command text of a `cmd` step (live 2026-10-18, node 28: the
            # serve_file request ran as a shell line, so no fetch service was started and the
            # payload fetch failed with "Connection refused").
            if inner.get("tool") in STRUCTURED_TOOLS:
                return inner
            if inner.get("tool") in ACTION_TO_TOOL:
                action = inner["tool"]
                return {"tool": ACTION_TO_TOOL[action], "name": action,
                        "via": inner.get("target") or request.get("via"),
                        "content": {"action": action, **(inner.get("arguments") or {})}}
        return request
    if tool in ("cmd", "code", "tool") and isinstance(content, dict):
        action = content.get("action")
        if action in ACTION_TO_TOOL:
            return {"tool": ACTION_TO_TOOL[action], "name": str(action),
                    "via": request.get("via"), "content": content}
    if tool in ("cmd", "code") and isinstance(content, dict):
        # A model may put the structured arguments inside the legacy content slot:
        # {"tool":"cmd","content":{"interpreter":"cmd","command":"..."}}.
        key = "command" if tool == "cmd" else "body"
        value = content.get(key)
        if isinstance(value, str) and value.strip():
            return {"tool": tool, "name": str(content.get("interpreter") or "cmd"),
                    "via": request.get("via"), "content": value}
    if tool == "tool" and isinstance(request.get("name"), str) and isinstance(content, dict):
        name = request["name"]
        if name in ACTION_TO_TOOL and "action" not in content:
            # Models sometimes write the legacy `tool`/`name` pair with the control
            # tool's arguments at the top level; unfold it the same way as `content.action`.
            return {"tool": ACTION_TO_TOOL[name], "name": name,
                    "via": request.get("via"), "content": {"action": name, **content}}
    return request


class ActionRequest(BaseModel):
    """One Action step: which tool, on which execution face, with what content."""

    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    tool: Literal["cmd", "code", "tool", "http", "stage", "msf", "control", "session"]
    name: str = Field(min_length=1, pattern=r"^[A-Za-z0-9_.+-]+$")
    #: ``kali`` -- the run's entry point; ``session`` -- the channel this node is bound to.
    via: Literal["kali", "session"]
    content: str | list[str] | dict

    @model_validator(mode="before")
    @classmethod
    def accept_tool_contract(cls, data):
        from src.tools.adapt import to_legacy_request
        return to_legacy_request(data)

    @model_validator(mode="after")
    def content_matches_tool(self):
        if (self.tool in CONTROL_SIDE_TOOLS and self.name != "remote_process"
                and self.via != CONTROL_PLANE_FACE):
            raise ValueError(f"{self.tool} runs on the control plane: via must be {CONTROL_PLANE_FACE}")
        if self.tool in CONTENT_MODELS:
            if not isinstance(self.content, dict):
                raise ValueError(f"{self.tool} content must be an object")
            CONTENT_MODELS[self.tool].model_validate(self.content)
            return self
        if self.tool == "tool":
            if not isinstance(self.content, list):
                raise ValueError("tool content must be an argv array")
        elif not isinstance(self.content, str) or not self.content.strip():
            raise ValueError("cmd/code content must be nonempty text")
        if self.tool == "code" and self.name not in {"python3", "bash", "sh", "powershell"}:
            raise ValueError("Unsupported code interpreter")
        if "\x00" in self.content or (isinstance(self.content, list)
                                      and any("\x00" in item for item in self.content)):
            raise ValueError("NUL is not executable content")
        return self

    def parsed_content(self):
        """The validated content object for the structured tools."""
        if self.tool not in CONTENT_MODELS:
            return self.content
        return CONTENT_MODELS[self.tool].model_validate(self.content)
