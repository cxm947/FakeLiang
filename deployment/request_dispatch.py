"""One delivery path for every stage: the model's four fields decide where and what runs.

`tool` / `name` / `via` / `content` are the whole request, and this module is the only place
that turns them into an execution. There are exactly two execution surfaces:

* the **kali entry** (``binding_kind == "controller_entry"``), used only by the run's own
  starting point;
* a **registered session** (``binding_kind == "console_session"``), used by every other node.

There is no VMware-guest surface and no fallback. A node that names a session the owner does
not hold is refused: running the command somewhere else is a different action, not a retry.

``tool`` meanings:

* ``session``                    -> the channel's own console layer (``console_command``);
* ``cmd`` / ``code`` / ``tool``  -> the interpreter named in ``name`` builds the command line;
* ``http`` / ``stage``           -> curl / a staged text file, sent to the bound session (or
                                    the kali entry when this node is the entry);
* ``msf`` / ``control``          -> the runtime's own side (peer service / control box).
"""

from __future__ import annotations

from base64 import b64encode

from src.agents.executor.tool_contracts import (ActionRequest, CONTROL_SIDE_TOOLS,
                                                STRUCTURED_TOOLS, command_line,
                                                normalize_action_request)
from src.agents.pre_verifier.schema import ExecutionRequest
from src.session.execution_session import ExecutionBinding, SessionReference
from src.session.pipeline_service import PipelineFailure
from src.session.session_backend import SessionRequest
from src.tools.receipt import is_confirmed, make_receipt


#: Terminal marker the owner frames every session command with.
DEFAULT_END_MARKER = "agv-call-end"

#: Which layer of a channel actually ran the request. The tool names the layer -- `session`
#: is the channel's own console, `cmd/code/tool/http/stage` on a channel is its shell --
#: and the receipt says which one it really was.
SURFACE_BY_TOOL = {"session": "console", "msf": "peer_service", "control": "control_plane"}


def _as_binding(binding):
    return (binding if isinstance(binding, ExecutionBinding)
            else ExecutionBinding.model_validate(binding))


def console_reference(backend, binding):
    """The session this binding names, when the owner really holds it."""
    if backend is None or binding.binding_kind == "controller_entry":
        return None
    try:
        listed = backend.list_sessions()
    except Exception:
        return None
    if str(binding.session.session_id) not in {str(key) for key in listed}:
        return None
    return SessionReference.model_validate(binding.session.model_dump())


def deliver_to_reference(reference, command, *, backend, end_marker=DEFAULT_END_MARKER,
                         timeout=60.0):
    """The one place a command line is written into a session reference.

    Everything that talks to a session -- the shell surface of a binding, a claimed carrier, a
    runtime-composed tunnel or delivery command, a liveness probe -- comes through here, so the
    framing, the receipt shape and the error taxonomy exist once.
    """
    if backend is None:
        raise PipelineFailure("会话没接上", "dispatch_transport_unavailable")
    reference = SessionReference.model_validate(reference)
    result = backend.execute(reference, SessionRequest(
        command=_framed(str(command), end_marker), end_markers=(end_marker,), timeout=timeout))
    return make_receipt(confirmed=bool(result.operation_confirmed),
                        response=result.model_dump())


def deliver(binding, request, *, backend=None, transports=None, end_marker=DEFAULT_END_MARKER,
            timeout=60.0, control_binding=None, control=None, session="auto"):
    """Run one request and return ``{"effect_known", "response"}``.

    Nothing here decides whether the request is a good idea; it only fixes where the content
    goes and what command line carries it.

    ``session="force"`` means the caller already resolved this channel (a claimed carrier), so
    the binding's own reference is used. ``session="auto"`` resolves the binding's own session
    from the owner and refuses when it is absent. ``session="never"`` is accepted only for the
    controller entry; a non-entry binding may never leave its session.
    """
    binding = _as_binding(binding)
    normalized = normalize_action_request(request)
    # The current contract: `{tool, target, arguments}` with a registry tool name. It
    # reaches the same registry dispatcher, which unfolds it to the legacy view.
    if isinstance(normalized, dict) and "arguments" in normalized:
        from src.agents.executor.schema import ActionExecutionRequest
        from src.tools.adapt import to_legacy_request

        parsed = ActionExecutionRequest.model_validate(normalized)
        control_side = parsed.tool in {"msf_job", "credential_test", "serve_file",
                                       "remote_process"}
        if not control_side and parsed.target != binding.via:
            raise PipelineFailure("参数没给到", "Request changed the frozen execution entry")
        if parsed.target == "session" and not control_side:
            _require_session(binding, backend=backend, session=session)
        if parsed.tool == "session_command" and binding.binding_kind == "controller_entry":
            # The kali entry has no channel of its own; a console command needs a session.
            raise PipelineFailure("会话没接上", "session_console_requires_a_session")
        from deployment.action_tools import dispatch as dispatch_tool

        legacy = to_legacy_request(parsed.model_dump())

        def execute(command):
            return _deliver_line(binding, command, backend=backend, transports=transports,
                                 end_marker=end_marker, timeout=timeout, session=session,
                                 interpreter="sh")

        receipt = dispatch_tool(
            legacy, backend=backend, transports=transports,
            binding=binding.model_dump(exclude_none=True),
            control_binding=(control_binding or binding.model_dump(exclude_none=True)),
            control=control, execute=execute)
        if receipt is None:
            # run_command / run_script: the typed registry builds and executes the line.
            from src.tools.dispatch import execute_request
            result = execute_request(parsed.model_dump(), binding=binding,
                                     backend=backend, transports=transports,
                                     end_marker=end_marker)
            receipt = _receipt_from_result(result)
            surface = ("entry" if binding.binding_kind == "controller_entry"
                       else "console" if parsed.tool == "session_command" else "shell")
        else:
            surface = ("entry" if binding.binding_kind == "controller_entry"
                       else SURFACE_BY_TOOL.get(str(legacy.get("tool")), "shell"))
        return _with_surface(receipt, surface, observed=is_confirmed(receipt))
    # Stored four-field structured requests keep their old view.
    if isinstance(normalized, dict) and normalized.get("tool") in STRUCTURED_TOOLS:
        structured = ActionRequest.model_validate(normalized)
        # Control-plane tools are exempt: a session-bound node still builds its payload
        # and serves it from the kali entry. The contract already pins those tools to
        # via=kali; comparing them with the node's frozen via would reject every hand-over.
        if structured.tool not in CONTROL_SIDE_TOOLS:
            _check_frozen_via(binding, structured)
        if structured.via == "session" and structured.tool not in CONTROL_SIDE_TOOLS:
            _require_session(binding, backend=backend, session=session)
        if structured.tool == "session" and binding.binding_kind == "controller_entry":
            # The kali entry has no channel of its own; a console command needs a session.
            raise PipelineFailure("会话没接上", "session_console_requires_a_session")
        if structured.tool in {"msf", "control"}:
            from deployment.action_tools import dispatch as dispatch_tool

            box = ((control_binding if structured.tool == "control" else None)
                   or binding.model_dump(exclude_none=True))

            def execute(command):
                return _deliver_line(binding, command, backend=backend, transports=transports,
                                     end_marker=end_marker, timeout=timeout, session=session,
                                     interpreter="sh")

            receipt = dispatch_tool(structured.model_dump(), backend=backend,
                                    transports=transports,
                                    binding=binding.model_dump(exclude_none=True),
                                    control_binding=box,
                                    control=control,
                                    execute=execute if structured.tool in {"http", "stage"} else None)
            surface = ("entry" if binding.binding_kind == "controller_entry"
                       else SURFACE_BY_TOOL[structured.tool])
            return _with_surface(receipt, surface,
                                 observed=is_confirmed(receipt))
        from src.tools.dispatch import execute_request

        result = execute_request(structured.model_dump(), binding=binding,
                                 backend=backend, transports=transports,
                                 end_marker=end_marker)
        receipt = _receipt_from_result(result)
        surface = ("entry" if binding.binding_kind == "controller_entry"
                   else "console" if structured.tool == "session" else "shell")
        return _with_surface(receipt, surface, observed=is_confirmed(receipt))
    step = ExecutionRequest.model_validate(request)
    _check_frozen_via(binding, step)
    if step.via == "session":
        _require_session(binding, backend=backend, session=session)
    from src.tools.dispatch import execute_request

    result = execute_request(step.model_dump(), binding=binding, backend=backend,
                             transports=transports, end_marker=end_marker)
    receipt = _receipt_from_result(result)
    return _with_surface(receipt, "entry" if binding.binding_kind == "controller_entry"
                         else "shell", observed=is_confirmed(receipt))


def _check_frozen_via(binding, request):
    """The model may not move a request off the node's frozen entry."""
    declared = getattr(request, "via", None)
    if declared is not None and declared != binding.via:
        raise PipelineFailure("参数没给到", "Request changed the frozen execution entry")


def _require_session(binding, *, backend, session):
    """A request aimed at a session must name one the owner still holds.

    Provider-owned channels (ssh/webshell) carry their own reference; only the console
    needs the owner lookup. A missing console session is a refusal, never a fallback.
    """
    if session != "auto" or binding.binding_kind == "controller_entry":
        return
    if str(getattr(binding, "provider", None) or "msf") != "msf":
        return
    if console_reference(backend, binding) is None:
        raise PipelineFailure("会话没接上", "dispatch_session_missing")


def _deliver_line(binding, command, *, backend, transports, end_marker, timeout, session,
                  interpreter="sh"):
    """Send one already-built command line to the binding's one surface."""
    if binding.binding_kind == "controller_entry":
        if session == "force":
            raise PipelineFailure("参数没给到", "controller_entry_cannot_force_a_session")
        if transports is None:
            raise PipelineFailure("会话没接上", "dispatch_transport_unavailable")
        step = ExecutionRequest(tool="cmd", name="bash", via="kali", content=str(command))
        receipt = transports.execute(binding.model_dump(exclude_none=True), step)
        return _with_surface(receipt, "entry", observed=is_confirmed(receipt))
    reference = None
    provider_name = str(getattr(binding, "provider", None) or "msf")
    if provider_name != "msf":
        # SSH/WebShell providers own their own reference; there is no MSF console to look up.
        reference = SessionReference.model_validate(binding.session.model_dump())
    elif session == "force":
        reference = SessionReference.model_validate(binding.session.model_dump())
    elif session == "auto":
        reference = console_reference(backend, binding)
    else:
        # "never" is not a way out of a session: there is no other surface to use.
        raise PipelineFailure("会话没接上", "dispatch_session_missing")
    if reference is None:
        raise PipelineFailure("会话没接上", "dispatch_session_missing")
    command = _single_line(str(command), interpreter=interpreter, platform=binding.platform)
    from src.tools.providers.resolve import provider_for

    provider = provider_for(binding, backend=backend, transports=transports)
    result = provider.execute(command, end_marker=end_marker, timeout=timeout)
    confirmed = getattr(result, "receipt_confirmed", None)
    if confirmed is None:
        confirmed = bool(result.ok)
    code = getattr(result, "return_code", None)
    receipt = make_receipt(
        confirmed=confirmed,
        succeeded=getattr(result, "command_succeeded", None),
        response={**_surface_fields(
            {**({"stdout": result.output, "output": result.output}
                if getattr(result, "output_reported", True) else {}),
             "stderr": getattr(result, "error_output", ""),
             **({"return_code": code} if type(code) is int else {}),
             "transport_error": bool(getattr(result, "transport_error", False)),
             "timed_out": bool(getattr(result, "timed_out", False))},
            "shell", observed=bool(confirmed)),
            "provider": provider.name})
    return receipt


def _surface_fields(response, surface, *, observed):
    """Where the request was routed, and where it actually ran (evidence-based).

    One field could not carry both: a route choice says nothing about whether the command ran in
    that layer, and that conflation is exactly how a console command once ended up in a shell.
    """
    return {**response, "resolved_surface": surface,
            "observed_surface": surface if observed else None}


def _with_surface(receipt, surface, *, observed):
    """The surface travels inside the receipt's response, which every stage may extend."""
    value = dict(receipt or {})
    response = value.get("response")
    value["response"] = (_surface_fields(response, surface, observed=observed)
                         if isinstance(response, dict)
                         else {**_surface_fields({}, surface, observed=observed),
                               "raw": response})
    return value


def _receipt_from_result(result):
    """One receipt from a provider/tool result, preserving absence of a field."""
    confirmed = getattr(result, "receipt_confirmed", None)
    if confirmed is None:
        confirmed = bool(result.ok)
    code = getattr(result, "return_code", None)
    return make_receipt(
        confirmed=confirmed,
        succeeded=getattr(result, "command_succeeded", None),
        response={**({"stdout": result.output, "output": result.output}
                     if getattr(result, "output_reported", True) else {}),
                  "stderr": getattr(result, "error_output", ""),
                  **({"return_code": code} if type(code) is int else {}),
                  "transport_error": bool(getattr(result, "transport_error", False)),
                  "timed_out": bool(getattr(result, "timed_out", False))})


def _framed(command: str, marker: str) -> str:
    """Keep the end marker on its own line so a command echo cannot end the capture."""
    return command.rstrip("\n") + "\necho " + marker + "\n"


def _single_line(command: str, interpreter="sh", *, platform="linux") -> str:
    """One line per channel write; a multi-line body is carried inside one line."""
    if "\n" not in command.strip():
        return command
    if str(platform).lower() == "windows":
        # One PowerShell channel write: UTF-16LE is what -EncodedCommand expects.
        blob = b64encode(command.encode("utf-16le")).decode("ascii")
        return "powershell -NoProfile -EncodedCommand " + blob
    from shlex import quote, split

    # `code` arrives already wrapped as `<runner> -c "<body>"`. Staging the whole wrapped
    # line as a script makes Python read `python3 -c` as its first statement (live
    # 2026-10-17: /tmp/agv_step.py line 1 "python3 -c ..." SyntaxError). Stage the body.
    try:
        parts = split(command)
    except ValueError:
        parts = []
    if len(parts) >= 3 and parts[1] == "-c":
        runner, body = parts[0], parts[2]
        if "python" in runner:
            blob = b64encode(body.encode("utf-8")).decode("ascii")
            return (f"printf %s {quote(blob)} | base64 -d > /tmp/agv_step.py && "
                    f"{runner} /tmp/agv_step.py")
        if runner in {"bash", "sh", "dash", "zsh"}:
            blob = b64encode(body.encode("utf-8")).decode("ascii")
            return (f"printf %s {quote(blob)} | base64 -d > /tmp/agv_step.sh && "
                    f"{runner} /tmp/agv_step.sh")

    blob = b64encode(command.encode("utf-8")).decode("ascii")
    suffix = "py" if "python" in str(interpreter) else "sh"
    runner = str(interpreter) if "python" in str(interpreter) else "sh"
    return (f"printf %s {quote(blob)} | base64 -d > /tmp/agv_step.{suffix} && "
            f"{runner} /tmp/agv_step.{suffix}")


__all__ = ["deliver", "deliver_to_reference", "console_reference", "DEFAULT_END_MARKER"]
