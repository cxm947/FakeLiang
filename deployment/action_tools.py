"""Dispatch the Action stage's structured tools.

The runtime's job here is parsing and dispatch only: build the deterministic command a
structured request asks for, hand it to the declared execution face, and return the receipt
unchanged. No tool decides what the model should do next, and no credential is ever part of
the request the model emits.

The peer-service tool exists so a card can observe or stop a job on the service the runtime
is already connected to, instead of the model composing a raw RPC call, which would put the
service credentials into the transcript. Arming the payload handler is not a card action:
the runtime builds the artifact and arms the listener as one step, from one payload name and
one port, before the Action starts.

The session-console tool exists because a shell and a console are different input streams on
the same channel: ``cmd``/``code`` write into a shell opened on the channel, while a command
belonging to the session's own command set has to be handed to the console layer.
"""

import base64
import shlex
import subprocess

from src.agents.executor.tool_contracts import (CONTROL_SIDE_TOOLS, STRUCTURED_TOOLS,
                                                ActionRequest, normalize_action_request)
from src.agents.pre_verifier.schema import ExecutionRequest
from src.session.execution_session import SessionReference
from src.session.pipeline_service import PipelineFailure
from src.tools.receipt import is_confirmed, make_receipt


def curl_command(spec, *, platform="linux") -> str:
    """One curl invocation, built only from the request's own fields."""
    parts = ["curl", "-sS", "-i", "--max-time", "60", "-X", spec.method, spec.url]
    for key, value in sorted(spec.headers.items()):
        parts += ["-H", str(key) + ": " + str(value)]
    if spec.multipart:
        for key, value in sorted(spec.multipart.items()):
            parts += ["-F", str(key) + "=" + str(value)]
    elif spec.body:
        parts += ["--data-binary", spec.body]
    if str(platform).lower() == "windows":
        # cmd /c is understood by both a cmd meterpreter shell and a PowerShell channel.
        return "cmd /c " + subprocess.list2cmdline(parts)
    return shlex.join(parts)


def stage_command(spec, *, platform="linux") -> str:
    """Write one text file at an execution-point path, then report its digest."""
    blob = base64.b64encode(spec.text.encode("utf-8")).decode("ascii")
    if str(platform).lower() == "windows":
        # The contract's path is POSIX-shaped; on Windows PowerShell treats /x as the
        # current drive's root, which keeps one card body valid for both platforms.
        return ("powershell -NoProfile -Command "
                "\"$b=[Convert]::FromBase64String('%s');"
                "[IO.File]::WriteAllBytes('%s',$b);"
                "(Get-FileHash -Algorithm SHA256 '%s').Hash\"" % (
                    blob, str(spec.path).replace("'", "''"),
                    str(spec.path).replace("'", "''")))
    path = shlex.quote(spec.path)
    command = ("mkdir -p \"$(dirname " + path + ")\" && printf %s " + shlex.quote(blob)
               + " | base64 -d > " + path + " && sha256sum " + path)
    if spec.path.endswith(".py"):
        # A transcribed program is checked where it will run: otherwise a transcription error
        # only shows up as a failed execution later (evidence: three attempts staged the same
        # broken text in output/pipeline-live-20261016-40/rounds/003).
        command += " && python3 -m py_compile " + path + " && echo agv-stage-compiled"
    return command


def dispatch(request, *, backend, transports, binding, control_binding=None, control=None,
             execute=None):
    """Run one structured tool request and return its receipt, or None when it is not one.

    ``cmd`` / ``code`` / ``tool`` are untouched: the caller keeps its own path for them.
    """
    normalized = normalize_action_request(request)
    parsed = ActionRequest.model_validate(normalized)
    unfolded = normalized is not request
    if parsed.tool not in STRUCTURED_TOOLS:
        return None
    spec = parsed.parsed_content()
    if parsed.tool == "session":
        receipt = _session_console(spec, backend=backend, binding=binding)
    elif parsed.tool == "msf":
        receipt = _peer_service(spec, backend=backend, binding=binding)
    elif parsed.tool == "control":
        # The control box is the runtime's own side, never the node's frozen face.
        receipt = _control_box(spec, transports=transports,
                               binding=control_binding or binding, control=control)
    else:
        platform = binding.get("platform", "linux")
        command = (curl_command(spec, platform=platform) if parsed.tool == "http"
                   else stage_command(spec, platform=platform))
        if execute is None:
            # The kali entry is the only face this module may call directly. A session-bound
            # node must pass `execute`, which the dispatcher owns.
            if binding.get("binding_kind") != "controller_entry":
                raise PipelineFailure("会话没接上", "action_tool_execution_face_missing")
            result = transports.execute(binding, ExecutionRequest(
                tool="code", name="bash", via="kali", content=command))
        else:
            try:
                result = execute(command)
            except PipelineFailure as exc:
                # Writing the same text to the same path twice is idempotent, so a dropped
                # RPC on a file write can be retried safely. Commands and scripts are not
                # retried here: their effect is not known after a lost reply.
                if parsed.tool != "stage" or getattr(exc, "retryable", None) is not True:
                    raise
                result = execute(command)
        receipt = make_receipt(confirmed=is_confirmed(result),
                               response=result.get("response"),
                               succeeded=result.get("command_succeeded"))
    if unfolded:
        # The compatibility layer keeps both readings: what the model sent and what ran.
        receipt = {**receipt, "normalized_request": parsed.model_dump(),
                   "request_original": request}
    return receipt


def _session_console(spec, *, backend, binding):
    """One console command on the channel this attempt is already bound to.

    The reference comes from the frozen binding, never from the model: a card names the
    command, the runtime resolves which session carries it.
    """
    if backend is None:
        raise PipelineFailure("会话没接上", "action_tool_session_unavailable")
    reference = SessionReference.model_validate(binding.get("session") or {})
    result = backend.console_command(reference, spec.command)
    confirmed = bool(result.operation_confirmed)
    return make_receipt(
        confirmed=confirmed,
        response={"stdout": result.output, "return_code": 0 if confirmed else 1,
                  "transport_error": False, "timed_out": not confirmed,
                  "console_confirmed": confirmed,
                  "session_id": reference.session_id})


def _peer_service(spec, *, backend, binding):
    if backend is None:
        raise PipelineFailure("会话没接上", "action_tool_peer_service_unavailable")
    if spec.action == "job_list":
        jobs = backend.list_jobs()
        return make_receipt(confirmed=True, succeeded=True,
                            response={"jobs": jobs, "return_code": 0,
                                      "transport_error": False, "timed_out": False})
    if spec.action == "job_stop":
        stopped = backend.stop_job(spec.job_id)
        # The peer service answered; whether the job was still running is in the
        # response, not a transport fact. Do not turn "already stopped" into an
        # unknown outcome.
        return make_receipt(confirmed=True,
                            response={"job_id": spec.job_id, "stopped": stopped,
                                      "return_code": 0 if stopped else 1,
                                      "transport_error": False, "timed_out": False})
    raise PipelineFailure("参数没给到", "action_tool_peer_action_unsupported")


def _control_box(spec, *, transports, binding, control=None):
    """Run one control-box action through the runtime's own receiver channel."""
    if spec.action == "serve_file":
        if binding.get("binding_kind") != "controller_entry":
            raise PipelineFailure("会话没接上", "control_tool_requires_the_kali_entry")
        # The server must be detached in its own subshell and must not hold the transport's
        # channel open, or the call outlives the transport budget and comes back as a timeout
        # (evidence: output/pipeline-live-20261016-34/rounds/003 step 3). Readiness is then
        # observed on the port instead of assumed.
        command = ("cd " + shlex.quote(spec.directory)
                   + " && (setsid nohup python3 -m http.server " + str(spec.port)
                   + " --bind 0.0.0.0 >/tmp/agv_http.log 2>&1 </dev/null &) && sleep 1"
                   + " && (ss -lnt 2>/dev/null | grep -q ':" + str(spec.port) + " '"
                   + " && echo agv-http-started || echo agv-http-failed)")
        result = transports.execute(binding, ExecutionRequest(
            tool="code", name="bash", via=binding["via"], content=command))
        # The command prints its own readiness marker; a transport that delivered the
        # command is not the same as a listener that is up (review finding P1/P0). The
        # control-plane transport wraps its stdout in an MCP envelope, so read both shapes.
        response = result.get("response") or {}
        text = str(response.get("stdout") or "")
        if not text:
            for item in ((response.get("response") or {}).get("content") or []):
                if isinstance(item, dict) and item.get("type") == "text":
                    text += str(item.get("text") or "")
        ready = "agv-http-started" in text
        return make_receipt(confirmed=bool(result.get("effect_known")),
                            succeeded=ready,
                            response=result.get("response"))
    if spec.action == "remote_process":
        # The owner resolves the credential reference and writes the command into the
        # node's own session; the model never sees the secret.
        if control is None:
            raise PipelineFailure("参数没给到", "control_tool_remote_process_unavailable")
        return control("remote_process", {"host": spec.host, "command": spec.command,
                                          "credential_ref": spec.credential_ref,
                                          "method": spec.method,
                                          "local_path": spec.local_path,
                                          "remote_path": spec.remote_path})
    if spec.action == "credential_test":
        if control is None:
            raise PipelineFailure("参数没给到", "control_tool_credential_test_unavailable")
        return control("credential_test", {"host": spec.host,
                                           "credential_ref": spec.credential_ref,
                                           "method": spec.test_method,
                                           "port": spec.port,
                                           "timeout": spec.timeout})
    raise PipelineFailure("参数没给到", "action_tool_control_action_unsupported")
