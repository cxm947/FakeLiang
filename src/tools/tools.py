"""Concrete capabilities. Transport is resolved by the caller's context."""

import base64
import shlex
from typing import Protocol

from .capability import ToolResult
from .schemas import (CredentialTestArgs, HttpRequestArgs, MsfJobArgs, RemoteProcessArgs,
                      RunCommandArgs, RunScriptArgs, ServeFileArgs, SessionCommandArgs,
                      StageFileArgs)


class ToolContext(Protocol):
    end_marker: str

    def provider_for(self, target: str): ...

    def control(self, name: str, arguments: dict) -> ToolResult: ...

    def platform_for(self, target: str) -> str: ...


def _quote(value: str, platform: str) -> str:
    if platform == "windows":
        return '"' + str(value).replace('"', '\\"') + '"'
    return shlex.quote(str(value))


def command_line(interpreter: str, command: str, *, platform: str = "linux") -> str:
    key = interpreter.lower()
    if platform == "linux" and key in {"cmd", "powershell"}:
        raise ValueError("windows interpreter on a linux target")
    if platform == "windows" and key in {"sh", "bash"}:
        raise ValueError("posix interpreter on a windows target")
    if key in {"sh", "bash", "cmd"}:
        return command
    if key == "powershell":
        return "powershell -NoProfile -Command " + _quote(command, "windows")
    if key == "python3":
        return "python3 -c " + _quote(command, platform)
    raise ValueError("unsupported interpreter: " + interpreter)


def script_line(interpreter: str, body: str, *, platform: str = "linux") -> str:
    key = interpreter.lower()
    if platform == "linux" and key == "powershell":
        raise ValueError("powershell on a linux target")
    if platform == "windows" and key in {"sh", "bash"}:
        raise ValueError("posix interpreter on a windows target")
    if key == "powershell":
        encoded = base64.b64encode(body.encode("utf-16le")).decode("ascii")
        return "powershell -NoProfile -EncodedCommand " + encoded
    if key == "python3":
        return "python3 -c " + _quote(body, platform)
    if key in {"bash", "sh"}:
        return key + " -c " + _quote(body, platform)
    raise ValueError("unsupported interpreter: " + interpreter)


class RunCommand:
    name = "run_command"
    description = ("Execute one command line on the target shell. Use for ping, sc, net, "
                   "curl, stat, id, whoami and similar single-line commands.")
    args_model = RunCommandArgs
    example = {"target": "session",
               "arguments": {"interpreter": "cmd", "command": "whoami"}}

    def execute(self, target, args, ctx):
        line = command_line(args.interpreter, args.command,
                            platform=ctx.platform_for(target))
        return ctx.provider_for(target).execute(
            line, end_marker=ctx.end_marker, timeout=args.timeout)


class RunScript:
    name = "run_script"
    description = ("Execute a multi-line script with the named interpreter. Use for "
                   "python3/bash logic; do not use it for a single command.")
    args_model = RunScriptArgs
    example = {"target": "session",
               "arguments": {"interpreter": "python3", "body": "print('ok')"}}

    def execute(self, target, args, ctx):
        from deployment.request_dispatch import _single_line
        platform = ctx.platform_for(target)
        line = _single_line(script_line(args.interpreter, args.body, platform=platform),
                            interpreter=args.interpreter, platform=platform)
        return ctx.provider_for(target).execute(
            line, end_marker=ctx.end_marker, timeout=args.timeout)


class HttpRequest:
    name = "http_request"
    description = "Send one HTTP request from the target and return status, headers and body."
    args_model = HttpRequestArgs
    example = {"target": "session",
               "arguments": {"method": "GET", "url": "http://host/"}}

    def execute(self, target, args, ctx):
        platform = ctx.platform_for(target)
        parts = ["curl", "-sS", "-i", "--max-time", "60", "-X", args.method, args.url]
        for key, value in sorted(args.headers.items()):
            parts += ["-H", f"{key}: {value}"]
        if args.multipart:
            for key, value in sorted(args.multipart.items()):
                parts += ["-F", f"{key}={value}"]
        elif args.body:
            parts += ["--data-binary", args.body]
        # POSIX shells use shlex quoting; cmd.exe does not treat single quotes as quoting.
        def quote(part):
            if platform == "windows":
                if any(ch in part for ch in ' &|<>^"'):
                    return '"' + part.replace('"', '\\"') + '"'
                return part
            return shlex.quote(part)
        line = " ".join(quote(part) for part in parts)
        return ctx.provider_for(target).execute(
            line, end_marker=ctx.end_marker, timeout=60)


class StageFile:
    name = "stage_file"
    description = "Write a text file on the target (base64 on disk, .py gets a syntax check)."
    args_model = StageFileArgs
    #: One meterpreter shell line can carry a few kilobytes; 800 produced five to six
    #: round trips for a small Python script and each round trip paid the channel's quiet
    #: window (37-44 s for a 3 KB card helper). 3000 keeps a normal card script to one or
    #: two writes without approaching the Rex packing limit.
    CHUNK = 3000
    example = {"target": "session",
               "arguments": {"path": "/tmp/x.py", "text": "print('ok')"}}

    def execute(self, target, args, ctx):
        blob = base64.b64encode(args.text.encode("utf-8")).decode("ascii")
        provider = ctx.provider_for(target)
        if ctx.platform_for(target) == "windows":
            line = ("powershell -NoProfile -Command \"$b=[Convert]::FromBase64String('%s');"
                    "[IO.File]::WriteAllBytes('%s',$b)\"" % (blob, args.path))
            return provider.execute(line, end_marker=ctx.end_marker, timeout=60)
        # A large script does not fit in one meterpreter shell line. Write the
        # base64 payload in bounded chunks, then decode once on the target.
        staged = str(args.path) + ".agv.b64"
        prep = ("mkdir -p \"$(dirname %s)\" && rm -f %s && : > %s"
                % (shlex.quote(args.path), shlex.quote(staged), shlex.quote(staged)))
        result = provider.execute(prep, end_marker=ctx.end_marker, timeout=30)
        if not result.ok:
            return result
        for index in range(0, len(blob), self.CHUNK):
            chunk = blob[index:index + self.CHUNK]
            result = provider.execute(
                "printf %%s %s >> %s" % (shlex.quote(chunk), shlex.quote(staged)),
                end_marker=ctx.end_marker, timeout=30)
            if not result.ok:
                return result
        line = ("base64 -d %s > %s && rm -f %s && sha256sum %s"
                % (shlex.quote(staged), shlex.quote(args.path),
                   shlex.quote(staged), shlex.quote(args.path)))
        if str(args.path).endswith(".py"):
            line += " && python3 -m py_compile " + shlex.quote(args.path) + " && echo agv-stage-compiled"
        return provider.execute(line, end_marker=ctx.end_marker, timeout=60)


class SessionCommand:
    name = "session_command"
    description = ("Send one command to the session's own console (meterpreter sysinfo/ps/"
                   "getuid/load/creds_all). System commands use run_command.")
    args_model = SessionCommandArgs
    example = {"target": "session", "arguments": {"command": "sysinfo"}}

    def execute(self, target, args, ctx):
        return ctx.provider_for(target).console(args.command)


class MsfJob:
    name = "msf_job"
    description = "List or stop a peer-service job. Listener creation is runtime-owned."
    args_model = MsfJobArgs
    example = {"target": "kali", "arguments": {"action": "job_list"}}

    def execute(self, target, args, ctx):
        return ctx.control("msf_job", {"action": args.action, "job_id": args.job_id})


class CredentialTest:
    name = "credential_test"
    description = ("Validate one stored credential against one host with an MSF login "
                   "scanner (smb/ldap/winrm/kerberos). The runtime resolves the secret.")
    args_model = CredentialTestArgs
    example = {"target": "kali",
               "arguments": {"method": "smb", "host": "target-host",
                             "credential_ref": "deployment-credential"}}

    def execute(self, target, args, ctx):
        return ctx.control("credential_test", args.model_dump())


class ServeFile:
    name = "serve_file"
    description = "Start an HTTP file server on the control plane for the target to fetch."
    args_model = ServeFileArgs
    example = {"target": "kali",
               "arguments": {"directory": "/tmp/materials", "port": 8000}}

    def execute(self, target, args, ctx):
        return ctx.control("serve_file",
                           {"directory": args.directory, "port": args.port})


class RemoteProcess:
    name = "remote_process"
    description = ("Create a process on a remote host; the execution layer resolves the "
                   "credential reference, the model never supplies a secret.")
    args_model = RemoteProcessArgs
    example = {"target": "kali",
               "arguments": {"host": "<target_host>",
                             "command": "C:\\Windows\\Temp\\x.exe"}}

    def execute(self, target, args, ctx):
        return ctx.control("remote_process",
                           {"host": args.host, "command": args.command,
                            "credential_ref": args.credential_ref,
                            "method": args.method,
                            "local_path": args.local_path,
                            "remote_path": args.remote_path})


def default_tools():
    return [RunCommand(), RunScript(), HttpRequest(), StageFile(), SessionCommand(),
            MsfJob(), CredentialTest(), ServeFile(), RemoteProcess()]
