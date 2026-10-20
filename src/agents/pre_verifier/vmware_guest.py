"""Local experiment carrier: VMware Guest Operations with private login bindings."""

from pathlib import Path
import shlex
import subprocess
import tempfile
from uuid import uuid4
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class GuestProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    vmx: str = Field(min_length=1)
    platform: Literal["windows", "linux"]
    user: str = Field(min_length=1)
    password: SecretStr


class GuestConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    vmrun: str = Field(min_length=1)
    guests: dict[str, GuestProfile]


def ps_quote(value):
    return "'" + value.replace("'", "''") + "'"


class VMwareGuest:
    def __init__(self, config_path):
        self.config = GuestConfig.model_validate_json(Path(config_path).read_text(encoding="utf-8"))

    def platform(self, name):
        return self.config.guests[name].platform

    def running(self):
        """Single inventory read, without polling or guest credentials."""
        result = subprocess.run([self.config.vmrun, "-T", "ws", "list"],
            capture_output=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode:
            raise RuntimeError("VMware running inventory failed")
        return result.stdout.decode("utf-8", "replace").splitlines()[1:]

    def revert(self, name, snapshot):
        """One blocking rollback; the caller must invoke guests sequentially."""
        available = self.call(name, "listSnapshots").decode("utf-8", "replace").splitlines()[1:]
        if snapshot not in available:
            raise ValueError(f"Snapshot not found on {name}: {snapshot}")
        output = self.call(name, "revertToSnapshot", snapshot, timeout=180)
        if self.config.guests[name].vmx not in self.running():
            self.call(name, "start", "nogui", timeout=90)
        return {"vm": name, "snapshot": snapshot, "reverted": True,
                "stdout": output.decode("utf-8", "replace")}

    def call(self, name, action, *args, timeout=45):
        profile = self.config.guests[name]
        password = profile.password.get_secret_value()
        command = [self.config.vmrun, "-T", "ws", "-gu", profile.user, "-gp", password,
                   action, profile.vmx, *map(str, args)]
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"VMware {action} timed out on {name}") from None
        if result.returncode:
            # Never include argv: guest credentials occur in vmrun arguments.
            message = (result.stdout + result.stderr).decode("utf-8", "replace")
            raise RuntimeError(f"VMware {action} failed on {name}: {message.replace(password, '<redacted>')[:300]}")
        return result.stdout

    def execute(self, name, command, *, root=False):
        windows = self.platform(name) == "windows"
        stem = ("C:\\Windows\\Temp\\" if windows else "/tmp/") + "agv_pre_" + uuid4().hex
        script = stem + (".ps1" if windows else ".sh")
        paths = [script, stem + ".out", stem + ".err", stem + ".rc"]
        if windows:
            body = ("$ErrorActionPreference='Stop'\n$global:LASTEXITCODE=0\n"
                    "try { & {\n" + command + "\n} > " + ps_quote(paths[1]) + " 2> " + ps_quote(paths[2]) +
                    "\n$rc=0; if ($LASTEXITCODE) {$rc=$LASTEXITCODE}\n} catch {\n"
                    "$_ | Out-File -FilePath " + ps_quote(paths[2]) + " -Encoding utf8; $rc=1\n}\n"
                    "[IO.File]::WriteAllText(" + ps_quote(paths[3]) + ",[string]$rc)\n")
        else:
            body = "#!/bin/sh\n(\n" + command + "\n) > " + shlex.quote(paths[1]) + " 2> " + shlex.quote(paths[2]) + "\nprintf '%s' $? > " + shlex.quote(paths[3]) + "\nchmod 644 " + " ".join(map(shlex.quote, paths[1:])) + "\n"
        cleanup_errors = []
        with tempfile.TemporaryDirectory(prefix="agv-pre-") as folder:
            local = Path(folder) / "request"
            local.write_text(body, encoding="utf-8-sig" if windows else "utf-8", newline="\n")
            try:
                self.call(name, "copyFileFromHostToGuest", local, script)
                if windows:
                    self.call(name, "runProgramInGuest", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                              "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, timeout=60)
                else:
                    invocation = "/bin/sh " + shlex.quote(script)
                    if root:
                        password = self.config.guests[name].password.get_secret_value()
                        invocation = "printf '%s\\n' " + shlex.quote(password) + " | sudo -S -p '' " + invocation
                    self.call(name, "runProgramInGuest", "/bin/sh", "-c", invocation, timeout=60)
                outputs = []
                for index, remote in enumerate(paths[1:]):
                    target = Path(folder) / str(index)
                    self.call(name, "copyFileFromGuestToHost", remote, target)
                    data = target.read_bytes()
                    if data.startswith((b'\xff\xfe', b'\xfe\xff')):
                        value = data.decode("utf-16")
                    else:
                        try:
                            value = data.decode("utf-8-sig")
                        except UnicodeDecodeError:
                            value = data.decode("gb18030", "replace")
                    outputs.append(value)
                result = {"stdout": outputs[0], "stderr": outputs[1], "return_code": int(outputs[2].strip()),
                          "transport_error": False, "execution_host": name, "carrier": "vmware_tools"}
            finally:
                cleanup_paths = paths
                if root and not windows:
                    try:
                        removal = "printf '%s\\n' " + shlex.quote(self.config.guests[name].password.get_secret_value()) + " | sudo -S -p '' rm -f -- " + " ".join(map(shlex.quote, paths))
                        self.call(name, "runProgramInGuest", "/bin/sh", "-c", removal, timeout=15)
                        cleanup_paths = []
                    except RuntimeError:
                        pass
                for remote in cleanup_paths:
                    try:
                        self.call(name, "deleteFileInGuest", remote, timeout=10)
                    except RuntimeError:
                        cleanup_errors.append(remote)
            result["cleanup_incomplete"] = cleanup_errors
            return result


class GuestCheckGateway:
    """Test-only routing around an existing Kali MCP gateway; model still owns checks."""
    def __init__(self, kali, guest, bindings, source_aliases=None):
        self.kali, self.guest, self.bindings = kali, guest, bindings
        self.source_aliases = source_aliases or {}
        for binding in bindings.values():
            if binding["platform"] != guest.platform(binding["vm"]):
                raise ValueError("Binding platform differs from guest profile")
            if not isinstance(binding.get("sudo", False), bool):
                raise ValueError("sudo must be a boolean")
            if binding.get("container") and (binding.get("container_runtime") not in {"docker", "podman"}
                                             or binding["platform"] != "linux"):
                raise ValueError("Container binding requires Linux and an explicit docker/podman runtime")

    def __enter__(self):
        self.kali.__enter__()
        self.definitions = self.kali.definitions
        return self

    def __exit__(self, *exc):
        return self.kali.__exit__(*exc)

    def execution_context(self, leaf):
        p = leaf["parameters"]
        if leaf["predicate"] == "hacl":
            host = p["source_host"]
        elif leaf["predicate"] == "networkServiceInfo" and p.get("protocol") != "local":
            host = "kali"
        else:
            host = p["host"]
        inspected_host = p.get("target_host", p.get("host"))
        # Optional lab routing is environment configuration, never a change of target.
        if leaf["predicate"] != "hacl" and inspected_host:
            origin = self.bindings.get(inspected_host, {}).get("check_from", host)
            host = origin.get(leaf["predicate"], host) if isinstance(origin, dict) else origin
        host = self.source_aliases.get(host, host)
        if host == "kali":
            context = {"via": "kali", "host": host, "platform": "linux"}
        else:
            binding = self.bindings.get(host)
            if binding is None:
                raise ValueError(f"No VM binding for {host}")
            context = {"via": "session", "host": host, "platform": binding["platform"],
                "container": binding.get("container"),
                # A host may declare one identity or an allowed set (a container reached
                # first as the web user, later as root); the check only needs to name the
                # declared range, the session carries the current fact.
                "identity": binding.get("identity") or next(iter(binding.get("identities") or []), None),
                "instructions": "执行层已进入此主机/容器。只生成在此环境直接执行的检查，不再添加连接或容器进入包装。"}
        context["instructions"] = context.get("instructions", "") + (
            "当前来源使用 Windows PowerShell 语法。" if context["platform"] == "windows"
            else "当前来源使用 POSIX shell 语法。")
        if inspected_host and host != inspected_host:
            context["inspected_host"] = inspected_host
            context["target_dns_name"] = self.bindings.get(inspected_host, {}).get("dns_name")
            context["instructions"] += (
                "执行层位于来源主机，检查对象仍是 leaf.parameters.host。必须显式对目标地址做远程只读检查，"
                "网络关系的目标以 target_host 为准。不能查询来源主机本地状态代替目标。"
                "只能使用已提供的身份和访问能力，不假设可用的运行库或客户端。")
        return context

    def execute_for(self, request, leaf):
        from .schema import ExecutionRequest
        from .mcp_client import command_for
        request = ExecutionRequest.model_validate(request)
        context = self.execution_context(leaf)
        if request.via != context["via"]:
            return {"is_error": True, "error": "执行入口与给定 execution 不一致", "execution": context}
        if context["via"] == "kali":
            return {**self.kali.execute(request.model_dump()), "execution": context}
        binding = self.bindings[context["host"]]
        windows = binding["platform"] == "windows"
        if windows:
            if request.tool == "cmd":
                command = request.content
            elif request.tool == "tool":
                command = "& " + " ".join(ps_quote(s) for s in [request.name, *request.content])
            elif request.name == "powershell":
                command = request.content
            else:
                return {"is_error": True, "error": "Windows guest requires a PowerShell script", "execution": context}
        else:
            command = command_for(request.model_dump())
        if binding.get("container"):
            identity = " --user " + shlex.quote(binding["identity"]) if binding.get("identity") else ""
            command = binding["container_runtime"] + " exec" + identity + " " + shlex.quote(binding["container"]) + " /bin/sh -c " + shlex.quote(command)
        try:
            observation = self.guest.execute(binding["vm"], command, root=binding.get("sudo", False))
        except RuntimeError as exc:
            # VMwareGuest constructs redacted transport errors without credential-bearing argv.
            return {"tool_name": "vmware_guest_check", "is_error": True,
                    "execution": context, "error": str(exc), "response": None}
        return {"tool_name": "vmware_guest_check", "is_error": observation["transport_error"],
                "execution": context, "response": observation}
