"""Translate the legacy four-field request into the single-tool contract."""

import shlex

from .request import ToolRequest


def from_legacy(request: dict) -> ToolRequest:
    """Accept `{tool,name,via,content}` while cards/prompts migrate."""
    tool = str(request.get("tool") or "").strip()
    name = str(request.get("name") or "").strip()
    via = str(request.get("via") or "kali").strip()
    content = request.get("content")
    target = "session" if via == "session" else "kali"

    if tool == "cmd":
        return ToolRequest(tool="run_command", target=target,
                           arguments={"interpreter": name or "sh",
                                      "command": str(content)})
    if tool == "code":
        return ToolRequest(tool="run_script", target=target,
                           arguments={"interpreter": name or "sh",
                                      "body": str(content)})
    if tool == "tool":
        argv = content if isinstance(content, list) else [str(content)]
        return ToolRequest(tool="run_command", target=target,
                           arguments={"interpreter": "sh",
                                      "command": shlex.join([name, *map(str, argv)])})
    if tool == "http":
        return ToolRequest(tool="http_request", target=target, arguments=dict(content or {}))
    if tool == "stage":
        return ToolRequest(tool="stage_file", target=target, arguments=dict(content or {}))
    if tool == "session":
        return ToolRequest(tool="session_command", target="session",
                           arguments={"command": str((content or {}).get("command") or "")})
    if tool == "msf":
        data = dict(content or {})
        return ToolRequest(tool="msf_job", target="kali",
                           arguments={"action": data.get("action", "job_list"),
                                      "job_id": str(data.get("job_id") or "")})
    if tool == "control":
        data = dict(content or {})
        action = str(data.get("action") or "")
        if action == "serve_file":
            return ToolRequest(tool="serve_file", target="kali",
                               arguments={"directory": data.get("directory", ""),
                                          "port": data.get("port")})
        if action == "remote_process":
            return ToolRequest(tool="remote_process", target="kali",
                               arguments={"host": data.get("host", ""),
                                          "command": data.get("command", ""),
                                          "credential_ref": data.get("credential_ref", ""),
                                          "method": data.get("method", "wmic"),
                                          "local_path": data.get("local_path", ""),
                                          "remote_path": data.get("remote_path", "")})
    raise ValueError("unsupported legacy request: " + tool)


def to_legacy_request(request: dict) -> dict:
    """Accept the new `{tool,target,arguments}` shape and expose the legacy view.

    The stage workflows still speak `tool/name/via/content`; this adapter keeps one
    normalization point so prompts and cards can migrate without duplicating logic.
    """
    if not isinstance(request, dict):
        return request
    if "arguments" not in request:
        # A model may use the legacy four fields but put a tool name in `name`
        # (`tool="tool", name="stage_file"`). Translate that pair through the same new
        # shape instead of rejecting a request whose intent is unambiguous (live
        # 2026-10-18, node 26: three attempts rejected as a contract violation).
        tool_name = str(request.get("name") or "").strip()
        if str(request.get("tool") or "").strip() == "tool" and tool_name in {
                "run_command", "run_script", "http_request", "stage_file",
                "session_command", "msf_job", "credential_test", "serve_file",
                "remote_process"}:
            return to_legacy_request({
                "tool": tool_name,
                "target": request.get("via") or "kali",
                "arguments": request.get("content") or {}})
        return request
    tool = str(request.get("tool") or "").strip()
    target = str(request.get("target") or "").strip()
    arguments = request.get("arguments") or {}
    if target not in {"kali", "session"}:
        raise ValueError("target must be kali or session")
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")

    if tool == "run_command":
        return {"tool": "cmd", "name": arguments.get("interpreter", "sh"),
                "via": target, "content": arguments.get("command", "")}
    if tool == "run_script":
        return {"tool": "code", "name": arguments.get("interpreter", "sh"),
                "via": target, "content": arguments.get("body", "")}
    if tool == "http_request":
        return {"tool": "http", "name": "http", "via": target,
                "content": arguments}
    if tool == "stage_file":
        return {"tool": "stage", "name": "stage", "via": target,
                "content": arguments}
    if tool == "session_command":
        return {"tool": "session", "name": "console", "via": "session",
                "content": {"command": arguments.get("command", "")}}
    if tool == "msf_job":
        return {"tool": "msf", "name": arguments.get("action", "job_list"),
                "via": "kali", "content": arguments}
    if tool == "credential_test":
        return {"tool": "control", "name": "credential_test", "via": "kali",
                "content": {"action": "credential_test",
                            "host": arguments.get("host", ""),
                            "credential_ref": arguments.get("credential_ref", ""),
                            "test_method": arguments.get("method", "smb"),
                            "port": arguments.get("port"),
                            "timeout": arguments.get("timeout", 60)}}
    if tool == "serve_file":
        return {"tool": "control", "name": "serve_file", "via": "kali",
                "content": {"action": "serve_file",
                            "directory": arguments.get("directory", ""),
                            "port": arguments.get("port")}}
    if tool == "remote_process":
        return {"tool": "control", "name": "remote_process", "via": "kali",
                "content": {"action": "remote_process",
                            "host": arguments.get("host", ""),
                            "command": arguments.get("command", ""),
                            "credential_ref": arguments.get("credential_ref", ""),
                            "method": arguments.get("method", "wmic"),
                            "local_path": arguments.get("local_path", ""),
                            "remote_path": arguments.get("remote_path", "")}}
    raise ValueError("unknown tool: " + tool)


def normalize_incoming(request: dict) -> dict:
    """Deprecated spelling kept for stored callers and older recordings."""
    return to_legacy_request(request)


__all__ = ["from_legacy", "normalize_incoming", "to_legacy_request"]
