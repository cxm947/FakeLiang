"""Kali entry provider: the run's own starting point through the existing transport."""

import json

from src.agents.pre_verifier.schema import ExecutionRequest
from .base import ProviderResult


def _text(value) -> str:
    if not isinstance(value, dict):
        return str(value or "")
    for key in ("stdout", "output"):
        if isinstance(value.get(key), str):
            return value[key]
    for key in ("structuredContent", "response", "result"):
        if value.get(key) is not None:
            text = _text(value[key])
            if text:
                return text
    content = value.get("content")
    if isinstance(content, list) and content and isinstance(content[0], dict):
        try:
            return _text(json.loads(content[0].get("text", "")))
        except (TypeError, ValueError):
            pass
    return ""


def _structured(value) -> dict:
    """Find the bridge's structured command receipt in either envelope shape."""
    if not isinstance(value, dict):
        return {}
    # Some transports and stored receipts hand back the flat command receipt
    # directly rather than wrapping it in an MCP envelope.
    if any(key in value for key in ("return_code", "stdout", "stderr", "timed_out")):
        return value
    direct = value.get("structuredContent")
    if isinstance(direct, dict):
        return direct
    nested = value.get("response")
    if isinstance(nested, dict):
        found = _structured(nested)
        if found:
            return found
        content = nested.get("content")
        if isinstance(content, list) and content and isinstance(content[0], dict):
            try:
                parsed = json.loads(content[0].get("text", ""))
            except (TypeError, ValueError):
                parsed = None
            if isinstance(parsed, dict):
                return parsed
    return {}


class KaliProvider:
    name = "kali"

    def __init__(self, binding, transports):
        self.binding = binding
        self.transports = transports

    def execute(self, line: str, *, end_marker: str, timeout: float) -> ProviderResult:
        request = ExecutionRequest(tool="code", name="bash", via="kali", content=line)
        result = self.transports.execute(self.binding, request)
        envelope = result.get("response") if isinstance(result, dict) else None
        data = _structured(envelope)
        confirmed = bool(result.get("effect_known"))
        code = data.get("return_code")
        # A present-but-null stdout is a partial receipt, not an empty command output.
        reported = (not ("stdout" in data and not isinstance(data.get("stdout"), str))
                    and not ("output" in data and not isinstance(data.get("output"), str)))
        return ProviderResult(ok=confirmed,
                              output=_text(result.get("response")),
                              error_output=str(data.get("stderr") or ""),
                              output_reported=reported,
                              timed_out=bool(data.get("timed_out") or result.get("timed_out")),
                              transport_error=bool(data.get("transport_error")
                                                   or result.get("transport_error")),
                              receipt_confirmed=confirmed,
                              return_code=code if type(code) is int else None)

    def console(self, command: str, *, timeout: float = 60.0) -> ProviderResult:
        return ProviderResult(ok=False, error="kali entry has no session console")

    def identity(self) -> dict:
        return {"host": "kali", "platform": "linux", "session_type": "entry"}

    def close(self) -> None:
        return None
