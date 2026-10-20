"""MSF provider: wraps the existing SessionBackend without changing its behavior."""

from src.session.execution_session import SessionReference
from src.session.session_backend import SessionRequest
from .base import ProviderResult


class MsfProvider:
    name = "msf"

    def __init__(self, backend, reference: SessionReference):
        self.backend = backend
        self.reference = reference

    def execute(self, line: str, *, end_marker: str, timeout: float) -> ProviderResult:
        framed = line.rstrip("\n") + "\necho " + end_marker + "\n"
        result = self.backend.execute(
            self.reference,
            SessionRequest(command=framed, end_markers=(end_marker,), timeout=timeout))
        if not result.operation_confirmed:
            # A one-shot channel can return before the command's stdout is flushed, and a
            # long-running target command can leave the marker queued behind its output.
            # One echo drains the pending tail; the marker decides, not the assumption
            # that the command ran. This is a transport flush, not a command retry.
            try:
                flush = self.backend.execute(
                    self.reference,
                    SessionRequest(command="echo " + end_marker,
                                   end_markers=(end_marker,),
                                   timeout=min(float(timeout), 20.0)))
            except Exception:
                flush = None
            if flush is not None:
                combined = (result.output or "") + "\n" + (flush.output or "")
                confirmed = bool(flush.operation_confirmed or end_marker in combined)
                return ProviderResult(
                    ok=confirmed, output=combined, receipt_confirmed=confirmed,
                    return_code=0 if confirmed else 1)
        return ProviderResult(ok=bool(result.operation_confirmed), output=result.output,
                              receipt_confirmed=bool(result.operation_confirmed),
                              return_code=0 if result.operation_confirmed else 1)

    def console(self, command: str, *, timeout: float = 60.0) -> ProviderResult:
        result = self.backend.console_command(self.reference, command, timeout=timeout)
        return ProviderResult(ok=bool(result.operation_confirmed), output=result.output,
                              receipt_confirmed=bool(result.operation_confirmed),
                              return_code=0 if result.operation_confirmed else 1)

    def identity(self) -> dict:
        metadata = self.backend.get_session(
            self.reference.session_id, instance_id=self.reference.instance_id)
        return {"host": metadata.host, "platform": metadata.platform,
                "session_type": metadata.type}

    def close(self) -> None:
        return None
