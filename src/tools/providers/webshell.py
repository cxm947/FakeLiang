"""WebShell provider: one command per HTTP request, response text is the receipt."""

import requests

from .base import ProviderResult


class WebshellProvider:
    name = "webshell"

    def __init__(self, endpoint: str, *, parameter: str = "cmd", timeout: float = 30.0):
        self.endpoint = endpoint
        self.parameter = parameter
        self.timeout = timeout

    def execute(self, line: str, *, end_marker: str, timeout: float) -> ProviderResult:
        try:
            response = requests.post(self.endpoint, data={self.parameter: line},
                                     timeout=min(timeout, self.timeout), verify=False)
        except requests.exceptions.Timeout as exc:
            return ProviderResult(ok=False, timed_out=True,
                                  error=type(exc).__name__ + ": " + str(exc),
                                  receipt_confirmed=False)
        except Exception as exc:
            return ProviderResult(ok=False, transport_error=True,
                                  error=type(exc).__name__ + ": " + str(exc),
                                  receipt_confirmed=False)
        text = response.text or ""
        # Any HTTP response is a terminal receipt for this write. A 500 with a body is
        # still something the model can judge; an unanswered request is not.
        return ProviderResult(ok=bool(response.ok and text.strip()), output=text,
                              receipt_confirmed=True,
                              return_code=0 if response.ok else 1)

    def console(self, command: str, *, timeout: float = 60.0) -> ProviderResult:
        return ProviderResult(ok=False, error="webshell has no session console")

    def identity(self) -> dict:
        return {"host": self.endpoint, "platform": "unknown",
                "session_type": "webshell"}

    def close(self) -> None:
        return None
