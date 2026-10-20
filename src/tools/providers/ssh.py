"""SSH provider: runs one command through the Kali entry's ssh client.

No extra Python SSH dependency is required: the Kali entry already holds the run key and
reaches the target. Each call is one non-interactive ssh invocation with an end marker.
"""

import shlex

from .base import ProviderResult


class SshProvider:
    name = "ssh"

    def __init__(self, binding, kali, *, key_path: str, port: int = 22):
        self.binding = binding
        self.kali = kali
        self.key_path = key_path
        self.port = int(port)

    def _address(self) -> str:
        addresses = self.binding.get("addresses") or []
        return str(addresses[0]) if addresses else str(self.binding.get("host") or "")

    def _user(self) -> str:
        return str(self.binding.get("identity") or "root")

    def _run(self, line: str, *, timeout: float) -> ProviderResult:
        remote = ("ssh -i " + shlex.quote(self.key_path)
                  + " -o IdentitiesOnly=yes -o StrictHostKeyChecking=no"
                  + " -o UserKnownHostsFile=/dev/null -o BatchMode=yes"
                  + " -p " + str(self.port) + " "
                  + shlex.quote(self._user() + "@" + self._address())
                  + " " + shlex.quote(line))
        return self.kali.execute(remote, end_marker=self.kali_end_marker, timeout=timeout)

    def execute(self, line: str, *, end_marker: str, timeout: float) -> ProviderResult:
        self.kali_end_marker = end_marker
        return self._run(line, timeout=timeout)

    def launch(self, line: str, *, end_marker: str, timeout: float) -> ProviderResult:
        """Run a control-box command (scp/ssh hand-over), not a target-side command."""
        self.kali_end_marker = end_marker
        return self.kali.execute(line, end_marker=end_marker, timeout=timeout)

    def console(self, command: str, *, timeout: float = 60.0) -> ProviderResult:
        self.kali_end_marker = "agv-call-end"
        return self._run(command, timeout=timeout)

    def identity(self) -> dict:
        return {"host": self._address(), "platform": "linux",
                "session_type": "ssh"}

    def close(self) -> None:
        return None
