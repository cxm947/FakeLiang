"""One OS backend: systemd-managed socat on a Linux pivot.

The injected runner executes a bounded shell command using the pinned session;
it must not retry ambiguous commands. Data connections go directly to socat's
TCP listener, never through a session tool's proxy/channel forwarding feature.
This module opens no connections and runs no processes by itself.
"""

from datetime import datetime, timezone
from hashlib import sha256
from typing import Callable, Protocol

from pydantic import BaseModel, ConfigDict

from .execution_session import SessionReference
from .tunnel import CleanupReceipt, TunnelFailure, TunnelRecord


class SystemTunnelOwner(Protocol):
    def install(self, record: TunnelRecord) -> None: ...
    def is_alive(self, record: TunnelRecord) -> bool: ...
    def uninstall(self, record: TunnelRecord) -> CleanupReceipt: ...


class CommandResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    returncode: int
    stdout: str
    effect_known: bool


class LinuxSocatOwner:
    def __init__(self, execute: Callable[[SessionReference, str], CommandResult]):
        self.execute = execute

    @staticmethod
    def _unit(record):
        # Derived names are shell-safe even when reading externally supplied rows.
        return "agv-tunnel-" + sha256(record.installation_id.encode()).hexdigest() + ".service"

    def _header(self, record):
        return f"""set -eu
unit='{self._unit(record)}'
port='{record.local_port}'
command -v systemctl >/dev/null
command -v ss >/dev/null
command -v grep >/dev/null
"""

    @staticmethod
    def _probe():
        # Check listener ownership, not just 'unit active' or an unrelated listener.
        return """alive() {
    systemctl is-active --quiet "$unit" || return 1
    pid=$(systemctl show "$unit" --property=MainPID --value) || return 2
    [ "$pid" -gt 0 ] || return 1
    listeners=$(ss -H -ltnp "sport = :$port") || return 2
    printf '%s\\n' "$listeners" | grep -F "pid=$pid," >/dev/null
}
"""

    def _execute(self, record, command):
        result = CommandResult.model_validate(self.execute(record.session, command))
        if not result.effect_known:
            raise TunnelFailure("tunnel_command_outcome_unknown")
        return result

    def install(self, record):
        command = self._header(record) + self._probe() + f"""
command -v systemd-run >/dev/null
socat=$(command -v socat)
systemd-run --quiet --collect --unit="$unit" --property=Type=exec \\
    --property=KillMode=control-group --property=Restart=no -- "$socat" \\
    'TCP4-LISTEN:{record.local_port},bind={record.listen_host},fork' \\
    'TCP4:{record.target_host}:{record.target_port}'
i=0
while [ "$i" -lt 50 ]; do
    if alive; then printf '%s\\n' "$unit:ready"; exit 0; fi
    systemctl is-active --quiet "$unit" || exit 20
    i=$((i + 1))
    sleep 0.1
done
exit 21
"""
        result = self._execute(record, command)
        if result.returncode != 0 or self._unit(record) + ":ready" not in result.stdout.splitlines():
            raise TunnelFailure("tunnel_start_or_port_conflict")

    def is_alive(self, record):
        result = self._execute(record, self._header(record) + self._probe() + """
if alive; then printf '%s\\n' "$unit:alive"; exit 0; else
    code=$?
    [ "$code" -eq 1 ] && exit 10
    exit 11
fi
""")
        if result.returncode == 10:
            return False
        if result.returncode != 0 or self._unit(record) + ":alive" not in result.stdout.splitlines():
            raise TunnelFailure("tunnel_probe_failed")
        return True

    def uninstall(self, record):
        command = self._header(record) + """
units=$(systemctl list-units --all --full --plain --no-legend "$unit")
if [ -n "$units" ]; then
    systemctl stop "$unit"
fi
units=$(systemctl list-units --all --full --plain --no-legend \\
    --state=active,activating,deactivating,reloading "$unit")
[ -z "$units" ] || exit 30
listeners=$(ss -H -ltn "sport = :$port")
[ -z "$listeners" ] || exit 32
printf '%s\\n' "$unit:cleaned"
"""
        result = self._execute(record, command)
        marker = self._unit(record) + ":cleaned"
        if result.returncode != 0 or marker not in result.stdout.splitlines():
            raise TunnelFailure("tunnel_cleanup_unconfirmed")
        return CleanupReceipt(run_id=record.run_id, tunnel_id=record.tunnel_id,
            installation_id=record.installation_id, evidence=marker,
            cleaned_at=datetime.now(timezone.utc))
