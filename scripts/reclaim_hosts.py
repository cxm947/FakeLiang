"""Host cleanup commands and completed leftover observations."""
from __future__ import annotations

from runtime import session_io



#: Everything our tools drop on a far side carries this prefix (payloads, clients, scratch).
ARTIFACT_PREFIX = "/tmp/agv"

#: Two commands, deliberately *not* one line: the remove step's own command line contains the
#: artifact prefix, so "kill then remove" in a single line has the shell kill itself (measured:
#: rc=255 and nothing removed). The kill patterns are bracketed for the same reason.
KILL_SCRIPT = "pkill -f '[a]gv_' >/dev/null 2>&1; pkill -f '[a]gv-' >/dev/null 2>&1; true"
REMOVE_SCRIPT = "rm -rf " + ARTIFACT_PREFIX + "* >/dev/null 2>&1; echo cleaned"


def hosts_of(rows):
    """List recorded hosts and explicitly bound console sessions."""
    hosts, carriers = [], []
    for row in rows:
        host = str(row.get("host") or "")
        if host and host not in hosts:
            hosts.append(host)
        if isinstance(row.get("endpoint"), dict) and row.get("session_id"):
            carriers.append(row)
    return hosts, carriers


#: Windows 靶机上"收掉我们的东西"：按命令行杀进程（马的命令行里带 agv），再删我们的文件。
#: 用 taskkill 对已知镜像名 + wmic 兜住命令行里带 agv 的（含验证流程的 cmd）。
KILL_SCRIPT_WINDOWS = (
    "taskkill /F /IM agv_session.exe /T 2>nul & "
    "taskkill /F /IM agv_migrate.exe /T 2>nul & "
    "for /f \"tokens=2 delims==\" %p in ('wmic process where \"commandline like '%agv%'\" get processid /value 2^>nul ^| findstr ProcessId') do @taskkill /F /PID %p /T 2>nul & "
    "echo KILL-DONE"
)
REMOVE_SCRIPT_WINDOWS = (
    "del /f /q C:\\Windows\\Temp\\agv* 2>nul & del /f /q C:\\Windows\\agv* 2>nul & "
    "del /f /q C:\\agv* 2>nul & echo REMOVE-DONE"
)


def clean_host(executor, carrier, *, apply=False):
    """Run cleanup through the recorded binding and report its command receipts."""
    platform = str(carrier.get("platform") or "").lower()
    if platform.startswith("windows"):
        kill, remove = KILL_SCRIPT_WINDOWS, REMOVE_SCRIPT_WINDOWS
    elif platform.startswith("linux"):
        kill, remove = KILL_SCRIPT, REMOVE_SCRIPT
    else:
        raise ValueError("RECLAIM_PLATFORM_UNDECLARED")
    label = carrier.get("logical") or carrier.get("host")
    if not apply:
        return "Would kill recorded payloads and remove their files on %s" % label
    killed = session_io.call_bound(carrier, {"tool": "cmd", "cmd": kill}, 90.0)
    if not killed["confirmed"]:
        return "%s: RECLAIM_CALL_UNRESOLVED" % label
    removed = session_io.call_bound(carrier, {"tool": "cmd", "cmd": remove}, 90.0)
    return "%s -> kill rc=%s, remove rc=%s %s" % (
        label, killed["command_rc"], removed["command_rc"],
        str(getattr(removed["outcome"], "stdout", "") or "").strip()[:40])

#: 回收之后的"回查"：把还没断的每一台机器看一遍还剩什么。
#: 爷爷 2026-10-06：「每一轮给到 kali 和靶场的所有东西，都要在跑完之后清理掉」——这句话得能被查，
#: 而不是靠感觉。所以回收不写"已完成"就完事：能进的机器都要回读一遍，把剩下的东西打出来。
LEFT_OVER_LINUX = (
    "echo '@@ files'; ls -d /tmp/agv* 2>/dev/null; "
    "echo '@@ listeners'; (ss -lntp 2>/dev/null || netstat -lntp 2>/dev/null) | "
    "grep -E '108[0-9]|109[0-9]'; "
    "echo '@@ processes'; ps ax 2>/dev/null | grep -E '[a]gv_|[h]ttp.server 10'; "
    "echo '@@ keyline'; grep -c agv /root/.ssh/authorized_keys 2>/dev/null; "
    "echo LEFTOVER-DONE"
)
LEFT_OVER_WINDOWS = (
    "echo @@ files & dir /b C:\\Windows\\Temp\\agv* 2>nul & "
    "echo @@ portproxy & netsh interface portproxy show all & "
    "echo @@ tasks & schtasks /query /fo LIST 2>nul | findstr /i agv & "
    "echo @@ processes & tasklist 2>nul | findstr /i agv & "
    "echo LEFTOVER-DONE"
)

#: 每个小节怎么判"剩没剩东西"：普通小节 = 任何非空行都算剩；keyline = 只有非 0 才算剩。
SECTION_RULE = {"files": "", "listeners": "", "processes": "", "keyline": "zero",
                "tasks": "", "portproxy": ""}


def _parse_leftover(text) -> dict:
    """Read report sections only until their explicit end line."""
    sections, current = {}, ""
    for line in str(text or "").replace("\r", "").splitlines():
        stripped = line.strip()
        if stripped == "LEFTOVER-DONE":
            break
        if stripped.startswith("@@ "):
            current = stripped[3:].strip()
            sections.setdefault(current, [])
        elif current and stripped:
            sections[current].append(stripped)
    return sections


def _leftover_items(sections) -> list:
    """按小节规则挑出"真的还剩东西"的行。"""
    items = []
    for name, lines in sections.items():
        rule = SECTION_RULE.get(name, "")
        for line in lines:
            if rule == "zero" and line == "0":
                continue
            if name == "portproxy" and ("---" in line or "地址" in line or "端口" in line
                                        or "listen" in line.lower()):
                continue
            items.append("%s: %s" % (name, line))
    return items


def leftover_scan(executor, rows, *, apply=False):
    """Only completed observations can establish that a host is clean."""
    lines = []
    for row in rows or ():
        label = str(row.get("logical") or row.get("host") or "")
        if not isinstance(row.get("endpoint"), dict) or not row.get("session_id"):
            continue
        if not apply:
            lines.append("会回查 %s" % label)
            continue
        try:
            platform = str(row.get("platform") or "").lower()
            if platform.startswith("windows"):
                script = LEFT_OVER_WINDOWS
            elif platform.startswith("linux"):
                script = LEFT_OVER_LINUX
            else:
                raise ValueError("RECLAIM_PLATFORM_UNDECLARED")
            result = session_io.call_bound(row, {"tool": "cmd", "cmd": script}, 90.0)
            if not result["confirmed"] or result["command_rc"] != 0:
                lines.append("%s: RECLAIM_OBSERVATION_UNCONFIRMED" % label)
                continue
            text = str(getattr(result["outcome"], "stdout", "") or "")
            if "LEFTOVER-DONE" not in text.splitlines():
                lines.append("%s: RECLAIM_REPORT_INCOMPLETE" % label)
                continue
            sections = _parse_leftover(text)
            required = {"files", "portproxy", "tasks", "processes"} if platform.startswith("windows") else {
                "files", "listeners", "processes", "keyline"}
            if not required.issubset(sections):
                lines.append("%s: RECLAIM_REPORT_INCOMPLETE" % label)
                continue
            items = _leftover_items(sections)
            lines.append("%s: %s" % (label, "Remaining: " + " | ".join(items[:6])
                                     if items else "Clean"))
        except (ValueError, OSError) as error:
            lines.append("%s: RECLAIM_OBSERVATION_UNCONFIRMED %s" % (label, str(error)[:80]))
    return lines or ["No bound sessions to inspect"]




def lab_extras(executor, rows, *, apply=False, skip_hosts=()):
    """The two lab-specific leftovers (redis config, planted key line), reported or removed.

    The control box itself is skipped: it is where we run from, not a host the lab extras belong to.
    """
    skip = {str(item) for item in skip_hosts}
    hosts = sorted({str(row.get("host")) for row in rows
                    if row.get("host") and str(row.get("host")) not in skip})
    lines = []
    for host in hosts:
        command = ("sed -i '/agv_session/d' /root/.ssh/authorized_keys 2>/dev/null; "
                   "for d in /var/lib/redis /data /tmp; do redis-cli -h " + host
                   + " CONFIG SET dir $d 2>/dev/null | grep -q OK && break; done; redis-cli -h "
                   + host + " CONFIG SET dbfilename dump.rdb >/dev/null; echo lab-extras-done")
        if apply:
            outcome = executor(["/bin/sh", "-c", command], 90.0)
            lines.append("applied on %s -> %s" % (host, str(getattr(outcome, "stdout", "") or "").strip()[:30]))
        else:
            lines.append("would apply the lab extras on %s" % host)
    return lines or ["no hosts in the ledger: nothing lab-specific to undo"]
