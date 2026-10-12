"""产物表：我们在这场子里改过什么，逆着它就能收回来（爷爷 2026-10-06 的口径）。

回收最难的地方不是"删文件"，而是"我不知道自己都干过什么"。所以凡是引擎自己动到场子的地方，
都在这里记一行：上传了什么文件到哪台机、起了什么进程、开了哪个监听、改过哪台机的防火墙、建过
什么计划任务/服务、挂载/写过哪个授权文件、动过什么配置。每行带一个 ``undo``（逆操作的 argv），
回收脚本从最新一行往回走，逐条执行；逆不掉的（例如"改过 redis 配置但没读回原值"）标 ``declared``，
如实列给人看，不假装收干净了。

模型自己下发的动作（schtasks / netsh / sc / net use / redis-cli config set …）由
:func:`declare_from_call` 从已执行的命令里**尽力**提取——这类行天然是"声明的"，不是"确认的"，
所以单独标注，回收时同样列出来。
"""
from __future__ import annotations

import re
import time
from uuid import uuid4

from runtime import harvest

#: 一个产物行的字段；``undo`` 为空表示"逆不掉，需要人看"。
ROW_FIELDS = ("artifact_id", "at", "node", "host", "kind", "action", "target", "detail",
              "evidence", "undo", "state")
#: 我们认识的动作类别。新类别 = 这里加一个值 + 写它的人。
KINDS = ("file", "process", "listener", "firewall", "task", "service", "mount", "key",
         "config", "session", "relay")
#: 行状态：引擎自己做的=applied；已回收=reverted；从命令里提取的=declared。
STATES = ("applied", "reverted", "declared")


def record(run_dir, *, kind, target="", host="", node="", action="create", detail="",
           evidence="", undo=(), state="applied") -> dict:
    """记下一个产物；``undo`` 是逆操作的 argv（list），空表示逆不掉。"""
    key = str(kind or "").strip()
    if key not in KINDS:
        raise ValueError("ARTIFACT_KIND_UNKNOWN: " + key)
    if state not in STATES:
        raise ValueError("ARTIFACT_STATE_UNKNOWN: " + str(state))
    row = {"artifact_id": "art-" + uuid4().hex[:12],
           "at": "%.3f" % time.time(),
           "node": str(node or ""), "host": str(host or ""), "kind": key,
           "action": str(action or "create"), "target": str(target or ""),
           "detail": str(detail or "")[:400], "evidence": str(evidence or ""),
           "undo": [str(part) for part in (undo or ())], "state": str(state)}
    harvest.record(run_dir, "artifact", row)
    return row


def read(run_dir) -> list:
    """按写入顺序返回产物行（最早的在前）。"""
    return harvest.read(run_dir, row_type="artifact")


def pending(rows) -> list:
    """还没回收、且有逆操作的行，倒序（最后做的先撤）。"""
    out = [row for row in rows
           if str(row.get("state")) != "reverted" and row.get("undo")]
    return list(reversed(out))


def manual(rows) -> list:
    """逆不掉的行：列给人看，别假装收干净了。"""
    return [row for row in rows
            if str(row.get("state")) in ("applied", "declared") and not row.get("undo")]


def revert(run_dir, rows, *, executors=(), apply=False) -> list:
    """倒序执行逆操作；每条回收结果都写回产物表。返回人读的一行行。"""
    lines = []
    for row in pending(rows):
        host = str(row.get("host") or "")
        executor = executors.get(host) if isinstance(executors, dict) else None
        argv = [str(part) for part in (row.get("undo") or [])]
        if executor is None:
            lines.append("手工：%s %s（%s 上没有可用的执行端）"
                         % (row.get("kind"), row.get("target"), host or "-"))
            continue
        if not apply:
            lines.append("会执行：%s %s -> %s" % (row.get("kind"), row.get("target"), " ".join(argv)))
            continue
        outcome = executor(argv, 90.0)
        ok = getattr(outcome, "returncode", None) == 0
        lines.append("%s：%s %s" % ("已回收" if ok else "回收失败",
                                    row.get("kind"), row.get("target")))
        if ok:
            record(run_dir, kind=str(row.get("kind")), target=str(row.get("target")),
                   host=host, node=str(row.get("node") or ""), action="delete",
                   detail="reverted " + str(row.get("artifact_id")),
                   evidence=str(row.get("artifact_id")), state="reverted")
    return lines


#: 模型下发的动作里，我们认得出的那些（尽力而为：这些是"声明"，不是"确认"）。
#: (正则, 类别, 逆操作 argv 模板) - 模板里的 {name}/{host}/{share} 由匹配与现场填。
DECLARED_PATTERNS = (
    (re.compile(r"schtasks(?:\.exe)?\s+/create\b.*?/tn\s+(?P<name>[^\s/]+)", re.I),
     "task", ["schtasks", "/delete", "/tn", "{name}", "/f"]),
    (re.compile(r"netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off", re.I),
     "firewall", ["netsh", "advfirewall", "set", "allprofiles", "state", "on"]),
    (re.compile(r"sc(?:\.exe)?\s+\\\\[^\s]+\s+create\s+(?P<name>[^\s]+)", re.I),
     "service", ["sc", "\\{host}", "delete", "{name}"]),
    (re.compile(r"net(?:\.exe)?\s+use\s+(?P<share>\\\\[^\s]+)", re.I),
     "mount", ["net", "use", "{share}", "/delete", "/y"]),
    (re.compile(r"redis-cli\b.*?config\s+set\s+(?P<name>dir|dbfilename)\s+(?P<value>\S+)", re.I),
     "config", []),
)


def declare_from_call(run_dir, request, *, node="", host="", evidence="") -> list:
    """从一条已执行的命令里提取"我们改了什么"；认不出来的动词返回空表。

    这是**声明**级别的记录：命令是否真的生效由节点自己的观测负责，回收时这些行仍要人看一眼。
    """
    text = " ".join(str(part) for part in (request.get("argv") or [])) if isinstance(request, dict) else ""
    if not text:
        text = str(request or "")
    rows = []
    for pattern, kind, undo in DECLARED_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        groups = match.groupdict()
        filled = [str(part).format(host=host, **groups) for part in undo]
        rows.append(record(run_dir, kind=kind, target=str(groups.get("name") or groups.get("share") or ""),
                           host=host, node=node, action="declare", detail=text[:200],
                           evidence=evidence, undo=filled, state="declared"))
    return rows
