"""Positions: which carrier and which entry serve a node, and what identity it holds there."""
from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from orchestration.graph_view import graph_nodes
from orchestration.session_flow import produced_exec_facts
from agents.verifier.backstops import _observed_privilege
from runtime import session_io, session_registry, sessions
from runtime.delivery_commands import DELIVERY_MATERIALS_DIR, DELIVERY_SSH_OPTIONS


def exec_preconditions(document, node_id):
    """Read channel premises from parsed facts in the complete source graph."""
    from graph import criteria

    return [(fact["arguments"][0], fact["arguments"][1], list(fact["produced_by"]))
            for fact in criteria.node_criteria(document, node_id)
            if fact["signature"] == "execCode/2"]


def record_in_place_observation(*, document, node_id, host_map, root, row):
    """Record what an in-place step observed about its own position, as this step's evidence.

    A step that raises privilege **where it already runs** produces an `execCode` fact for its own
    position: no new session appears, so the engine reads the position's own identity and stores
    one immutable context observation for this node (external review 2026-10-08: privilege belongs
    to a context, and the channel keeps exactly one owner). Nothing is registered when the fact
    names another host, when the position cannot answer, or when its identity does not reach the
    privilege the fact asks for.
    """
    from runtime import session_io, session_registry, sessions
    if not isinstance(row, dict) or not row.get("channel_id"):
        return []
    position_address = str((host_map or {}).get(str(row.get("logical") or ""))
                           or row.get("logical") or "")
    recorded = []
    for logical, privilege in produced_exec_facts(document, node_id):
        wanted = str((host_map or {}).get(str(logical)) or logical)
        if not wanted or wanted != position_address or not str(privilege or "").strip():
            continue
        alive, _observed = sessions.probe(row, timeout=25.0)
        if not alive:
            continue
        fresh = next((item for item in session_registry.snapshot(root)
                      if item.get("channel_id") == row.get("channel_id")), row)
        identity = dict(fresh.get("identity") or {})
        matched, _why = _observed_privilege(identity, privilege)
        if not matched:
            continue
        recorded.append(session_registry.register_observation(
            root, channel_id=str(fresh["channel_id"]), logical=str(fresh.get("logical") or ""),
            privilege=str(privilege), identity=identity,
            environment=str(identity.get("environment") or "host"),
            source_node=str(node_id), source_call=str(identity.get("call_id") or ""),
            evidence_call_id=str(identity.get("call_id") or "")))
    return recorded


def host_contexts(path):
    """The optional third column of the host map: what kind of place a name really is.

    Deployment data, never a code list. A name marked ``container`` (or ``isolated``) is one the
    resident console cannot own, and that is the *declared* reason nothing is migrated out of it -
    a sandbox is not "not applicable" by nature, it says so here. Anything unmarked is a host.
    """
    rows = {}
    if not path:
        return rows
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        cells = [cell.strip() for cell in text.split(",")]
        if len(cells) >= 3 and cells[0] != "host":
            rows.setdefault(cells[0], cells[2])
    return rows


def graph_service_port(document, logical, *, service="http"):
    """The port the plan itself records for that host's service; empty when the plan says nothing.

    A step that runs *through* a position has no endpoint of its own (its scope names the position),
    but its recipe may still need to name the service it talks to. That number is a graph fact --
    `networkServiceInfo(host,laravel,http,81,...)` -- so it is read, not guessed.
    """
    if document is None or not logical:
        return ""
    fallback = ""
    for node in graph_nodes(document):
        if str(node.get("target_host") or "") != str(logical):
            continue
        port = str(node.get("port") or "")
        if not port.isdigit():
            continue
        if str(node.get("service") or "").lower() == str(service or "").lower():
            return port
        fallback = fallback or port
    return fallback


def resolve_position_recipe(recipe, *, address, port=""):
    """Freeze one entry recipe: the addresses a later step would need are baked in right here.

    A card cannot know a deployment's addresses, and a later step must not guess them either
    (2026-10-06 口径：地址是部署事实). The step that plants the entry has both in hand, so the
    row it leaves behind names them and later steps only re-observe the entry.

    A placeholder that cannot be answered is refused by name: a recipe registered with an empty port
    reads as a working entry and fails on every later use (measured 2026-10-08 in rehearsal).
    """
    raw = [str(part) for part in recipe.get("url_args") or []]
    if any("{port}" in part for part in raw) and not str(port).strip():
        raise ValueError("POSITION_PORT_UNRESOLVED")
    resolved = dict(recipe)
    resolved["url_args"] = [str(part).replace("{host}", str(address)).replace("{port}", str(port))
                            for part in raw]
    if any("{" in part or "}" in part for part in resolved["url_args"]):
        raise ValueError("POSITION_RECIPE_UNBOUND")
    return resolved


def privilege_matches(declared, observed):
    """Does what the entry answered match the privilege the card declared for it?"""
    text = str(observed or "").strip().lower()
    if not text:
        return False
    parts = [part.replace("_", "-") for part in text.replace("\t", " ").split() if part]
    want = str(declared or "").strip().lower().replace("_", "-")
    if not want:
        return True
    if want in ("root", "system", "administrator", "nt authority-system"):
        return parts[:1] == ["0"] or "root" in parts[:2]
    return want in parts


def observe_position_privilege(row, *, executor, timeout=60.0):
    """Ask the new entry who its commands run as; "" when it will not say.

    A declared privilege is an execution fact, so a position that declares one is asked to show it
    (bridge 2026-10-08: 权限属于执行上下文). An entry that answers something *else* is refused; an
    entry that only cannot answer yet is still registered, with the observation left unknown.
    """
    try:
        call = session_io.position_call(row, {"tool": "cmd", "cmd": "id -u; id -un"},
                                             executor=executor, timeout=timeout)
    except (ValueError, OSError, RuntimeError):
        return ""
    if not call["confirmed"]:
        return ""
    body = session_io._frame_body(str((call["outcome"].stdout if call["outcome"] else "") or ""),
                                       call["marker"])
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    return " ".join(lines[:2])


def register_declared_position(*, card, node_id, document=None, host_map=None, scope=None, root,
                               executor=None, source_call=""):
    """Register the entry this step left behind as a position; nothing replays the planting chain.

    Only a proved step reaches this call, so the entry has already answered once in this run; the
    row records where it is and the recipe that talks to it, and every later use observes it again.
    """
    position = card.get("provides_position")
    if not isinstance(position, dict):
        return None
    #: 位置在哪是图上的事实：卡没写就按这一步产出的 execCode 主机解析（不猜地址）。
    declared = str(position.get("host") or "")
    facts = produced_exec_facts(document, node_id) if document is not None else []
    logical = declared or str(facts[0][0] if facts else "")
    address = str((host_map or {}).get(logical) or logical)
    if not address:
        return None
    #: 这条入口的**执行身份**：卡声明优先（例如"经 SUID 助手以 root 执行"），否则取这一步产出事实的权限。
    privilege = str(position.get("privilege") or "")
    if not privilege and len(facts) > 0 and len(facts[0]) > 1:
        privilege = str(facts[0][1] or "")
    try:
        recipe = resolve_position_recipe(position.get("recipe") or {}, address=address,
                                         port=str((scope or {}).get("port")
                                                  or graph_service_port(document, logical)))
    except ValueError as error:
        #: 配方里有答不出来的占位：**拒绝登记**并具名，别留一条看着能用、每次用都失败的入口。
        return {"state": "failed", "reason": str(error)[:120], "logical": logical,
                "host": address}
    row = sessions.register_web_position(
        root, host=address, logical=logical, recipe=recipe,
        platform=str(recipe.get("platform") or "linux"),
        source_node=str(node_id), source_call=str(source_call or ""), privilege=privilege)
    observed = observe_position_privilege(row, executor=executor) if (privilege and executor) \
        else ""
    if privilege and executor and observed and not privilege_matches(privilege, observed):
        return {"state": "failed",
                "reason": "POSITION_PRIVILEGE_MISMATCH: %s -> %s" % (privilege, observed[:60]),
                "channel_id": row["channel_id"], "logical": logical, "host": address}
    if observed:
        #: 观测分三层记清楚（桥 2026-10-08）：这次调用**成功**、执行环境**符合声明**（身份/主机），
        #: 以及因此下游能用它拿到什么前提。这一行是"环境"那一层的证据，不是连接属性。
        session_registry.register_observation(
            root, channel_id=row["channel_id"], logical=logical, privilege=privilege,
            identity={"observed": observed}, environment="entry", source_node=str(node_id))
    return row


def build_entry_position(*, card, node_id, document=None, host_map=None, root, carrier=None,
                         executor=None, source_call="", timeout=120.0):
    """Build the entry a card says it leaves on a real host, then register it as a position.

    The step reached that host only through an isolated position, so there is nothing to reuse yet:
    the run authorises **itself** (its own key), runs the card's bounded action through the position
    it already owns, waits for the card's own marker, and then proves the new entry **through
    itself** -- one ssh command whose answer has to show the identity the card asks for. Short of
    that, the row is not registered and the card's cleanup is reported instead.
    """
    setup = card.get("entry_setup")
    if not isinstance(setup, dict) or carrier is None or executor is None:
        return None
    candidate = setup.get("candidate") or {}
    facts = produced_exec_facts(document, node_id) if document is not None else []
    logical = str(facts[0][0] if facts else "")
    address = str((host_map or {}).get(logical) or logical)
    if not address:
        return None
    from runtime.markers import shell_command

    #: 密钥属于**控制端**（键在哪儿生成、ssh 在哪儿跑，是一件事）：路径与控制端既有约定一致。
    #: 写成本机路径的话，真机第一步就会在控制端上拿一个 Windows 路径去 ssh-keygen。
    nonce = uuid4().hex[:10]
    key_path = "%s/agv_entry_%s.key" % (DELIVERY_MATERIALS_DIR, nonce)
    #: **密钥类型是部署事实**：2026-10-08 真机实测，宿主 sshd 接受 ed25519，而 RSA(SHA-1) 签名被
    #: 默认策略拒绝（key 写进 authorized_keys 了、`grep` 找得到，登录却静默失败）。注释里带
    #: `agv-entry-` 前缀，卡的 cleanup（`sed -i '/agv/d'`）才认得出这一行是本次运行加的。
    made = executor(["/bin/sh", "-c",
                     "mkdir -p %s && ssh-keygen -q -t ed25519 -N '' -C agv-entry-%s -f %s "
                     ">/dev/null 2>&1; chmod 600 %s; cat %s.pub"
                     % (DELIVERY_MATERIALS_DIR, nonce, key_path, key_path, key_path)], 60.0)
    public = str(made.stdout or "").strip()
    runtime_cleanup = ["rm -f %s %s.pub" % (key_path, key_path)]
    if not public:
        return {"state": "failed", "reason": "ENTRY_SETUP_KEY_UNREADABLE",
                "runtime_cleanup": runtime_cleanup}
    values = {"public_key": public, "key_path": key_path, "target_host": address,
              "username": str(candidate.get("username") or ""),
              "port": str(candidate.get("port") or "")}
    #: 身份证据要**正面**说明"这一发落在哪台机器上"：连接对象就是图的这台主机（地址 + 端口），
    #: 回答是从这条连接回来的 —— 这比"没看到容器标记"强（用户命名空间里也可以是 uid 0，
    #: 桥 2026-10-08 点名："缺标记"不是环境身份的正面证据）。
    connection = {"host": address, "port": values["port"], "account": values["username"],
                  "via": "entry ssh"}
    #: 台账：控制端密钥是这一轮**自己造**的资源，谁拥有、怎么删、现在是什么状态，都记下来。

    def filled(text):
        out = str(text)
        for name, value in values.items():
            out = out.replace("{" + name + "}", value)
        return out

    action = [filled(part) for part in setup["action"]]
    try:
        call = session_io.position_call(carrier, {"tool": "cmd", "cmd": shell_command(action)},
                                             executor=executor, timeout=timeout)
    except (ValueError, OSError, RuntimeError) as error:
        return {"state": "failed", "reason": "ENTRY_SETUP_ACTION_REFUSED: " + str(error)[:160]}
    #: 只看**帧里**的回答：帧外还有我们自己打印的标记行，拿整段当回答会把标记当身份读。
    body = session_io._frame_body(
        str((call["outcome"].stdout if call["outcome"] else "") or ""), call["marker"])
    if str(setup["ready_marker"]) not in body or not call["confirmed"]:
        return {"state": "failed", "reason": "ENTRY_SETUP_MARKER_MISSING",
                "cleanup": list(setup.get("cleanup") or []),
                "runtime_cleanup": runtime_cleanup}
    recipe = {"kind": "argv_command", "platform": "linux",
              "argv": ["/usr/bin/ssh", "-i", key_path,
                       *DELIVERY_SSH_OPTIONS.split(),
                       "-o", "ConnectTimeout=10",
                       "-p", values["port"],
                       "%s@%s" % (values["username"], address)], "command_flag": ""}
    probe = {"kind": "console_session", "session_type": "entry", "position_kind": "ssh",
             "recipe": recipe, "platform": "linux", "host": address, "logical": logical,
             "capacity": {"max_bytes": 4096, "source": "one ssh command"}}
    try:
        verified = session_io.position_call(probe, {"tool": "cmd", "cmd": filled(setup["verify"])},
                                                 executor=executor, timeout=timeout)
    except (ValueError, OSError, RuntimeError) as error:
        return {"state": "failed", "reason": "ENTRY_SETUP_VERIFY_REFUSED: " + str(error)[:160],
                "cleanup": list(setup.get("cleanup") or []),
                "runtime_cleanup": runtime_cleanup}
    seen = session_io._frame_body(
        str((verified["outcome"].stdout if verified["outcome"] else "") or ""),
        verified["marker"])
    identity = setup.get("identity") or {}
    wanted = str(identity.get("uid") or "").strip()
    first = next((line.strip() for line in seen.splitlines() if line.strip()), "")
    forbidden = [str(item) for item in identity.get("must_not_contain") or []]
    required = [str(item) for item in identity.get("must_contain") or []]
    if not verified["confirmed"] or (wanted and first != wanted) \
            or any(item and item in seen for item in forbidden) \
            or any(item and item not in seen for item in required):
        return {"state": "failed", "reason": "ENTRY_SETUP_IDENTITY_UNCONFIRMED",
                "observed": seen[:200], "connection": connection,
                "cleanup": list(setup.get("cleanup") or []),
                "runtime_cleanup": runtime_cleanup}
    row = sessions.register_web_position(
        root, host=address, logical=logical, recipe=recipe, platform="linux",
        source_node=str(node_id), source_call=str(source_call or ""), kind="ssh",
        #: 这条 ssh 入口以什么身份跑，是它自己的执行事实：卡要求 uid 0 就是要 root。
        #: 记下来，后面那一步（前提写 root）才选得中它，机器兜底也才有得对。
        privilege=("root" if str((setup.get("identity") or {}).get("uid") or "").strip() == "0"
                   else ""))
    #: 环境那一层的证据：这条入口连到的是哪台机器、命令以什么身份跑（真机实测为 `0 / ubuntu / init`
    #: ——uid 0、宿主主机名、1 号进程是 init 而不是容器进程）。
    session_registry.register_observation(
        root, channel_id=row["channel_id"], logical=logical,
        privilege=str(row.get("privilege") or ""),
        identity={"observed": seen[:200], "connection": connection},
        environment="host" if "docker" not in seen else "container",
        source_node=str(node_id), source_call=str(source_call or ""))
    #: 这一次落在**宿主**上的授权（卡声明的那条动作写进去的东西）也是一件落物：
    #: 归属写清、清理命令留着、状态留 pending（"请求过"不等于"已清掉"）。
    return {"state": "registered", "channel_id": row["channel_id"], "logical": logical,
            "host": address, "key_path": key_path, "connection": connection,
            "observation": seen[:200] or verified["marker"]}


def channel_candidates(document, node, rows, *, host_map=None):
    """Return all exact source-position bindings, without ranking or upstream substitution."""
    mapping = host_map or {}
    required = {(host, str(mapping.get(host) or host), str(privilege or ""))
                for host, privilege, _producers in exec_preconditions(document, node["id"])}
    out, ids = [], set()
    for row in rows:
        identity = str(row.get("channel_id") or "")
        if (not identity or identity in ids or row.get("kind") != "console_session"
                or row.get("lifecycle") == "revoked"
                or (row.get("observation") or {}).get("state") == "dead"):
            continue
        if not any(row.get("logical") == logical and row.get("host") == address
                    for logical, address, _privilege in required):
            continue
        if str(row.get("session_type") or "") in ("web", "entry"):
            #: 入口位置没有 console 端口：能用与否由它自己的入口回答（probe 走配方）。
            if not isinstance(row.get("recipe"), dict) or not row["recipe"]:
                continue
            ids.add(identity)
            out.append((row, "declared web position"))
            continue
        if not row.get("session_id") or not row.get("endpoint"):
            continue
        ids.add(identity)
        out.append((row, "explicit source-position binding"))
    #: 同一台主机上可能有两条件入口（容器里的 web 账户一条，经助手执行 root 的一条）：
    #: 这一步的前提写了哪个权限，就先要哪一条 —— 权限属于执行上下文，模型不该在两条里猜
    #: （桥 2026-10-08）。
    wanted = {privilege for _host, _address, privilege in required if privilege}
    if wanted and any(str(row.get("privilege") or "") in wanted for row, _reason in out):
        out = [item for item in out if str(item[0].get("privilege") or "") in wanted]
    return out


def resolve_carrier_for_node(document, node_id, rows, *, host_map=None):
    """Deterministic carrier for one step - no candidate list, no model call.

    爷爷 2026-10-08 口径：这一步"在哪台机、以什么权限"由**图上的前置**给定（本节点的 `execCode/2`
    前置；直接前置里没有就退一步，看产出那条前置的上一个步骤）。登记表按 `(主机, 规范化权限)`
    去重之后，这个键最多命中一条，所以这里只需要**读出来**，不需要"挑"。

    三种结果分开说：`"CONTROL"`（这一步不需要承载，从控制端执行）、命中的那一条、以及
    `"CARRIER_UNAVAILABLE"` —— 后者是**运行资源**事实，**不能**被写成"图上前置为假"。
    """
    from graph import criteria as graph_criteria
    from runtime import carriers

    def step_view(step_id):
        return {"preconditions": [
            {"predicate": str(fact.get("signature") or "").split("/")[0],
             "args": list(fact.get("arguments") or ()),
             "produced_by": fact.get("produced_by") or None}
            for fact in graph_criteria.node_criteria(document, str(step_id))]}

    graph = {str(item.get("id")): step_view(str(item.get("id")))
             for item in graph_nodes(document)}
    registry = [{"id": str(row.get("channel_id") or ""),
                 "host": str(row.get("logical") or row.get("host") or ""),
                 #: 键的一半用**图上的权限词**（登记时随会话一起记下来），两边同名才比得上；
                 #: 读回来的身份串（`NT AUTHORITY\SYSTEM` 之类）只是证据，不是键。
                 "identity_user": str(row.get("privilege_term")
                                      or (row.get("identity") or {}).get("user")
                                      or row.get("privilege") or "")}
                for row in rows]
    carrier, reason = carriers.resolve_carrier(step_view(str(node_id)), graph, registry)
    if carrier == "CONTROL":
        return None, "CONTROL"
    if carrier is None:
        return None, str(reason)
    matches = [row for row in rows
               if str(row.get("channel_id") or "") == str((carrier or {}).get("id"))]
    if len(matches) != 1:
        return None, "CARRIER_RECORD_NOT_UNIQUE"
    return matches[0], "CARRIER_RESOLVED"
