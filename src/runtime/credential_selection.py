"""Credential material selection and representation ordering."""
from __future__ import annotations

from runtime.credential_facts import FACT_FIELDS, _bindings
from runtime.credential_source import (
    _digest, _error, _external_key, _private_path, _resolve,
)


def _check_host(row, host_map):
    if host_map is not None:
        current = str(host_map.get(row["logical"]) or row["logical"])
        if current != row["host"]:
            _error("STALE_HOST")


def _matching(rows, bindings, host_map):
    candidates = []
    for row in rows:
        if any(tuple(row[key] for key in FACT_FIELDS) == fact
               and (not producers or row["source_node"] in producers)
               for fact, producers in bindings):
            _check_host(row, host_map)
            candidates.append(row)
    return candidates


def _select_records(candidates, *, run_dirs=(), repository=None, user="", realm=""):
    if not candidates:
        _error("MISSING")
    resolved, conflicts = [], set()
    for row in candidates:
        material = _resolve(row, run_dirs=run_dirs, repository=repository)
        if user and material["user"] != user:
            conflicts.add("USER_CONFLICT")
            continue
        if realm and material["domain"] != realm:
            conflicts.add("REALM_CONFLICT")
            continue
        resolved.append((row, material))
    if not resolved:
        _error("USER_CONFLICT" if "USER_CONFLICT" in conflicts else "REALM_CONFLICT")
    # Carrying the same proof twice does not invent a second credential; independent rows do.
    unique = {}
    for row, material in resolved:
        key = (row["source_run"], row["source_node"], *[row[name] for name in FACT_FIELDS],
               row["source_path"], row["source_key"], row["source_digest"])
        unique[key] = material
    if len(unique) != 1:
        #: 同一个账号的两种**表示**（cleartext 密码 / NTLM hash）不是两个凭据 —— kiwi 的 creds_all
        #: 一次就给两种，把它们当歧义会让整条支线停住（2026-10-06 walk-47：node 48/2/44 全卡在
        #: CREDENTIAL_AMBIGUOUS）。挑法写明：**密码优先**（一个明文口令哪里都能登，hash 要对方支持
        #: 传哈希），并且挑中的那一种随手交给下游，别让模型自己猜手里拿的是哪种。
        #: 只有"同一个账号 + 恰好这两种表示"才放宽；真正的两套凭据仍然报歧义。
        accounts = {(str(m.get("user") or ""), str(m.get("domain") or "")) for m in unique.values()}
        #: 材料里的字段叫 mode（password / ntlm），不是 kind：第一次按 kind 找的是空值，放宽没触发。
        kinds = {str(m.get("mode") or m.get("kind") or "") for m in unique.values()}
        if len(accounts) == 1 and kinds == {"password", "ntlm"}:
            for preference in ("password", "ntlm"):
                for material in unique.values():
                    if str(material.get("mode") or material.get("kind") or "") == preference:
                        chosen = dict(material)
                        chosen["representation"] = preference
                        return chosen
        _error("AMBIGUOUS")
    return dict(next(iter(unique.values())))


def select(document, node, rows, *, host_map=None, run_dirs=(), repository=None,
           user="", realm=""):
    """Legacy single-reference selection retains its exact-one contract."""
    return _select_records(_matching(rows, _bindings(document, node), host_map),
                           run_dirs=run_dirs, repository=repository, user=user, realm=realm)


def select_candidates(document, node, rows, *, source=None, host_map=None,
                      run_dirs=(), repository=None, user="", realm=""):
    """Supply one candidate per origin, usable-representation first, provenance second.

    Within an origin :func:`_select_records` already prefers the cleartext password over the
    NTLM hash ("一个明文口令哪里都能登，hash 要对方支持传哈希"). Across origins that rule was
    missing, so a derived *hash* outranked a declared *password* and the first candidate could
    not fill the slot it was handed to at all.

    实测 2026-10-06 walk-68 node 2：凭据候选 order=1 是 node 5 从 LSASS 读出来的 NTLM hash，
    order=2 才是配置里的明文口令。模型照「derived first」把 hash 填进 `schtasks /p` 与
    `net use \\\\host\\C$ /user:... <口令>` 这种**只吃明文**的槽位，回执分别是
    `错误: 拒绝访问`（create/run）与 `发生系统错误 1326 / 登录失败: 未知的用户名或错误密码`
    （net use）——同一个洞、同一条命令、只换了候选就一次失败一次成功，日志里两处都被
    redaction 抹成 `<redacted>`，于是看起来像"随机失败"，白烧了四个回合里的三个。

    一个明文口令在**任何**槽位都能用（密码槽直接填；要传哈希的工具普遍也收 `-p <明文>`），
    hash 只在对方收哈希时可用。所以先按表示排（password → ntlm），同表示内再按来源排
    （derived → external），来源仍留在记录里，归因不丢。

    ponytail: direct getAccount/hasAccount facts bind hosts; no transitive account search.
    A bad existing reference refuses the dispatch instead of silently changing its origin.
    """
    bindings = _bindings(document, node)
    matching = _matching(rows, bindings, host_map)
    grouped = {"derived": [], "external": []}
    for row in matching:
        grouped[row.get("source_kind", "external")].append(row)
    if source is not None:
        path = str(_private_path(source["path"], run_dirs=run_dirs, repository=repository))
        identities = {(row["source_path"], row["source_key"], row["source_digest"])
                      for row in grouped["external"]}
        for fact, _producers in bindings:
            logical, graph_user, symbol, privilege = fact
            key = _external_key(source, graph_user, symbol)
            if key is None:
                continue
            digest = _digest(source["credentials"][key])
            identity = (path, key, digest)
            if identity in identities:
                continue
            identities.add(identity)
            grouped["external"].append({"logical": logical, "graph_user": graph_user,
                                        "symbol": symbol, "privilege": privilege,
                                        "source_node": "", "source_run": "",
                                        "source_path": path, "source_key": key,
                                        "source_digest": digest})
    ranked = []
    for rank, origin in enumerate(("derived", "external")):
        if grouped[origin]:
            material = _select_records(grouped[origin], run_dirs=run_dirs,
                                       repository=repository, user=user, realm=realm)
            ranked.append((origin, rank, material))
    if not ranked:
        _error("MISSING")
    #: 材料里的字段叫 mode（password / ntlm），不是 kind：只认一个会让排序静默失效。
    #: 只有**确知是哈希**的表示才降级；什么都没声明的按明文对待（外部源给的都是明文口令），
    #: 免得一个没写 mode 的旧源被当成"不能用"排到后面去。
    hash_like = {"ntlm", "hash", "ntlm-hash", "lm", "lm-hash"}

    def _sort_key(item):
        _origin, origin_rank, material = item
        representation = str(material.get("mode") or material.get("kind") or "").strip().lower()
        return (1 if representation in hash_like else 0, origin_rank)

    ranked.sort(key=_sort_key)
    return [{"order": order, "origin": origin, "credential_ref": material}
            for order, (origin, _origin_rank, material) in enumerate(ranked, 1)]
