"""验证回合：把"这一步要证明什么"变成给模型的一次验证任务（D62）。

判据从图上来（`graph.criteria`），验证动作由模型做，机器判定只兜底。这个模块**只组装任务、
只解释答复**，不发起调用 —— 发起方是验证流程，谁跑谁记录（这样"验证过什么"永远和"跑了什么"对得上）。

为什么要它：今天"这一步成没成"是卡片自称 + 模型自称（账本里 `MODEL_CLAIM_NOT_MACHINE_VERIFIED`
就是这件事的诚实写法），而图里每条 LEAF 依赖本来就带着判据，运行时一次都没读过。验证回合把那份
判据真正用起来：**要证明的事实清单由程序算，怎么观测由模型定，结论必须引用本次原始输出**。
"""

from __future__ import annotations

VERIFY_KIND = "verified"

#: 结论词表（D65，按外部评审细化）：
#: * TRUE / FALSE —— 有证据的成立/不成立；
#: * UNKNOWN —— **正式结论**（没观测到目标状态时只能用这个，模型不许"补"出事实）；
#: * UNRESOLVED_CONFLICT —— 双方都有可信观测且互相矛盾时的正式结论（不是和稀泥）。
FACT_VERDICTS = ("TRUE", "FALSE", "UNKNOWN", "UNRESOLVED_CONFLICT")

#: 验证器必须声明"它的证据能证明什么"（D65 第 4 条）：
#: * sufficient —— 充分条件检查通过可以支持成立，未通过**未必**能否证；
#: * necessary  —— 必要条件检查失败可以支持不成立，通过**未必**能证明整体成立；
#: * partial    —— 只更新对应子条件，不能直接宣布整体成功。
PROOF_SCOPES = ("sufficient", "necessary", "partial")

#: 谁给的判断：探针（机器）还是模型。冲突裁决要用到它（D65 第 5 条）。
VERIFIERS = ("probe", "model")

from agents.verifier.prompts import SYSTEM


#: 判据种类 -> 用哪张卡去复核（D62 的兜底表：复用现有前置卡，不另起一套机制）。
#: 认不出的种类**不做机器兜底**：交模型判并标注"未兜底"，不因为"规则不认识"就把节点判死。
BACKSTOP_CARDS = {
    "network_reachability": "pre.nmap_tcp_probe",
    "service_exposure": "pre.service_version",
    "credential": "pre.credential_valid",
    "environment_fact": "pre.netsecurity_firewall_state",
    "capability": "pre.tool_present",
}


def backstop_for(criteria_row) -> str:
    """这条判据该用哪张卡复核；没有就给空串（=不硬判）。"""
    return BACKSTOP_CARDS.get(str((criteria_row or {}).get("validation_kind") or ""), "")


def verification_task(document, node_id, *, harvest=(), calls=(), graph_criteria=None,
                     must_produce=None, host_map=None, source_bindings=None,
                     role_accounts=None) -> dict:
    """一次验证任务的输入负载。

    ``graph_criteria``（通常是 `graph.criteria.node_criteria`）与 ``must_produce``（`criteria.to_produce`）
    都由调用方传 —— 这里不 import 图模块，于是"验证什么"和"怎么读图"两件事互不纠缠，测试也不必造文档。
    "本步要产出的 OR 事实"这份关系在图上写在 OR 节点那一侧，所以它是**算好传进来**的，不在这里猜。
    """
    rows = list(graph_criteria or ())
    mine = {str(item.get("ref")) for item in (must_produce or ())}
    for row in rows:
        #: 区分"本步要产出的"和"上一步留下的"：前者只能用本步自己的观测支持；后者是输入，
        #: 本步**重新观测到**才算证据，否则如实 UNKNOWN（不许引用别的节点的调用 —— 2026-10-06 烟测实测）。
        row["role"] = "produce" if str(row.get("ref")) in mine else "consume"
    #: **本步要产出的事实也要进清单**：只问"消费的事实"会把"这一步到底成没成"漏掉，
    #: 模型只能对别人的东西答 UNKNOWN（2026-10-06 烟测就是这么发现的）。产出的事实排在最前。
    rows = [dict(item, role="produce") for item in (must_produce or ())] + rows
    return {"node_id": str(node_id),
            "identity_context": {
                "kind": "deployment_declaration",
                "role_addresses": dict(host_map or {}),
                "vantage_roles": dict(source_bindings or {}),
                #: 部署声明的"图上的账号角色 = 现场哪个真实账号"（只有身份，没有材料）。
                #: 缺了它，`getAccount(pc1,domain_administrator,…)` 与现场看到的
                #: `WHOAMIANONY\Administrator` 对不上，模型只能如实答 UNKNOWN（walk-134 node 5）。
                "role_accounts": {str(role): dict(value)
                                  for role, value in (role_accounts or {}).items()},
            },
            "facts": rows,
            "must_produce": list(must_produce or ()),
            #: 本轮已有的收获（壳 / 凭据）：验证时可以用，但**不能**拿它当"刚刚观测到"。
            #: 会话行要带上**引擎自己观测到的身份**（谁、什么权限、什么环境、哪次调用看到的）：
            #: 这一步的交接是不是成了、交回来的是不是那个身份，是引擎亲眼看过的现场事实，
            #: 光给一行"有会话"模型看不见（2026-10-08 walk-152 node 44 实测：会话以系统身份登记了、
            #: 机器判据也立了产出事实，模型却因为看不见这条会话而写"不满足"）。
            "harvest": [{"row_type": row.get("row_type"), "kind": row.get("kind"),
                         "host": row.get("host"), "logical": row.get("logical"),
                         "privilege": row.get("privilege"), "session_id": row.get("session_id"),
                         "credential_id": row.get("credential_id"),
                         "session_type": row.get("session_type"),
                         "observed_identity": {"user": (row.get("identity") or {}).get("user"),
                                               "uid": (row.get("identity") or {}).get("uid"),
                                               "hostname": (row.get("identity") or {}).get("hostname"),
                                               "environment": (row.get("identity") or {}).get("environment")},
                         "identity_call_id": (row.get("identity") or {}).get("call_id"),
                         "observed_at": (row.get("observation") or {}).get("at"),
                         "observation_state": (row.get("observation") or {}).get("state")}
                        for row in harvest or ()],
            #: 这一步已经跑过的调用（引用只能从这些里挑）。
            "calls": [{"call_id": str((row or {}).get("call_id") or ""),
                       "request": (row or {}).get("request") or {}}
                      for row in calls or ()],
            "backstop": {"machine_checkable": [row.get("ref") for row in rows
                                               if row.get("machine_checkable")]}}


def read_verdict(payload, *, expected_refs, credited_calls) -> dict:
    """Validate coverage, provenance and proof labels; do not establish facts."""
    if (not isinstance(payload, dict)
            or ("kind" in payload and payload["kind"] != VERIFY_KIND)):
        raise ValueError("VERIFY_SHAPE: expected a facts object")
    facts = payload.get("facts")
    if not isinstance(facts, list) or not facts:
        raise ValueError("VERIFY_SHAPE: facts must be a non-empty list")
    known = {str(ref) for ref in expected_refs}
    credited = {str(call) for call in credited_calls}
    read, seen = [], set()
    for row in facts:
        if not isinstance(row, dict):
            raise ValueError("VERIFY_SHAPE: each fact is an object")
        ref = row.get("ref")
        if not isinstance(ref, str) or ref not in known:
            raise ValueError("VERIFY_REF_UNKNOWN: %s" % ref)
        if ref in seen:
            raise ValueError("VERIFY_REF_DUPLICATE: " + ref)
        seen.add(ref)
        verdict, proof, verifier = row.get("verdict"), row.get("proof"), row.get("verifier")
        if verdict not in FACT_VERDICTS:
            raise ValueError("VERIFY_VERDICT_UNKNOWN: " + ref)
        if proof not in PROOF_SCOPES:
            raise ValueError("VERIFY_PROOF_UNKNOWN: " + ref)
        if verifier not in VERIFIERS:
            raise ValueError("VERIFY_VERIFIER_UNKNOWN: " + ref)
        #: An UNKNOWN row carries no citation, and a model that says so with an explicit `null`
        #: is not making a shape error: treat it as "no citation" instead of throwing the whole
        #: verification turn away (measured 2026-10-08, walk-132 node 5).
        call_id, quote = row.get("call_id") or "", row.get("quote") or ""
        if not isinstance(call_id, str) or not isinstance(quote, str):
            raise ValueError("VERIFY_CITATION_INVALID: " + ref)
        if verdict in ("TRUE", "FALSE") or call_id or quote:
            if call_id not in credited:
                raise ValueError("VERIFY_CALL_UNCREDITED: " + ref)
            if not quote.strip():
                raise ValueError("VERIFY_QUOTE_MISSING: " + ref)
        item = {"ref": ref, "verdict": verdict, "proof": proof, "verifier": verifier,
                "call_id": call_id, "quote": quote}
        if verdict in ("UNKNOWN", "UNRESOLVED_CONFLICT"):
            reason, checked = row.get("reason"), row.get("checked_calls")
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError("VERIFY_UNKNOWN_REASON_MISSING: " + ref)
            if (not isinstance(checked, list)
                    or any(not isinstance(call, str) for call in checked)
                    or len(checked) != len(set(checked)) or set(checked) != credited):
                raise ValueError("VERIFY_UNKNOWN_SOURCE_INVALID: " + ref)
            item.update(reason=reason.strip(), checked_calls=list(checked))
        read.append(item)
    missing = sorted(known - seen)
    if missing:
        raise ValueError("VERIFY_REF_MISSING: %s" % ", ".join(missing))
    return {"node_id": "", "facts": read}
