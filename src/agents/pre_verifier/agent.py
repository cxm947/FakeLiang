"""节点前提验证角色。"""

from copy import deepcopy

from src.orchestration.validation import PRE_FIELDS, RESULTS, _aggregate, _identity, _observation
from src.orchestration.model import UNKNOWN

def pre(context):
    expected = context["leaf_requirements"]
    record = context.get("record")
    outer_valid = isinstance(record, list)
    rows = record if outer_valid else []
    grouped = {fid: [] for fid in expected}
    complete = outer_valid
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("fact_id"), str):
            complete = False
            continue
        fid = row["fact_id"]
        if fid not in grouped:
            complete = False
            continue
        grouped[fid].append(row)
    belonging = context.get("belongs", True) and not context.get("duplicate", False)
    facts, evidence, values = [], [], []
    for fid in expected:
        entries = grouped[fid]
        row = entries[0] if len(entries) == 1 else {}
        valid = (bool(belonging) and outer_valid and len(entries) == 1
                 and set(row) == PRE_FIELDS and row.get("节点类型") == "LEAF"
                 and row.get("result") in RESULTS
                 and _observation(row.get("使用的skill"))
                 and _observation(row.get("返回的结果"))
                 and context["known"].get(fid) is True
                 and fid in context["snapshot"])
        value = row["result"] if valid else UNKNOWN
        basis = {"observed": row.get("返回的结果"),
                 "reference": f"nodes/{context['node_id']}/pre/{fid}",
                 "使用的skill": row.get("使用的skill")}
        identity = _identity(context, fid, context["snapshot"])
        entry = {"fact_id": fid, "result": value, "valid": bool(valid),
                 **deepcopy(basis), "evidence": [deepcopy(basis)] if valid else [], **identity}
        facts.append(entry)
        if valid:
            evidence.append({"fact_id": fid, "result": value, **deepcopy(basis), **identity})
        values.append(value)
        complete = complete and valid
    result = _aggregate(values, complete and bool(belonging))
    return {"result": result, "reason": "前提验证" + result,
            "evidence": evidence, "facts": facts}

