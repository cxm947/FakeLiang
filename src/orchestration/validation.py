"""角色共用的节点与依据验证。"""

from src.orchestration.model import FAIL, PASS, UNKNOWN

RESULTS = (PASS, FAIL, UNKNOWN)
PRE_FIELDS = frozenset(("fact_id", "节点类型", "result", "使用的skill", "返回的结果"))
NODE_FIELDS = frozenset(("node_id", "节点类型", "result", "evidence",
                         "验证该节点的skill", "返回的结果"))
IDENTITY_FIELDS = frozenset(("run_id", "attempt_id", "snapshot", "fact_version"))


def _aggregate(values, complete=True):
    if FAIL in values:
        return FAIL
    return PASS if complete and all(value == PASS for value in values) else UNKNOWN


def _observation(value):
    if not isinstance(value, str) or not value.strip():
        return False
    normalized = value.strip().replace("\\", "/").lower()
    return not any(reference in normalized for reference in ("nodes/", "facts/", ":pre", ":post"))


def _same(value, expected):
    if type(value) is not type(expected):
        return False
    if isinstance(value, dict):
        return set(value) == set(expected) and all(_same(value[key], expected[key]) for key in value)
    if isinstance(value, list):
        return len(value) == len(expected) and all(_same(left, right) for left, right in zip(value, expected))
    return value == expected


def _belongs(record, context, fact_version):
    expected = {key: context[key] for key in ("run_id", "attempt_id", "snapshot")}
    expected["fact_version"] = fact_version
    return all(key not in record or _same(record[key], value) for key, value in expected.items())


def _identity(context, fact_id, versions):
    return {"run_id": context["run_id"], "node_id": context["node_id"],
            "attempt_id": context["attempt_id"], "fact_version": versions.get(fact_id)}


def _node_record(record, node_id, kind, optional=()):
    return (isinstance(record, dict) and NODE_FIELDS <= set(record)
            and set(record) <= NODE_FIELDS | IDENTITY_FIELDS | set(optional)
            and type(record.get("node_id")) is int and record["node_id"] == int(node_id)
            and record.get("节点类型") == kind and record.get("result") in RESULTS
            and _observation(record.get("验证该节点的skill"))
            and _observation(record.get("返回的结果")))

