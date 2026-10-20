"""Legacy record validation for the explicitly simulated orchestration runner."""

from copy import deepcopy

from src.orchestration.validation import _node_record, _observation
from src.orchestration.model import UNKNOWN


def action(context):
    record = deepcopy(context.get("record"))
    if not isinstance(record, dict):
        return {"result": UNKNOWN, "ended": True, "evidence": [],
                "invalid_result": True, "reason": "验证未知"}
    if (not _node_record(record, context["node_id"], "AND", ("ended",))
            or not _observation(record.get("evidence"))):
        record["original_result"] = deepcopy(record.get("result"))
        record["invalid_result"] = True
        record["result"] = UNKNOWN
    record.setdefault("ended", True)
    return record
