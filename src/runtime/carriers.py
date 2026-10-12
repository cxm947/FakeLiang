"""Pure carrier registry; no input mutation.
step: {"preconditions": [fact, ...]}
fact: {"predicate": str, "args": list/tuple, "produced_by": optional step_id}
graph: {step_id: step}; state/registry: list of carrier records.
Records use nonempty string host/identity_user and string/integer id.
"""
import re
from collections.abc import Mapping


_PROMPT = re.compile(
    r"^(?:(?:PS )?(?:[A-Za-z]:)?\\[^>\r\n]*>"
    r"|[^\s@]+@[^\s:]+:[^$#\r\n]*[$#])[ \t]*"
)
_ECHO = frozenset({"whoami", "id -un", "echo agvCHREADY", "agvCHREADY"})


def _identity(raw):
    if not isinstance(raw, str):
        raise ValueError("RECORD_SHAPE_INVALID")
    lines = [_PROMPT.sub("", line.strip(), count=1).strip()
             for line in raw.splitlines()]
    lines = [line for line in lines if line]
    # Only discard exact known echoes when accompanied by another line.
    # A lone identity such as "whoami" must retain its spelling.
    if len(lines) > 1:
        lines = [line for line in lines if line not in _ECHO]
    if len(lines) != 1:
        raise ValueError("RECORD_SHAPE_INVALID")
    value = lines[0]
    label = "Server username:"
    if value.startswith(label):
        value = value[len(label):].strip()
    if not value:
        raise ValueError("RECORD_SHAPE_INVALID")
    return value


def canonical_key(record):
    if not isinstance(record, Mapping):
        raise ValueError("RECORD_SHAPE_INVALID")
    host = record.get("host")
    if not isinstance(host, str) or not host.strip():
        raise ValueError("RECORD_SHAPE_INVALID")
    return host, _identity(record.get("identity_user"))


def _record_id(record):
    value = record.get("id")
    # Restrict event fields to JSON scalar values, excluding bool.
    if type(value) not in (str, int):
        raise ValueError("RECORD_SHAPE_INVALID")
    return value


def register(state, record):
    key = canonical_key(record)
    new_id = _record_id(record)
    for existing in state:
        if canonical_key(existing) == key:
            return list(state), {
                "action": "dropped", "reason": "duplicate_key",
                "kept": _record_id(existing), "dropped": new_id,
            }
    return [*state, dict(record)], {"action": "registered", "id": new_id}


def _exec_key(facts):
    for fact in facts:
        args = fact.get("args", ())
        if (fact.get("predicate") == "execCode"
                and isinstance(args, (list, tuple)) and len(args) == 2):
            return canonical_key({"host": args[0], "identity_user": args[1]})
    return None


def resolve_carrier(step, graph, registry):
    """First execCode/2 in prerequisite order wins; look back at most once.
    Missing carrier returns (None, CARRIER_UNAVAILABLE), never success CONTROL.
    Graph references must exist; this function does not evaluate fact truth.
    """
    facts = step.get("preconditions", ())
    key = _exec_key(facts)
    if key is None:
        for fact in facts:
            producer = fact.get("produced_by")
            if producer is not None:
                key = _exec_key(graph[producer].get("preconditions", ()))
                if key is not None:
                    break
    if key is None:
        return "CONTROL", "CONTROL"
    for record in registry:
        if canonical_key(record) == key:
            return record, "CARRIER_RESOLVED"
    return None, "CARRIER_UNAVAILABLE"
