import json

from runtime.carriers import canonical_key, register, resolve_carrier


def test_canonical_key():
    values = [
        r"\Windows\system32>Server username: NT AUTHORITY\SYSTEM",
        "agvCHREADY\nC:\\Windows\\system32>\nServer username: root",
        "alice@node:~$ whoami\nDomain\\Alice",
        "whoami",
    ]
    assert [canonical_key({"host": "H", "identity_user": value})
            for value in values] == [
        ("H", r"NT AUTHORITY\SYSTEM"), ("H", "root"),
        ("H", r"Domain\Alice"), ("H", "whoami"),
    ]


def test_register():
    original = []
    first = {"id": "a", "host": "H", "identity_user": "root"}
    second = {"id": "b", "host": "H",
              "identity_user": "Server username: root"}
    state1, added = register(original, first)
    state2, dropped = register(state1, second)
    assert (original, state1, state2, added,
            json.loads(json.dumps(dropped))) == (
        [], [first], [first], {"action": "registered", "id": "a"},
        {"action": "dropped", "reason": "duplicate_key",
         "kept": "a", "dropped": "b"},
    )


def test_resolve_carrier():
    carrier = {"id": "a", "host": "H", "identity_user": "root"}
    execution = {"predicate": "execCode",
                 "args": ["H", "Server username: root"]}
    missing = {"predicate": "execCode", "args": ["absent", "root"]}
    fact = {"predicate": "ready", "args": [], "produced_by": 0}
    older = {"predicate": "ready", "args": [], "produced_by": 1}
    wrong_arity = {"predicate": "execCode", "args": ["H"]}
    graph = {0: {"preconditions": [execution]},
             1: {"preconditions": [fact]}}
    cases = [
        [execution],         # Direct requirement, normalized key.
        [fact],              # One producer step back (id 0 is valid).
        [],                  # No carrier requirement.
        [fact, missing],     # Direct miss must not use producer's carrier.
        [older],             # Never follow two producer steps.
        [wrong_arity],       # Only execCode/2 matches.
    ]
    assert [resolve_carrier({"preconditions": facts}, graph, [carrier])
            for facts in cases] == [
        (carrier, "CARRIER_RESOLVED"), (carrier, "CARRIER_RESOLVED"),
        ("CONTROL", "CONTROL"), (None, "CARRIER_UNAVAILABLE"),
        ("CONTROL", "CONTROL"), ("CONTROL", "CONTROL"),
    ]


if __name__ == "__main__":
    test_canonical_key()
    test_register()
    test_resolve_carrier()
