"""Shared planner refusals and text checks."""

class PlannerIOError(ValueError):
    """A malformed message or a named refusal of the proposed choice."""

    def __init__(self, reason_code, detail=None, *, facts=None):
        self.reason_code = reason_code
        self.detail = detail or ""
        self.facts = facts
        super().__init__(reason_code + (": " + self.detail if self.detail else ""))

    def as_refusal(self):
        result = {"reason_code": self.reason_code, "detail": self.detail}
        if self.facts is not None:
            result["facts"] = self.facts
        return result


def _text(value) -> bool:
    return isinstance(value, str) and value.strip() != "" and value.strip() != "null"
