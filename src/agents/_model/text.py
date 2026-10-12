"""Model response text parsing and request digests."""
from __future__ import annotations

import json
from hashlib import sha256

from agents._prompt_resources import read_prompt





#: A fenced code block, spelled without a literal backtick so this file stays quotable.
FENCE = "\x60\x60\x60"

def _digest(text: str) -> str:
    """A stable id for one request: the same prompt always hashes to the same value."""
    return sha256(text.encode("utf-8")).hexdigest()


def _excerpt(text: str, *, secret: str = "", limit: int = 600) -> str:
    """A bounded copy of a provider body for the record, with the transport credential removed.

    Only for replies that could not be used: an answer that parsed is already on the record, and
    copying bodies around is how credentials leak. A secret still present in the excerpt is
    replaced, not dropped, so the shape of the failure stays readable.
    """
    body = str(text or "")
    if secret:
        body = body.replace(str(secret), "<redacted>")
    return body[:limit]


def _decoded_dump(text: str) -> str:
    """One searchable string for whatever the answer decodes to; empty when it is not JSON.

    A credential can hide in a non-object answer too (run86): the decoded value - a string, a
    list, a number - is what the guard has to look at, not just the JSON object case.
    """
    try:
        value = json.loads(text)
    except ValueError:
        return ""
    return json.dumps(value, ensure_ascii=False)


def _parse_json_text(text: str) -> tuple[dict | None, str]:
    """Read exactly one JSON object, optionally in one complete JSON fence."""
    body = str(text or "").strip()
    if not body:
        return None, "the model returned an empty answer"

    lines = body.splitlines()
    if (len(lines) >= 3 and lines[0] in (FENCE, FENCE + "json")
            and lines[-1] == FENCE):
        body = "\n".join(lines[1:-1]).strip()

    try:
        payload = json.loads(body)
    except ValueError as error:
        return None, "the answer is not JSON: " + str(error)

    if not isinstance(payload, dict):
        return None, "the answer is not a JSON object"
    return payload, ""


def _json_object_prompts(system: str, user: str) -> tuple[str, str]:
    """Supply the JSON-mode instruction only when both caller texts lack it."""
    if "json" in system.lower() or "json" in user.lower():
        return system, user
    instruction = read_prompt(__package__, "templates/json_object_instruction.txt")
    if "json" not in instruction.lower():
        raise ValueError("MODEL_JSON_OBJECT_INSTRUCTION_MISSING_JSON")
    return system + ("\n\n" if system else "") + instruction, user
