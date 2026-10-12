"""Assemble a native request offline; never construct a model or obtain a key."""
from copy import deepcopy

from .render import assemble
from agents.executor.native_tools import OVERLAY, schemas


def assemble_native(request):
    raw = deepcopy(request)
    card = raw.pop("card", None) or {"allowed_tools": ["cmd", "finish"]}
    raw["tools"] = []
    result = assemble(raw)
    result["protocol"] = "native-tools-v1"
    result["messages"][0]["content"] += OVERLAY
    result["tools"] = schemas(card)
    return result
