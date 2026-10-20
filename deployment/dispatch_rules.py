"""The dispatch contract shared by the three stage prompts.

The authoritative tool list is the capability registry (``src.tools``): the model emits
``{tool, target, arguments}`` and the registry validates the arguments before the single
dispatcher (``deployment.request_dispatch``) sends anything. This module names what each
stage may emit so a prompt cannot drift from the registry without a test failing.

The earlier four-field text (``tool / name / via / content``) is a compatibility view:
``src.tools.adapt.to_legacy_request`` still accepts stored requests, but it is no longer
what the prompts teach.
"""

from __future__ import annotations

#: Tools each stage may emit, in the order its prompt lists them.
STAGE_TOOLS = {
    "pre": ("run_command", "run_script", "session_command"),
    "post": ("run_command", "run_script", "session_command"),
}

#: Sentences every stage prompt must carry verbatim.
SHARED_LINES = (
    "只返回一个 JSON 对象，恰好包含 tool、target、arguments。",
    "target 只能是 kali 或 session",
)


def action_tools():
    """Action's tool list comes from the same registry the dispatcher uses."""
    from src.tools.dispatch import default_registry
    return tuple(default_registry().names())


__all__ = ["SHARED_LINES", "STAGE_TOOLS", "action_tools"]
