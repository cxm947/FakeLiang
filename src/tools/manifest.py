"""Render the tool manifest for a model prompt."""

import json


def build_manifest(registry) -> list[dict]:
    return registry.manifest()


def render_manifest_text(registry) -> str:
    lines = ["可用工具（只能从下列 tool 中选一个）："]
    for item in registry.manifest():
        lines.append("- " + item["name"] + "：" + item["description"])
        lines.append("  arguments schema: " + json.dumps(item["schema"], ensure_ascii=False))
        lines.append("  示例: " + json.dumps(item["example"], ensure_ascii=False))
    lines.append("target 只能是 kali 或 session；provider 由 target=session 的会话记录决定。")
    return "\n".join(lines)

