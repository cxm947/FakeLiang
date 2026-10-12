"""Optional SDK import and request arguments."""
from __future__ import annotations

from .text import _json_object_prompts


def _sdk_module():
    """官方 SDK，装了就返回模块，没装返回 None（测试环境可能没装，退路是自带 urllib）。"""
    try:
        from openai import OpenAI  # noqa: F401
    except Exception:
        return None
    import openai
    return openai


#: 关思考的**关**只有一种写法：DeepSeek 文档里的 ``extra_body={"thinking": {"type": "disabled"}}``。
#: 2026-10-06 实测（爷爷口径）：这条字段只在**直连供应商**时算数 ——
#:   直连 https://api.deepseek.com 的 chat.completions：输出只有 message、0 个思考 token；
#:   同一份 payload 经本机 127.0.0.1:7789 model router：依旧吐出 reasoning 项（多出来的是
#:   被改写的请求体，input 还多 25 token）。所以调用方要用官方 SDK 直连，别指到 router 上。
def sdk_kwargs(*, model: str, system: str, user: str, temperature: float = 0.0,
               max_tokens: int = 0, effort: str = "") -> dict:
    """官方 SDK ``chat.completions.create`` 的入参（纯函数：形状可以离线钉住）。"""
    system, user = _json_object_prompts(str(system), str(user))
    kwargs = {
        "model": str(model),
        "temperature": float(temperature),
        "messages": [{"role": "system", "content": str(system)},
                     {"role": "user", "content": str(user)}],
        #: 需要的是一个 JSON 对象，不是散文：别让调用方去猜括号。
        "response_format": {"type": "json_object"},
    }
    if max_tokens:
        kwargs["max_tokens"] = int(max_tokens)
    if str(effort or "").strip().lower() == "none":
        kwargs["extra_body"] = {"thinking": {"type": "disabled"}}
    return kwargs
