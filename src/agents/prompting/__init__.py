"""角色依据的共享加载与渲染。"""

from .loader import load_prompt
from .render import render_messages

__all__ = ["load_prompt", "render_messages"]
