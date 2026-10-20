"""角色依据的共享渲染。"""

from jinja2 import Environment, StrictUndefined

from .schema import validate_prompt


def render_messages(document, **variables):
    """验证并渲染角色依据，缺少变量时不通过。"""
    validate_prompt(document)
    environment = Environment(undefined=StrictUndefined, keep_trailing_newline=True)
    return [
        {"role": role,
         "content": environment.from_string(document[field]).render(**variables)}
        for role, field in (("system", "system_template"), ("user", "user_template"))
    ]
