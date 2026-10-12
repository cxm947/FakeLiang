"""运行层：固定 argv 执行、调用记录与脱敏。

会话 / 接管 / 装配 / 判定 / 整图循环都不在这里了（2026-10-04 删旧），
所以 `import runtime` 不会顺带拉起那些机器。
"""

from .redact import redact_argv, redact_text
from .runner import (CallResult, ExecOutcome, execute, new_call_id, plan_payload,
                     subprocess_executor)

__all__ = [
    "CallResult",
    "ExecOutcome",
    "execute",
    "new_call_id",
    "plan_payload",
    "redact_argv",
    "redact_text",
    "subprocess_executor",
]
