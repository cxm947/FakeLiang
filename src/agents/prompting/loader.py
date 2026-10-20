"""角色依据的共享加载。"""

from pathlib import Path

import yaml

from .schema import validate_prompt


def load_prompt(path):
    """加载并验证角色依据，保留正文换行。"""
    document = yaml.safe_load(Path(path).read_text(encoding="utf-8-sig"))
    return validate_prompt(document)
