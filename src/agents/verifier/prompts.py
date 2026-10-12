"""Exact static text for verification requests and shape retries."""
from __future__ import annotations

from agents._prompt_resources import read_prompt

SYSTEM = read_prompt(__package__, "templates/runtime_system.txt")
RETRY_PREFIX = read_prompt(__package__, "templates/retry_prefix.txt")
RETRY_SUFFIX = read_prompt(__package__, "templates/retry_suffix.txt")
