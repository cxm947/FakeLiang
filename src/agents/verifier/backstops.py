"""Verification backstops: what the run can decide from its own receipts and probes."""
from __future__ import annotations

import re


from .reachability import REACHABILITY_PROBE, backstop_reachability, _net_access_criterion
from .execution_identity import (
    EXEC_CODE_SIGNATURE, _exec_code_criterion, _observed_privilege, backstop_exec_code,
)
