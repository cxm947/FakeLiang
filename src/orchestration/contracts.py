"""Small value types the walk and one step pass between each other."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class StepLimits:
    python: str
    timeout: float
    max_steps: int
    model_timeout: float


@dataclass(frozen=True)
class CredentialInputs:
    source: dict | None
    run_dirs: list[Path]
    materials_dir: Path | None
    role_accounts: dict


@dataclass
class DeliveryState:
    """本步交付资源；允许准备过程中留下部分完成的资源信息。"""

    plan: dict | None = None
    built_declaration: dict | None = None
    relay_facts: dict | None = None


@dataclass(frozen=True)
class ReasonEvent:
    stage: str
    reason: str
    detail: str = ""


@dataclass(frozen=True)
class StepResult:
    node_id: str
    row: dict
    binding_selection: dict
    reason_trace: tuple[ReasonEvent, ...]


@dataclass
class WalkResult:
    """整轮输出，不传给 run_step。"""

    state: dict = field(default_factory=dict)
    order: list[str] = field(default_factory=list)
    planner_notes: list[dict] = field(default_factory=list)
    planner_trace: list[dict] = field(default_factory=list)
    planner_error: dict | None = None
