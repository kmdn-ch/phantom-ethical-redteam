"""Attack planning models: plans, actions, and cognitive state."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

import uuid


class PlanStatus(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ABANDONED = "abandoned"
    BLOCKED = "blocked"


class ActionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AttackAction:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    description: str = ""
    tool_name: Optional[str] = None
    tool_args: dict = field(default_factory=dict)
    script_code: Optional[str] = None
    depends_on: list[str] = field(default_factory=list)
    status: ActionStatus = ActionStatus.PENDING
    result_summary: str = ""
    priority: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, ActionStatus) else self.status
        return d

    @classmethod
    def from_dict(cls, data: dict) -> AttackAction:
        data = dict(data)
        if isinstance(data.get("status"), str):
            data["status"] = ActionStatus(data["status"])
        return cls(**data)


@dataclass
class AttackPlan:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    objective: str = ""
    hypothesis: Optional[str] = None  # hypothesis ID this plan tests
    actions: list[AttackAction] = field(default_factory=list)
    status: PlanStatus = PlanStatus.ACTIVE
    priority: float = 0.0
    created_turn: int = 0
    abandoned_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "objective": self.objective,
            "hypothesis": self.hypothesis,
            "actions": [a.to_dict() for a in self.actions],
            "status": self.status.value,
            "priority": self.priority,
            "created_turn": self.created_turn,
            "abandoned_reason": self.abandoned_reason,
        }

    @classmethod
    def from_dict(cls, data: dict) -> AttackPlan:
        data = dict(data)
        if isinstance(data.get("status"), str):
            data["status"] = PlanStatus(data["status"])
        if data.get("actions"):
            data["actions"] = [AttackAction.from_dict(a) for a in data["actions"]]
        return cls(**data)


@dataclass
class AttackState:
    """Full cognitive state of the planning layer."""

    plans: list[AttackPlan] = field(default_factory=list)
    current_plan_id: Optional[str] = None
    turn: int = 0

    def active_plans(self) -> list[AttackPlan]:
        return [p for p in self.plans if p.status == PlanStatus.ACTIVE]

    def get_plan(self, plan_id: str) -> Optional[AttackPlan]:
        return next((p for p in self.plans if p.id == plan_id), None)

    def next_action(self) -> Optional[tuple[AttackPlan, AttackAction]]:
        """Return the highest-priority pending action across all active plans."""
        best: Optional[tuple[AttackPlan, AttackAction]] = None
        for plan in sorted(self.active_plans(), key=lambda p: -p.priority):
            for action in plan.actions:
                if action.status == ActionStatus.PENDING:
                    deps_met = all(
                        any(
                            a.id == dep and a.status == ActionStatus.DONE
                            for p2 in self.plans
                            for a in p2.actions
                        )
                        for dep in action.depends_on
                    )
                    if deps_met:
                        if best is None or action.priority > best[1].priority:
                            best = (plan, action)
        return best

    def to_dict(self) -> dict:
        return {
            "plans": [p.to_dict() for p in self.plans],
            "current_plan_id": self.current_plan_id,
            "turn": self.turn,
        }

    @classmethod
    def from_dict(cls, data: dict) -> AttackState:
        data = dict(data)
        if data.get("plans"):
            data["plans"] = [AttackPlan.from_dict(p) for p in data["plans"]]
        return cls(**data)
