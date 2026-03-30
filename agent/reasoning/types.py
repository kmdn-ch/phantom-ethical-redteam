"""Core data types for the reasoning engine.

These will migrate to ``agent.models.plans`` once that module is created.
For now they live here so the reasoning package is self-contained.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class PlanStatus(Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ABANDONED = "abandoned"
    BLOCKED = "blocked"


class HypothesisConfidence(Enum):
    SPECULATIVE = "speculative"
    PROBABLE = "probable"
    CONFIRMED = "confirmed"
    DISPROVED = "disproved"


@dataclass
class Hypothesis:
    id: str = field(default_factory=lambda: f"h_{uuid.uuid4().hex[:8]}")
    statement: str = ""
    confidence: HypothesisConfidence = HypothesisConfidence.SPECULATIVE
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    created_turn: int = 0
    last_updated_turn: int = 0


@dataclass
class AttackAction:
    """A single step in an attack plan."""

    id: str = field(default_factory=lambda: f"a_{uuid.uuid4().hex[:8]}")
    description: str = ""
    tool_name: Optional[str] = None
    tool_args: dict = field(default_factory=dict)
    script_code: Optional[str] = None
    depends_on: list[str] = field(default_factory=list)
    status: str = "pending"  # pending | running | done | failed | skipped
    result_summary: str = ""
    priority: float = 0.0


@dataclass
class AttackPlan:
    id: str = field(default_factory=lambda: f"p_{uuid.uuid4().hex[:8]}")
    objective: str = ""
    hypothesis: Optional[str] = None  # hypothesis ID this plan tests
    actions: list[AttackAction] = field(default_factory=list)
    status: PlanStatus = PlanStatus.ACTIVE
    priority: float = 0.0
    created_turn: int = 0
    abandoned_reason: str = ""


@dataclass
class AttackState:
    """The full cognitive state of the agent."""

    plans: list[AttackPlan] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    current_plan_id: Optional[str] = None
    turn: int = 0
    target_model: dict = field(default_factory=dict)

    def active_plans(self) -> list[AttackPlan]:
        return [p for p in self.plans if p.status == PlanStatus.ACTIVE]

    def get_plan(self, plan_id: str) -> Optional[AttackPlan]:
        return next((p for p in self.plans if p.id == plan_id), None)

    def get_hypothesis(self, hyp_id: str) -> Optional[Hypothesis]:
        return next((h for h in self.hypotheses if h.id == hyp_id), None)

    def next_action(self) -> Optional[tuple[AttackPlan, AttackAction]]:
        """Return the highest-priority pending action across all active plans."""
        best: Optional[tuple[AttackPlan, AttackAction]] = None
        for plan in sorted(self.active_plans(), key=lambda p: -p.priority):
            for action in plan.actions:
                if action.status != "pending":
                    continue
                deps_met = all(
                    any(
                        a.id == dep and a.status == "done"
                        for p2 in self.plans
                        for a in p2.actions
                    )
                    for dep in action.depends_on
                )
                if deps_met and (best is None or action.priority > best[1].priority):
                    best = (plan, action)
        return best
