"""Phantom v3 Reasoning Engine.

The brain of Phantom -- planning, reflection, strategy, and context management.

This package contains pure reasoning logic with no dependencies on agent.tools
or agent.providers.  LLM access is injected as a callable ``llm_call(messages) -> str``
so that every component remains testable and provider-agnostic.

Data-type definitions (AttackState, AttackPlan, Hypothesis, ...) live in
``agent.reasoning.types`` until the ``agent.models.plans`` module is created,
at which point they should migrate there.
"""

from agent.reasoning.types import (
    AttackAction,
    AttackPlan,
    AttackState,
    Hypothesis,
    HypothesisConfidence,
    PlanStatus,
)
from agent.reasoning.planner import PlanningLayer
from agent.reasoning.reflector import ReflectionLayer
from agent.reasoning.strategist import Strategist
from agent.reasoning.context_manager import ContextManager

__all__ = [
    # Data types
    "AttackAction",
    "AttackPlan",
    "AttackState",
    "Hypothesis",
    "HypothesisConfidence",
    "PlanStatus",
    # Reasoning layers
    "PlanningLayer",
    "ReflectionLayer",
    "Strategist",
    "ContextManager",
]
