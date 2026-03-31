"""Tests for agent.models.plans — AttackAction, AttackPlan, AttackState."""

import pytest

from agent.models.plans import (
    ActionStatus,
    AttackAction,
    AttackPlan,
    AttackState,
    PlanStatus,
)


# ---------------------------------------------------------------------------
# AttackAction
# ---------------------------------------------------------------------------


def test_action_defaults():
    a = AttackAction()
    assert a.status == ActionStatus.PENDING
    assert a.priority == 0.0
    assert a.depends_on == []


def test_action_roundtrip():
    a = AttackAction(
        description="Run nmap scan",
        tool_name="nmap",
        tool_args={"target": "10.0.0.1"},
        priority=0.8,
        status=ActionStatus.DONE,
        result_summary="3 open ports",
    )
    d = a.to_dict()
    assert d["status"] == "done"

    restored = AttackAction.from_dict(d)
    assert restored.description == "Run nmap scan"
    assert restored.status == ActionStatus.DONE


# ---------------------------------------------------------------------------
# AttackPlan
# ---------------------------------------------------------------------------


def test_plan_defaults():
    p = AttackPlan()
    assert p.status == PlanStatus.ACTIVE
    assert p.actions == []


def test_plan_roundtrip():
    actions = [
        AttackAction(description="step 1", priority=0.9),
        AttackAction(description="step 2", priority=0.5),
    ]
    p = AttackPlan(
        objective="Enumerate web services",
        actions=actions,
        priority=0.7,
        status=PlanStatus.ACTIVE,
    )
    d = p.to_dict()
    assert d["status"] == "active"
    assert len(d["actions"]) == 2

    restored = AttackPlan.from_dict(d)
    assert restored.objective == "Enumerate web services"
    assert len(restored.actions) == 2
    assert restored.actions[0].priority == 0.9


# ---------------------------------------------------------------------------
# AttackState — next_action scheduling
# ---------------------------------------------------------------------------


def test_next_action_returns_highest_priority():
    a1 = AttackAction(id="a1", description="low", priority=0.2)
    a2 = AttackAction(id="a2", description="high", priority=0.9)
    plan = AttackPlan(objective="test", actions=[a1, a2], priority=1.0)
    state = AttackState(plans=[plan])

    result = state.next_action()
    assert result is not None
    _, action = result
    assert action.id == "a2"


def test_next_action_skips_done():
    a1 = AttackAction(id="a1", priority=0.9, status=ActionStatus.DONE)
    a2 = AttackAction(id="a2", priority=0.5, status=ActionStatus.PENDING)
    plan = AttackPlan(objective="test", actions=[a1, a2], priority=1.0)
    state = AttackState(plans=[plan])

    result = state.next_action()
    assert result is not None
    _, action = result
    assert action.id == "a2"


def test_next_action_respects_dependencies():
    a1 = AttackAction(id="a1", priority=0.5, status=ActionStatus.PENDING)
    a2 = AttackAction(
        id="a2", priority=0.9, depends_on=["a1"], status=ActionStatus.PENDING
    )
    plan = AttackPlan(objective="test", actions=[a1, a2], priority=1.0)
    state = AttackState(plans=[plan])

    result = state.next_action()
    assert result is not None
    _, action = result
    # a2 has higher priority but depends on a1 which is not done
    assert action.id == "a1"


def test_next_action_dependency_met():
    a1 = AttackAction(id="a1", priority=0.5, status=ActionStatus.DONE)
    a2 = AttackAction(
        id="a2", priority=0.9, depends_on=["a1"], status=ActionStatus.PENDING
    )
    plan = AttackPlan(objective="test", actions=[a1, a2], priority=1.0)
    state = AttackState(plans=[plan])

    result = state.next_action()
    assert result is not None
    _, action = result
    assert action.id == "a2"


def test_next_action_none_when_all_done():
    a1 = AttackAction(id="a1", status=ActionStatus.DONE)
    plan = AttackPlan(objective="test", actions=[a1], priority=1.0)
    state = AttackState(plans=[plan])

    assert state.next_action() is None


def test_next_action_ignores_abandoned_plans():
    a1 = AttackAction(id="a1", priority=0.9, status=ActionStatus.PENDING)
    plan = AttackPlan(
        objective="abandoned", actions=[a1], priority=1.0, status=PlanStatus.ABANDONED
    )
    state = AttackState(plans=[plan])

    assert state.next_action() is None


def test_next_action_cross_plan_priority():
    a1 = AttackAction(id="a1", priority=0.3, status=ActionStatus.PENDING)
    a2 = AttackAction(id="a2", priority=0.8, status=ActionStatus.PENDING)
    plan_lo = AttackPlan(objective="lo", actions=[a1], priority=0.5)
    plan_hi = AttackPlan(objective="hi", actions=[a2], priority=0.9)
    state = AttackState(plans=[plan_lo, plan_hi])

    result = state.next_action()
    assert result is not None
    _, action = result
    assert action.id == "a2"


# ---------------------------------------------------------------------------
# AttackState — helpers
# ---------------------------------------------------------------------------


def test_active_plans():
    p1 = AttackPlan(status=PlanStatus.ACTIVE)
    p2 = AttackPlan(status=PlanStatus.COMPLETED)
    p3 = AttackPlan(status=PlanStatus.ACTIVE)
    state = AttackState(plans=[p1, p2, p3])

    assert len(state.active_plans()) == 2


def test_get_plan():
    p = AttackPlan(id="plan-1", objective="test")
    state = AttackState(plans=[p])

    assert state.get_plan("plan-1") is p
    assert state.get_plan("nonexistent") is None


# ---------------------------------------------------------------------------
# AttackState — serialization
# ---------------------------------------------------------------------------


def test_attack_state_roundtrip():
    a1 = AttackAction(id="a1", description="scan", status=ActionStatus.DONE)
    a2 = AttackAction(id="a2", description="exploit", depends_on=["a1"])
    plan = AttackPlan(objective="test", actions=[a1, a2], priority=0.8)
    state = AttackState(plans=[plan], current_plan_id=plan.id, turn=5)

    d = state.to_dict()
    restored = AttackState.from_dict(d)

    assert restored.turn == 5
    assert restored.current_plan_id == plan.id
    assert len(restored.plans) == 1
    assert restored.plans[0].actions[0].status == ActionStatus.DONE
