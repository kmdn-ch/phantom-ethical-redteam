"""Tests for agent.reasoning.reflector — ReflectionLayer parsing and stall detection."""

import pytest

from agent.models.events import EventBus, EventType
from agent.reasoning.reflector import ReflectionLayer
from agent.reasoning.types import AttackPlan, AttackState, PlanStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_reflector(**kwargs):
    defaults = {"mission_id": "m-test", "reflect_every": 3, "stall_threshold": 4}
    defaults.update(kwargs)
    return ReflectionLayer(**defaults)


# ---------------------------------------------------------------------------
# parse_reflection
# ---------------------------------------------------------------------------


def test_parse_reflection_valid():
    r = _make_reflector()
    text = """\
Some preamble text.

<reflection>
progress: Making good progress on SQL injection vector
approach_effective: yes
blind_spots: SSTI, deserialization
decision: continue
next_priority: Test SSTI on /api endpoint
custom_tool_needed: no
</reflection>

More text after.
"""
    result = r.parse_reflection(text)
    assert result is not None
    assert result["progress"] == "Making good progress on SQL injection vector"
    assert result["approach_effective"] == "yes"
    assert result["decision"] == "continue"
    assert "SSTI" in result["blind_spots"]


def test_parse_reflection_no_block():
    r = _make_reflector()
    result = r.parse_reflection("Just plain text, no reflection block.")
    assert result is None


def test_parse_reflection_empty_block():
    r = _make_reflector()
    result = r.parse_reflection("<reflection>\n</reflection>")
    assert result is not None
    assert result == {}


def test_parse_reflection_colon_in_value():
    r = _make_reflector()
    text = (
        "<reflection>\nprogress: Target at http://10.0.0.1:8080 scanned\n</reflection>"
    )
    result = r.parse_reflection(text)
    assert result is not None
    assert "http://10.0.0.1:8080" in result["progress"]


# ---------------------------------------------------------------------------
# should_reflect
# ---------------------------------------------------------------------------


def test_should_reflect_periodic():
    r = _make_reflector(reflect_every=3)
    r._last_reflect_turn = 0
    state = AttackState(turn=3)
    assert r.should_reflect(state) is True


def test_should_reflect_not_yet():
    r = _make_reflector(reflect_every=3)
    r._last_reflect_turn = 0
    state = AttackState(turn=2)
    assert r.should_reflect(state) is False


def test_should_reflect_critical_finding():
    r = _make_reflector(reflect_every=100)  # high interval
    r._last_reflect_turn = 0
    state = AttackState(
        turn=1,
        findings=[{"severity": "CRITICAL", "title": "RCE"}],
    )
    assert r.should_reflect(state) is True


def test_should_reflect_abandoned_plan():
    r = _make_reflector(reflect_every=100)
    r._last_reflect_turn = 0
    plan = AttackPlan(status=PlanStatus.ABANDONED, created_turn=1)
    state = AttackState(turn=2, plans=[plan])
    assert r.should_reflect(state) is True


def test_should_reflect_multiple_failures():
    r = _make_reflector(reflect_every=100)
    r._last_reflect_turn = 0
    from agent.reasoning.types import AttackAction

    a1 = AttackAction(status="failed")
    a2 = AttackAction(status="failed")
    plan = AttackPlan(status=PlanStatus.ACTIVE, actions=[a1, a2])
    state = AttackState(turn=1, plans=[plan])
    assert r.should_reflect(state) is True


# ---------------------------------------------------------------------------
# Stall detection
# ---------------------------------------------------------------------------


def test_stall_detection_triggers():
    r = _make_reflector(stall_threshold=3, reflect_every=100)
    state = AttackState(turn=0, findings=[])

    # Simulate 3 consecutive dry turns
    for turn in range(3):
        state.turn = turn
        r._update_stall_counter(state)

    assert r._consecutive_dry_turns >= 3
    state.turn = 3
    assert r.should_reflect(state) is True


def test_stall_resets_on_new_finding():
    r = _make_reflector(stall_threshold=4)
    state = AttackState(turn=0, findings=[])

    # 2 dry turns
    for turn in range(2):
        state.turn = turn
        r._update_stall_counter(state)

    assert r._consecutive_dry_turns == 2

    # New finding at turn 2
    state.turn = 2
    state.findings.append({"severity": "HIGH", "title": "Found something"})
    r._update_stall_counter(state)

    assert r._consecutive_dry_turns == 0


# ---------------------------------------------------------------------------
# apply_reflection
# ---------------------------------------------------------------------------


def test_apply_reflection_pivot():
    r = _make_reflector()
    state = AttackState()
    plan = AttackPlan(status=PlanStatus.ACTIVE, priority=0.8)
    state.plans.append(plan)

    reflection = {"decision": "pivot"}
    actions = r.apply_reflection(reflection, state)

    assert "Deprioritized" in actions[0]
    assert plan.priority < 0.8


def test_apply_reflection_continue():
    r = _make_reflector()
    state = AttackState()
    reflection = {"decision": "continue"}
    actions = r.apply_reflection(reflection, state)
    assert actions == []


def test_apply_reflection_escalate():
    r = _make_reflector()
    state = AttackState()
    reflection = {"decision": "escalate"}
    actions = r.apply_reflection(reflection, state)
    assert any("escalation" in a for a in actions)


# ---------------------------------------------------------------------------
# Rule-based reflection (no LLM)
# ---------------------------------------------------------------------------


def test_rule_based_on_stall():
    r = _make_reflector(stall_threshold=2, llm_call=None)
    state = AttackState(turn=0, findings=[])

    # Simulate stall
    for turn in range(3):
        state.turn = turn
        r._update_stall_counter(state)

    result = r._rule_based_reflection(state, event_bus=None)
    assert result is not None
    assert result["decision"] == "pivot"


def test_rule_based_no_stall():
    r = _make_reflector(stall_threshold=10, llm_call=None)
    state = AttackState(turn=1, findings=[{"title": "x"}])
    r._consecutive_dry_turns = 0

    result = r._rule_based_reflection(state, event_bus=None)
    assert result is None


# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------


def test_reflect_emits_events():
    bus = EventBus()
    emitted = []
    bus.subscribe_all(lambda e: emitted.append(e))

    r = _make_reflector(stall_threshold=2, llm_call=None, reflect_every=1)
    state = AttackState(turn=0, findings=[])

    # Force enough turns to exceed stall threshold (need stall_threshold + 1 dry turns)
    for turn in range(5):
        state.turn = turn
        r.reflect([], state, event_bus=bus)

    # Should have emitted DECISION events (rule-based reflection triggers on stall)
    event_types = {e.event_type for e in emitted}
    assert EventType.DECISION in event_types
    # STALL_DETECTED should fire once consecutive dry turns >= threshold
    assert EventType.STALL_DETECTED in event_types or EventType.PIVOT in event_types
