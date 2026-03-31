"""Tests for agent.reasoning.context_manager — ContextManager prompt building."""

import pytest

from agent.reasoning.context_manager import ContextManager, PROVIDER_LIMITS
from agent.reasoning.types import AttackState, Hypothesis, HypothesisConfidence


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_default_ollama_small_context():
    cm = ContextManager("template", provider_name="ollama")
    assert cm.is_small_context is True
    assert cm._max_tokens == PROVIDER_LIMITS["ollama"]


def test_anthropic_large_context():
    cm = ContextManager("template", provider_name="anthropic")
    assert cm.is_small_context is False
    assert cm._max_tokens == 200_000


def test_custom_max_tokens():
    cm = ContextManager("template", provider_name="ollama", max_tokens=32_000)
    assert cm._max_tokens == 32_000
    assert cm.is_small_context is False


def test_set_provider_limits():
    cm = ContextManager("template")
    cm.set_provider_limits("openai", 128_000)
    assert cm._provider == "openai"
    assert cm._max_tokens == 128_000


# ---------------------------------------------------------------------------
# build_prompt
# ---------------------------------------------------------------------------


def test_build_prompt_structure():
    template = (
        "System: {tool_list}\n"
        "State: {state_summary}\n"
        "Graph: {graph_summary}\n"
        "Hypotheses: {hypotheses}\n"
        "Plan: {last_plan}"
    )
    cm = ContextManager(template, provider_name="anthropic")
    state = AttackState(turn=3)

    messages = cm.build_prompt(
        mission_memory=None,
        attack_state=state,
        attack_graph=None,
        recent_messages=[{"role": "user", "content": "Hello"}],
        tool_list="nmap, ffuf",
    )

    # Should have system message + user message
    assert messages[0]["role"] == "system"
    assert "nmap, ffuf" in messages[0]["content"]
    assert "Turn: 3" in messages[0]["content"]

    # Recent messages should be included
    assert any(m["content"] == "Hello" for m in messages)


def test_build_prompt_with_tool_results():
    cm = ContextManager(
        "{tool_list}{state_summary}{graph_summary}{hypotheses}{last_plan}"
    )
    state = AttackState(turn=1)

    results = [{"tool": "nmap", "output": "80/tcp open http"}]
    messages = cm.build_prompt(
        mission_memory=None,
        attack_state=state,
        attack_graph=None,
        recent_messages=[],
        tool_results=results,
    )

    # Last message should contain tool results
    assert any("nmap" in m.get("content", "") for m in messages)


def test_build_prompt_no_tool_results():
    cm = ContextManager(
        "{tool_list}{state_summary}{graph_summary}{hypotheses}{last_plan}"
    )
    state = AttackState(turn=1)

    messages = cm.build_prompt(
        mission_memory=None,
        attack_state=state,
        attack_graph=None,
        recent_messages=[],
        tool_results=None,
    )
    # Only system message
    assert len(messages) == 1


# ---------------------------------------------------------------------------
# Hypotheses rendering
# ---------------------------------------------------------------------------


def test_hypotheses_rendering():
    cm = ContextManager(
        "{tool_list}{state_summary}{graph_summary}{hypotheses}{last_plan}"
    )
    state = AttackState(
        turn=5,
        hypotheses=[
            Hypothesis(
                id="h1",
                statement="Outdated Apache",
                confidence=HypothesisConfidence.PROBABLE,
            ),
            Hypothesis(
                id="h2",
                statement="Disproved",
                confidence=HypothesisConfidence.DISPROVED,
            ),
            Hypothesis(
                id="h3",
                statement="Confirmed",
                confidence=HypothesisConfidence.CONFIRMED,
            ),
        ],
    )

    messages = cm.build_prompt(
        mission_memory=None,
        attack_state=state,
        attack_graph=None,
        recent_messages=[],
    )
    system = messages[0]["content"]
    # Only non-disproved/non-confirmed hypotheses should appear
    assert "h1" in system
    assert "Outdated Apache" in system


def test_no_hypotheses():
    cm = ContextManager("{hypotheses}")
    state = AttackState(turn=1)
    messages = cm.build_prompt(
        mission_memory=None, attack_state=state, attack_graph=None, recent_messages=[]
    )
    assert "No active hypotheses" in messages[0]["content"]


# ---------------------------------------------------------------------------
# _truncate
# ---------------------------------------------------------------------------


def test_truncate_short():
    assert ContextManager._truncate("hello", 100) == "hello"


def test_truncate_long():
    text = "x" * 200
    result = ContextManager._truncate(text, 50)
    assert len(result) <= 50
    assert "truncated" in result


# ---------------------------------------------------------------------------
# Conversation trimming
# ---------------------------------------------------------------------------


def test_trim_conversation_budget():
    cm = ContextManager("template", provider_name="ollama")
    msgs = [
        {"role": "user", "content": "A" * 1000},
        {"role": "assistant", "content": "B" * 1000},
        {"role": "user", "content": "C" * 100},
    ]
    # With a small budget, only the most recent messages should fit
    trimmed = cm._trim_conversation(msgs, 500)
    assert len(trimmed) <= len(msgs)
    # Most recent should always be included
    assert trimmed[-1]["content"] == "C" * 100


def test_trim_conversation_empty():
    cm = ContextManager("template")
    assert cm._trim_conversation([], 1000) == []


# ---------------------------------------------------------------------------
# Small context compression
# ---------------------------------------------------------------------------


def test_small_context_compresses_tool_results():
    cm = ContextManager("template", provider_name="ollama")
    msgs = [
        {"role": "tool", "content": "x" * 2000},
        {"role": "user", "content": "short"},
    ]
    compressed = cm._compress_tool_results_in_messages(msgs)
    assert len(compressed[0]["content"]) < 2000
    assert "truncated" in compressed[0]["content"]
    assert compressed[1]["content"] == "short"


def test_large_context_no_compression():
    cm = ContextManager("template", provider_name="anthropic")
    msgs = [{"role": "tool", "content": "x" * 2000}]
    # _compress is only called for small context, but we test the method directly
    # For large context, trim_conversation should NOT call compress
    trimmed = cm._trim_conversation(msgs, 100_000)
    assert len(trimmed[0]["content"]) == 2000


# ---------------------------------------------------------------------------
# Graph summary
# ---------------------------------------------------------------------------


def test_graph_summary_none():
    cm = ContextManager("{graph_summary}")
    state = AttackState(turn=1)
    messages = cm.build_prompt(
        mission_memory=None, attack_state=state, attack_graph=None, recent_messages=[]
    )
    assert "No attack graph" in messages[0]["content"]
