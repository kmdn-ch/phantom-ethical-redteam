"""Context manager -- builds token-budget-aware prompts for the LLM.

Assembles the full prompt from structured state (mission memory, attack state,
attack graph, recent conversation) instead of dumping raw tool output into the
conversation history.

For Ollama / small-context models: aggressive summarization.
For cloud providers with large windows: include more raw detail.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from agent.reasoning.types import AttackState

logger = logging.getLogger(__name__)

# Approximate tokens-per-character ratio (conservative estimate)
_CHARS_PER_TOKEN = 3.5

# Default token budgets per prompt section
_DEFAULT_BUDGETS = {
    "system_prompt": 0.10,    # 10% for the system prompt
    "state_summary": 0.20,    # 20% for mission memory + attack state
    "graph_summary": 0.10,    # 10% for attack graph
    "hypotheses": 0.10,       # 10% for hypotheses
    "last_plan": 0.10,        # 10% for current plan
    "conversation": 0.30,     # 30% for recent conversation turns
    "tool_results": 0.10,     # 10% for latest tool results
}

# Provider context window sizes (tokens)
PROVIDER_LIMITS: dict[str, int] = {
    "anthropic": 200_000,
    "openai": 128_000,
    "grok": 128_000,
    "gemini": 128_000,
    "mistral": 128_000,
    "deepseek": 64_000,
    "ollama": 8_000,  # Conservative default for local models
}


class ContextManager:
    """Builds token-budget-aware prompts for the reasoning loop."""

    def __init__(
        self,
        system_prompt_template: str,
        provider_name: str = "ollama",
        max_tokens: Optional[int] = None,
    ):
        self._template = system_prompt_template
        self._provider = provider_name
        self._max_tokens = max_tokens or PROVIDER_LIMITS.get(provider_name, 8_000)
        self._budgets = dict(_DEFAULT_BUDGETS)

    def set_provider_limits(self, provider_name: str, max_tokens: int) -> None:
        self._provider = provider_name
        self._max_tokens = max_tokens

    @property
    def is_small_context(self) -> bool:
        return self._max_tokens <= 16_000

    def build_prompt(
        self,
        mission_memory: Any,
        attack_state: AttackState,
        attack_graph: Any,
        recent_messages: list[dict[str, str]],
        tool_results: Optional[list[dict[str, str]]] = None,
        tool_list: str = "",
    ) -> list[dict[str, str]]:
        """Assemble the full message list for one LLM turn.

        Returns a list of message dicts ready to send to any provider.
        """
        budget = self._compute_budgets()

        # 1. System prompt with dynamic placeholders
        state_summary = self._build_state_summary(mission_memory, attack_state, budget["state_summary"])
        graph_summary = self._build_graph_summary(attack_graph, budget["graph_summary"])
        hypotheses = self._build_hypotheses(attack_state, budget["hypotheses"])
        last_plan = self._build_plan_summary(attack_state, budget["last_plan"])

        system_content = self._template.replace("{tool_list}", tool_list)
        system_content = system_content.replace("{state_summary}", state_summary)
        system_content = system_content.replace("{graph_summary}", graph_summary)
        system_content = system_content.replace("{hypotheses}", hypotheses)
        system_content = system_content.replace("{last_plan}", last_plan)

        messages: list[dict[str, str]] = [
            {"role": "system", "content": system_content},
        ]

        # 2. Recent conversation (trimmed to budget)
        trimmed = self._trim_conversation(recent_messages, budget["conversation"])
        messages.extend(trimmed)

        # 3. Latest tool results (if any)
        if tool_results:
            results_text = self._format_tool_results(tool_results, budget["tool_results"])
            messages.append({"role": "user", "content": results_text})

        return messages

    def _compute_budgets(self) -> dict[str, int]:
        """Convert percentage budgets to character counts."""
        total_chars = int(self._max_tokens * _CHARS_PER_TOKEN)
        return {
            section: int(total_chars * pct)
            for section, pct in self._budgets.items()
        }

    def _build_state_summary(
        self, memory: Any, state: AttackState, char_budget: int
    ) -> str:
        lines: list[str] = []
        lines.append(f"Turn: {state.turn}")

        # Target model
        if state.target_model:
            targets = ", ".join(
                f"{k}: {v}" if isinstance(v, str) else f"{k}: {len(v)} items"
                for k, v in list(state.target_model.items())[:5]
            )
            lines.append(f"Targets: {targets}")

        # Mission memory summary
        if memory is not None:
            try:
                mem_budget = char_budget // 2
                mem_summary = memory.summary_for_context(mem_budget)
                lines.append(mem_summary)
            except Exception:
                lines.append(f"Findings: {len(getattr(memory, 'findings', {}))}")

        # Findings count by severity
        if state.findings:
            sev_counts: dict[str, int] = {}
            for f in state.findings:
                s = f.get("severity", "info")
                sev_counts[s] = sev_counts.get(s, 0) + 1
            sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(sev_counts.items()))
            lines.append(f"Finding counts: {sev_str}")

        summary = "\n".join(lines)
        return self._truncate(summary, char_budget)

    def _build_graph_summary(self, graph: Any, char_budget: int) -> str:
        if graph is None:
            return "No attack graph yet."

        try:
            nodes = getattr(graph, "nodes", {})
            edges = getattr(graph, "edges", [])

            if not nodes:
                return "No attack graph yet."

            lines = [f"Graph: {len(nodes)} nodes, {len(edges)} edges"]

            # Show chains if available and context allows
            if not self.is_small_context:
                try:
                    chains = graph.get_chains()
                    if chains:
                        lines.append(f"Attack chains found: {len(chains)}")
                        for chain in chains[:3]:
                            path_labels = []
                            for node_id in chain:
                                node = nodes.get(node_id)
                                if node:
                                    path_labels.append(getattr(node, "label", node_id))
                            lines.append(f"  Chain: {' -> '.join(path_labels)}")
                except Exception:
                    pass

            return self._truncate("\n".join(lines), char_budget)
        except Exception:
            return "Attack graph unavailable."

    def _build_hypotheses(self, state: AttackState, char_budget: int) -> str:
        active = [
            h for h in state.hypotheses
            if h.confidence.value not in ("disproved", "confirmed")
        ]
        if not active:
            return "No active hypotheses."

        lines = []
        for h in active[:10]:  # Cap at 10
            lines.append(f"[{h.id}] {h.confidence.value}: {h.statement}")
            if h.evidence_for:
                lines.append(f"  Evidence for: {', '.join(h.evidence_for[:3])}")

        return self._truncate("\n".join(lines), char_budget)

    def _build_plan_summary(self, state: AttackState, char_budget: int) -> str:
        active_plans = state.active_plans()
        if not active_plans:
            return "No active plan. Decide what to do next."

        lines = []
        for plan in active_plans[:3]:
            pending = [a for a in plan.actions if a.status == "pending"]
            done = [a for a in plan.actions if a.status == "done"]
            failed = [a for a in plan.actions if a.status == "failed"]
            lines.append(
                f"Plan [{plan.id}] pri={plan.priority:.1f}: {plan.objective} "
                f"({len(done)} done, {len(pending)} pending, {len(failed)} failed)"
            )
            for a in pending[:3]:
                lines.append(f"  -> {a.description or a.tool_name or 'dynamic script'}")

        return self._truncate("\n".join(lines), char_budget)

    def _trim_conversation(
        self, messages: list[dict[str, str]], char_budget: int
    ) -> list[dict[str, str]]:
        """Keep the most recent messages that fit within budget."""
        if not messages:
            return []

        result: list[dict[str, str]] = []
        chars_used = 0

        for msg in reversed(messages):
            content = msg.get("content", "")
            msg_chars = len(content)

            if chars_used + msg_chars > char_budget and result:
                break

            result.insert(0, msg)
            chars_used += msg_chars

        # For small contexts, summarize old tool results
        if self.is_small_context:
            result = self._compress_tool_results_in_messages(result)

        return result

    def _compress_tool_results_in_messages(
        self, messages: list[dict[str, str]]
    ) -> list[dict[str, str]]:
        """For small-context providers, truncate long tool result messages."""
        max_result_chars = 500
        compressed = []
        for msg in messages:
            content = msg.get("content", "")
            role = msg.get("role", "")
            if role == "tool" and len(content) > max_result_chars:
                truncated = content[:max_result_chars] + "\n... [truncated for context budget]"
                compressed.append({**msg, "content": truncated})
            else:
                compressed.append(msg)
        return compressed

    def _format_tool_results(
        self, results: list[dict[str, str]], char_budget: int
    ) -> str:
        lines = ["[TOOL RESULTS]"]
        chars = 15
        for r in results:
            tool = r.get("tool", "unknown")
            output = r.get("output", "")
            header = f"\n--- {tool} ---\n"
            if chars + len(header) + len(output) > char_budget:
                # Truncate this result
                remaining = max(0, char_budget - chars - len(header) - 30)
                output = output[:remaining] + "\n... [truncated]"
            lines.append(header + output)
            chars += len(header) + len(output)
            if chars >= char_budget:
                break
        return "\n".join(lines)

    @staticmethod
    def _truncate(text: str, max_chars: int) -> str:
        if len(text) <= max_chars:
            return text
        return text[:max_chars - 20] + "\n... [truncated]"

    @classmethod
    def from_file(
        cls,
        prompt_path: str | Path,
        provider_name: str = "ollama",
        max_tokens: Optional[int] = None,
    ) -> ContextManager:
        """Load system prompt template from file."""
        template = Path(prompt_path).read_text(encoding="utf-8")
        return cls(template, provider_name, max_tokens)
