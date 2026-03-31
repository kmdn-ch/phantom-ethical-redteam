"""Reflection / metacognition layer.

After observing tool results the reflector asks: "What did I learn?
Should I pivot?"  It produces structured observations that update
mission memory and emits DECISION / PIVOT events via the EventBus.

Stall detection is built in: if N consecutive turns produce no new
findings the reflector triggers a pivot recommendation.

This module has **no** dependency on ``agent.tools`` or ``agent.providers``.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Optional

from agent.models.events import Event, EventBus, EventType, Severity
from agent.reasoning.types import AttackState, PlanStatus

logger = logging.getLogger(__name__)

LLMCall = Callable[[list[dict]], str]

# Default: if this many consecutive turns yield no new findings, trigger stall.
_DEFAULT_STALL_THRESHOLD = 4


class ReflectionLayer:
    """Metacognitive evaluation of agent performance and approach effectiveness.

    Parameters
    ----------
    llm_call:
        Provider-agnostic LLM callable ``(messages) -> str``.
    reflect_every:
        Periodic reflection interval (in turns).
    stall_threshold:
        Number of consecutive no-new-finding turns before a stall is declared.
    mission_id:
        Identifier for the current mission (used when emitting events).
    """

    def __init__(
        self,
        llm_call: Optional[LLMCall] = None,
        reflect_every: int = 3,
        stall_threshold: int = _DEFAULT_STALL_THRESHOLD,
        mission_id: str = "",
    ) -> None:
        self.llm_call = llm_call
        self.reflect_every = reflect_every
        self.stall_threshold = stall_threshold
        self.mission_id = mission_id

        self._last_reflect_turn: int = 0
        self._findings_at_turn: dict[int, int] = {}  # turn -> cumulative findings count
        self._consecutive_dry_turns: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reflect(
        self,
        tool_results: list[dict[str, Any]],
        attack_state: AttackState,
        event_bus: Optional[EventBus] = None,
    ) -> Optional[dict[str, str]]:
        """Run a full reflection cycle.

        1. Check whether reflection is warranted this turn.
        2. Build a reflection prompt incorporating tool results and state.
        3. Call the LLM to reason about progress.
        4. Parse the structured ``<reflection>`` block.
        5. Apply decisions (pivot / deprioritize / escalate).
        6. Update stall detection counters.
        7. Emit events if the approach changes.

        Returns the parsed reflection dict, or ``None`` if reflection was
        skipped or the LLM did not produce a valid block.
        """
        # Track stall detection regardless of whether we reflect
        self._update_stall_counter(attack_state)

        if not self.should_reflect(attack_state):
            return None

        state_summary = self._build_state_summary(attack_state)
        prompt = self.build_reflection_prompt(tool_results, state_summary)

        # If no LLM callable, we can only do rule-based stall detection
        if self.llm_call is None:
            return self._rule_based_reflection(attack_state, event_bus)

        messages: list[dict] = [
            {
                "role": "system",
                "content": (
                    "You are Phantom's metacognition layer.  Evaluate the "
                    "agent's progress and output a <reflection> block."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        llm_text = self.llm_call(messages)
        reflection = self.parse_reflection(llm_text)

        if reflection is None:
            logger.warning("LLM did not produce a valid <reflection> block")
            return None

        actions = self.apply_reflection(reflection, attack_state)

        # Emit events
        if event_bus is not None:
            self._emit_reflection_events(reflection, actions, attack_state, event_bus)

        self._last_reflect_turn = attack_state.turn
        return reflection

    # ------------------------------------------------------------------
    # Reflection triggers
    # ------------------------------------------------------------------

    def should_reflect(self, state: AttackState) -> bool:
        """Determine if reflection is needed this turn."""
        turns_since = state.turn - self._last_reflect_turn

        # Periodic
        if turns_since >= self.reflect_every:
            return True

        # After a critical / high finding
        if state.findings and state.findings[-1].get("severity") in (
            "CRITICAL",
            "HIGH",
        ):
            return True

        # After a plan was recently abandoned
        if any(
            p.status == PlanStatus.ABANDONED
            and p.created_turn > self._last_reflect_turn
            for p in state.plans
        ):
            return True

        # Consecutive action failures (2+)
        recent_failures = 0
        for plan in state.active_plans():
            for a in plan.actions:
                if a.status == "failed":
                    recent_failures += 1
        if recent_failures >= 2:
            return True

        # Stall detected
        if self._consecutive_dry_turns >= self.stall_threshold:
            return True

        return False

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def build_reflection_prompt(
        self,
        tool_results: list[dict[str, Any]],
        state_summary: str,
    ) -> str:
        """Construct the metacognitive reflection query.

        Includes recent tool results and a compact state summary so the
        LLM has full context for its self-evaluation.
        """
        # Format tool results compactly
        results_block = self._format_tool_results(tool_results)

        stall_note = ""
        if self._consecutive_dry_turns >= self.stall_threshold:
            stall_note = (
                f"\nWARNING: {self._consecutive_dry_turns} consecutive turns with "
                "no new findings.  Strongly consider pivoting.\n"
            )

        return f"""\
[REFLECTION REQUIRED]
Before choosing your next action, evaluate your approach.
{stall_note}
STATE SUMMARY:
{state_summary}

RECENT TOOL RESULTS:
{results_block}

Answer these questions in a <reflection> block:
1. PROGRESS: Am I making meaningful progress toward compromising the target?
2. APPROACH: Is my current strategy the most efficient? What am I missing?
3. DIMINISHING RETURNS: Am I repeating similar actions without new results?
4. BLIND SPOTS: What attack vectors have I NOT tried? (SSRF, SSTI, deserialization, race conditions, business logic, etc.)
5. PIVOT DECISION: Should I continue current plan, modify it, or pivot entirely?
6. TOOL GAP: Do I need a custom script that my built-in tools cannot provide?

Output format:
<reflection>
progress: [1-2 sentences]
approach_effective: [yes/no/partial]
blind_spots: [comma-separated list of untested vectors]
decision: [continue|modify|pivot|escalate]
next_priority: [what to do next and why]
custom_tool_needed: [yes/no -- if yes, describe what it should do]
</reflection>
"""

    # ------------------------------------------------------------------
    # Reflection parsing
    # ------------------------------------------------------------------

    _RE_REFLECTION = re.compile(r"<reflection>(.*?)</reflection>", re.DOTALL)

    def parse_reflection(self, llm_text: str) -> Optional[dict[str, str]]:
        """Extract and parse the ``<reflection>`` block from LLM output.

        Returns a dict of key-value pairs, or ``None`` if no block found.
        """
        match = self._RE_REFLECTION.search(llm_text)
        if not match:
            return None

        block = match.group(1)
        reflection: dict[str, str] = {}
        for line in block.strip().splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                reflection[key.strip()] = value.strip()
        return reflection

    # ------------------------------------------------------------------
    # Apply reflection decisions
    # ------------------------------------------------------------------

    def apply_reflection(
        self,
        reflection: dict[str, str],
        state: AttackState,
    ) -> list[str]:
        """Translate reflection decisions into concrete state changes.

        Returns a list of human-readable action descriptions for logging.
        """
        actions_taken: list[str] = []
        decision = reflection.get("decision", "continue")

        if decision == "pivot":
            for plan in state.active_plans():
                plan.priority = max(0.1, plan.priority - 0.3)
            actions_taken.append("Deprioritized all active plans for pivot")
            # Reset stall counter -- the pivot is the response
            self._consecutive_dry_turns = 0

        if decision == "escalate":
            actions_taken.append("Flagged for human input escalation")

        if decision == "modify":
            actions_taken.append(
                "Current approach will be modified based on reflection"
            )

        if reflection.get("approach_effective") == "no":
            actions_taken.append(
                "Approach marked ineffective -- plans will be reassessed"
            )

        return actions_taken

    # ------------------------------------------------------------------
    # Stall detection
    # ------------------------------------------------------------------

    def _update_stall_counter(self, state: AttackState) -> None:
        """Track consecutive turns with no new findings."""
        current_count = len(state.findings)
        prev_count = self._findings_at_turn.get(state.turn - 1, 0)

        if current_count <= prev_count:
            self._consecutive_dry_turns += 1
        else:
            self._consecutive_dry_turns = 0

        self._findings_at_turn[state.turn] = current_count

    # ------------------------------------------------------------------
    # Rule-based fallback (no LLM)
    # ------------------------------------------------------------------

    def _rule_based_reflection(
        self,
        state: AttackState,
        event_bus: Optional[EventBus],
    ) -> Optional[dict[str, str]]:
        """Minimal reflection when no LLM is available.

        Uses heuristics: stall detection, failure counting.
        """
        reflection: dict[str, str] = {}

        if self._consecutive_dry_turns >= self.stall_threshold:
            reflection["progress"] = (
                f"Stalled for {self._consecutive_dry_turns} turns with no new findings"
            )
            reflection["approach_effective"] = "no"
            reflection["decision"] = "pivot"
            reflection["next_priority"] = "Try unexplored attack vectors"
            reflection["blind_spots"] = "unknown"
            reflection["custom_tool_needed"] = "no"

            actions = self.apply_reflection(reflection, state)
            if event_bus is not None:
                self._emit_reflection_events(reflection, actions, state, event_bus)
            self._last_reflect_turn = state.turn
            return reflection

        return None

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    def _emit_reflection_events(
        self,
        reflection: dict[str, str],
        actions: list[str],
        state: AttackState,
        event_bus: EventBus,
    ) -> None:
        """Emit DECISION and/or PIVOT events via the EventBus."""
        decision = reflection.get("decision", "continue")

        # Always emit a DECISION event
        event_bus.emit(
            Event(
                mission_id=self.mission_id,
                turn=state.turn,
                event_type=EventType.DECISION,
                phase="reflection",
                reasoning=f"Reflection decision: {decision}. " + "; ".join(actions),
                metadata={"reflection": reflection},
            )
        )

        # Emit PIVOT when the approach changes
        if decision in ("pivot", "escalate"):
            event_bus.emit(
                Event(
                    mission_id=self.mission_id,
                    turn=state.turn,
                    event_type=EventType.PIVOT,
                    phase="reflection",
                    reasoning=reflection.get("next_priority", ""),
                    metadata={
                        "blind_spots": reflection.get("blind_spots", ""),
                        "custom_tool_needed": reflection.get(
                            "custom_tool_needed", "no"
                        ),
                    },
                )
            )

        # Emit STALL_DETECTED if applicable
        if self._consecutive_dry_turns >= self.stall_threshold:
            event_bus.emit(
                Event(
                    mission_id=self.mission_id,
                    turn=state.turn,
                    event_type=EventType.STALL_DETECTED,
                    phase="reflection",
                    reasoning=(
                        f"{self._consecutive_dry_turns} consecutive turns "
                        "with no new findings"
                    ),
                )
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_state_summary(self, state: AttackState) -> str:
        """Build a compact state summary for the reflection prompt."""
        active_plans = state.active_plans()
        completed = [p for p in state.plans if p.status == PlanStatus.COMPLETED]
        abandoned = [p for p in state.plans if p.status == PlanStatus.ABANDONED]

        total_actions = sum(len(p.actions) for p in state.plans)
        done_actions = sum(
            1 for p in state.plans for a in p.actions if a.status == "done"
        )
        failed_actions = sum(
            1 for p in state.plans for a in p.actions if a.status == "failed"
        )

        lines = [
            f"Turn {state.turn}",
            f"Plans: {len(active_plans)} active, {len(completed)} completed, "
            f"{len(abandoned)} abandoned",
            f"Actions: {done_actions}/{total_actions} done, {failed_actions} failed",
            f"Findings: {len(state.findings)} total",
        ]

        if state.findings:
            lines.append("Recent findings:")
            for f in state.findings[-3:]:
                lines.append(f"  [{f.get('severity', '?')}] {f.get('title', '')[:60]}")

        return "\n".join(lines)

    @staticmethod
    def _format_tool_results(tool_results: list[dict[str, Any]]) -> str:
        """Format tool results compactly for inclusion in the reflection prompt."""
        if not tool_results:
            return "(no recent tool results)"

        parts: list[str] = []
        for i, result in enumerate(tool_results[-5:], 1):
            tool = result.get("tool", result.get("tool_name", "unknown"))
            output = str(result.get("output", result.get("content", "")))
            # Truncate long outputs
            if len(output) > 500:
                output = output[:250] + "\n[...truncated...]\n" + output[-250:]
            parts.append(f"[{i}] {tool}:\n{output}")

        return "\n\n".join(parts)
