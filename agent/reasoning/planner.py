"""Planning layer -- manages attack plans, hypotheses, and action prioritization.

The planner is the core of Phantom's tactical reasoning.  It maintains the full
``AttackState`` and parses structured plan commands (XML blocks) that the LLM
embeds in its text output.

This module has **no** dependency on ``agent.tools`` or ``agent.providers``.
LLM access is injected as a callable so the layer stays testable.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Callable, Optional

from agent.reasoning.types import (
    AttackAction,
    AttackPlan,
    AttackState,
    Hypothesis,
    HypothesisConfidence,
    PlanStatus,
)

logger = logging.getLogger(__name__)

# Type alias for the provider-agnostic LLM callable.
# Signature: takes a list of message dicts, returns the assistant text.
LLMCall = Callable[[list[dict]], str]


class PlanningLayer:
    """Manages attack plans, hypotheses, and action prioritization.

    Parameters
    ----------
    llm_call:
        Provider-agnostic function ``(messages) -> str``.  Used when the
        planner needs to ask the LLM a clarifying question (e.g. "given
        these findings, propose a plan").  Most plan parsing is done on
        the LLM's *existing* output, so ``llm_call`` is only invoked for
        explicit plan-generation requests.
    state:
        Optional pre-existing state to resume from (e.g. loaded session).
    """

    def __init__(
        self,
        llm_call: Optional[LLMCall] = None,
        state: Optional[AttackState] = None,
    ) -> None:
        self.llm_call = llm_call
        self.state: AttackState = state if state is not None else AttackState()

    # ------------------------------------------------------------------
    # Prompt injection
    # ------------------------------------------------------------------

    def inject_state_into_prompt(self, messages: list[dict]) -> list[dict]:
        """Add a compact state summary to the conversation context.

        The summary is injected as a user message immediately before the
        last message so the LLM has the freshest context window view of
        the current attack state.

        Returns a **new** list -- the original is not mutated.
        """
        summary = self._serialize_state_compact()
        if not summary.strip():
            return list(messages)

        state_msg: dict = {
            "role": "user",
            "content": f"[PHANTOM_STATE]\n{summary}\n[/PHANTOM_STATE]",
        }
        if len(messages) <= 1:
            return list(messages) + [state_msg]
        return list(messages[:-1]) + [state_msg] + [messages[-1]]

    # ------------------------------------------------------------------
    # Compact serialisation (token-efficient)
    # ------------------------------------------------------------------

    def _serialize_state_compact(self) -> str:
        """Produce a token-efficient summary of the current attack state.

        Only includes *actionable* information: active hypotheses, active
        plans with pending actions, recent findings, and the target model.
        Disproved hypotheses and completed plans are omitted to save tokens.
        """
        lines: list[str] = []
        lines.append(f"Turn: {self.state.turn}")

        # Active hypotheses (skip disproved to save tokens)
        active_hyps = [
            h
            for h in self.state.hypotheses
            if h.confidence != HypothesisConfidence.DISPROVED
        ]
        if active_hyps:
            lines.append("Hypotheses:")
            for h in active_hyps:
                lines.append(f"  [{h.id}] {h.confidence.value}: {h.statement}")

        # Active plans with pending actions
        for plan in self.state.active_plans():
            pending = [a for a in plan.actions if a.status == "pending"]
            done = [a for a in plan.actions if a.status == "done"]
            lines.append(
                f"Plan [{plan.id}] pri={plan.priority:.1f}: {plan.objective} "
                f"({len(done)} done, {len(pending)} pending)"
            )
            for a in pending[:3]:  # at most 3 pending actions shown
                lines.append(f"  -> {a.description or a.tool_name}")

        # Recent findings (last 5, with severity)
        if self.state.findings:
            lines.append(f"Findings: {len(self.state.findings)} total")
            for f in self.state.findings[-5:]:
                lines.append(
                    f"  [{f.get('severity', '?')}] {f.get('title', '')[:80]}"
                )

        # Target model (compact JSON)
        if self.state.target_model:
            lines.append(f"Target model: {_compact_json(self.state.target_model)}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Plan / hypothesis parsing from LLM text
    # ------------------------------------------------------------------

    def parse_plan_actions(self, llm_text: str) -> str:
        """Parse structured plan commands from LLM output.

        Recognises four XML block types:

        - ``<plan_create>``       -- creates a new plan with actions
        - ``<plan_update>``       -- updates action statuses / priority
        - ``<plan_abandon>``      -- marks a plan as abandoned
        - ``<hypothesis_update>`` -- changes hypothesis confidence

        State is mutated in-place.  Returns the *cleaned* text with all
        plan/hypothesis XML blocks removed.
        """
        self._parse_plan_create(llm_text)
        self._parse_plan_update(llm_text)
        self._parse_plan_abandon(llm_text)
        self._parse_hypothesis_update(llm_text)

        cleaned = self._strip_plan_blocks(llm_text)
        return cleaned

    # -- plan_create -------------------------------------------------------

    _RE_PLAN_CREATE = re.compile(
        r"<plan_create\s+(.*?)>(.*?)</plan_create>",
        re.DOTALL,
    )
    _RE_ACTION = re.compile(r"<action\s+(.*?)/>", re.DOTALL)

    def _parse_plan_create(self, text: str) -> None:
        for match in self._RE_PLAN_CREATE.finditer(text):
            attrs = _parse_attrs(match.group(1))
            actions_block = match.group(2)

            plan = AttackPlan(
                objective=attrs.get("objective", ""),
                priority=float(attrs.get("priority", "0.5")),
                hypothesis=attrs.get("hypothesis") or None,
                created_turn=self.state.turn,
            )

            prev_id: Optional[str] = None
            for action_match in self._RE_ACTION.finditer(actions_block):
                a_attrs = _parse_attrs(action_match.group(1))
                action = AttackAction(
                    description=a_attrs.get("description", ""),
                    tool_name=a_attrs.get("tool") or None,
                    tool_args=_safe_json(a_attrs.get("args", "{}")),
                    script_code=None,
                    priority=float(a_attrs.get("priority", "0.5")),
                )
                # Handle "depends_on" -- special value "prev" links to
                # the previous action in the block.
                dep = a_attrs.get("depends_on", "")
                if dep == "prev" and prev_id:
                    action.depends_on = [prev_id]
                elif dep:
                    action.depends_on = [d.strip() for d in dep.split(",") if d.strip()]

                plan.actions.append(action)
                prev_id = action.id

            self.state.plans.append(plan)
            logger.info(
                "Plan created [%s] %s (%d actions, pri=%.1f)",
                plan.id,
                plan.objective[:60],
                len(plan.actions),
                plan.priority,
            )

    # -- plan_update -------------------------------------------------------

    _RE_PLAN_UPDATE = re.compile(
        r"<plan_update\s+(.*?)>(.*?)</plan_update>",
        re.DOTALL,
    )
    _RE_ACTION_STATUS = re.compile(r"<action_status\s+(.*?)/>", re.DOTALL)
    _RE_REPRIORITIZE = re.compile(r"<reprioritize\s+(.*?)/>", re.DOTALL)

    def _parse_plan_update(self, text: str) -> None:
        for match in self._RE_PLAN_UPDATE.finditer(text):
            attrs = _parse_attrs(match.group(1))
            plan_id = attrs.get("id", "")
            body = match.group(2)

            plan = self.state.get_plan(plan_id)
            if plan is None:
                logger.warning("plan_update references unknown plan %s", plan_id)
                continue

            # Update action statuses
            for am in self._RE_ACTION_STATUS.finditer(body):
                aa = _parse_attrs(am.group(1))
                action_id = aa.get("id", "")
                for action in plan.actions:
                    if action.id == action_id:
                        action.status = aa.get("status", action.status)
                        action.result_summary = aa.get("summary", action.result_summary)
                        break

            # Reprioritize
            for rm in self._RE_REPRIORITIZE.finditer(body):
                ra = _parse_attrs(rm.group(1))
                if "priority" in ra:
                    plan.priority = float(ra["priority"])

            # Check if all actions are done -> mark plan completed
            if plan.actions and all(a.status == "done" for a in plan.actions):
                plan.status = PlanStatus.COMPLETED
                logger.info("Plan [%s] completed: %s", plan.id, plan.objective[:60])

    # -- plan_abandon ------------------------------------------------------

    _RE_PLAN_ABANDON = re.compile(
        r'<plan_abandon\s+id="([^"]+)"\s+reason="([^"]+)"\s*/?>',
    )

    def _parse_plan_abandon(self, text: str) -> None:
        for match in self._RE_PLAN_ABANDON.finditer(text):
            plan = self.state.get_plan(match.group(1))
            if plan:
                plan.status = PlanStatus.ABANDONED
                plan.abandoned_reason = match.group(2)
                logger.info(
                    "Plan [%s] abandoned: %s (reason: %s)",
                    plan.id,
                    plan.objective[:40],
                    plan.abandoned_reason[:60],
                )

    # -- hypothesis_update -------------------------------------------------

    _RE_HYPOTHESIS_UPDATE = re.compile(
        r'<hypothesis_update\s+id="([^"]+)"\s+confidence="([^"]+)"'
        r'(?:\s+evidence="([^"]*)")?\s*/?>',
    )

    def _parse_hypothesis_update(self, text: str) -> None:
        for match in self._RE_HYPOTHESIS_UPDATE.finditer(text):
            hyp_id = match.group(1)
            hyp = self.state.get_hypothesis(hyp_id)
            if hyp is None:
                # Auto-create if the LLM references a new hypothesis
                logger.debug("Auto-creating hypothesis %s from update block", hyp_id)
                hyp = Hypothesis(
                    id=hyp_id,
                    created_turn=self.state.turn,
                )
                self.state.hypotheses.append(hyp)

            try:
                hyp.confidence = HypothesisConfidence(match.group(2))
            except ValueError:
                logger.warning(
                    "Invalid confidence value '%s' for hypothesis %s",
                    match.group(2),
                    hyp_id,
                )
                continue

            evidence = match.group(3)
            if evidence:
                hyp.evidence_for.append(evidence)
            hyp.last_updated_turn = self.state.turn

    # -- strip plan blocks from display text -------------------------------

    _RE_STRIP = re.compile(
        r"<(?:plan_create|plan_update|plan_abandon|hypothesis_update)\b"
        r"[^>]*(?:/>|>.*?</(?:plan_create|plan_update|plan_abandon|hypothesis_update)>)",
        re.DOTALL,
    )

    def _strip_plan_blocks(self, text: str) -> str:
        return self._RE_STRIP.sub("", text).strip()

    # ------------------------------------------------------------------
    # Explicit plan generation via LLM call
    # ------------------------------------------------------------------

    def generate_initial_plan(
        self,
        target_description: str,
        scope_summary: str,
    ) -> None:
        """Ask the LLM to produce an initial attack plan for the mission.

        This is called once at mission start.  The LLM's response is
        parsed for plan blocks, updating ``self.state``.
        """
        if self.llm_call is None:
            logger.warning("No llm_call configured -- cannot generate initial plan")
            return

        messages: list[dict] = [
            {
                "role": "system",
                "content": (
                    "You are Phantom's planning engine.  Given a target "
                    "description and scope, produce an initial attack plan "
                    "using <plan_create> XML blocks.  Include hypotheses "
                    "where applicable."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Target: {target_description}\n"
                    f"Scope: {scope_summary}\n\n"
                    "Create an initial reconnaissance plan."
                ),
            },
        ]
        response = self.llm_call(messages)
        self.parse_plan_actions(response)


# ======================================================================
# Module-level helpers (private)
# ======================================================================


def _parse_attrs(attr_string: str) -> dict[str, str]:
    """Parse XML-like ``key="value"`` attributes from a string.

    Handles the subset of XML attributes used by Phantom plan blocks.
    Does NOT handle escaped quotes inside values -- plan blocks should
    avoid them.
    """
    return dict(re.findall(r'(\w+)="([^"]*)"', attr_string))


def _safe_json(s: str) -> dict:
    """Parse a JSON string, returning an empty dict on any error."""
    try:
        result = json.loads(s) if s else {}
        return result if isinstance(result, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _compact_json(obj: dict) -> str:
    """Serialize a dict with minimal whitespace."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
