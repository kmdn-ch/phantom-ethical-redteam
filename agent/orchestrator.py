"""Phantom v3 Orchestrator -- PAOR agentic loop.

Replaces the linear AgentClient.think() loop with Plan-Act-Observe-Reflect.
The LLM reasons freely; the framework maintains structured state and memory.
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from agent.models.events import Event, EventBus, EventType, Severity
from agent.models.findings import (
    ActionRecord,
    Finding,
    Hypothesis,
    HypothesisConfidence,
    TargetInfo,
)
from agent.models.graph import AttackGraph, EdgeType, GraphEdge, GraphNode, NodeType
from agent.models.plans import ActionStatus, AttackAction, AttackPlan, AttackState, PlanStatus
from agent.models.state import MissionPhase, MissionState
from agent.providers.base import BaseLLMProvider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity tag detection (reused from v2 for backwards compatibility)
# ---------------------------------------------------------------------------
_SEVERITY_RE = re.compile(
    r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]"
    r"|(\[\+\]\s*.*?(session|shell|exploit|vulnerable))"
    r"|(\[\*\]\s*.*?(found|opened|success))",
    re.IGNORECASE,
)

# Default configuration values
_DEFAULT_MAX_TURNS = 80
_DEFAULT_MAX_PARALLEL = 4
_DEFAULT_STRATEGIST_INTERVAL = 5
_DEFAULT_REFLECT_INTERVAL = 3
_DEFAULT_COMPACT_MAX_CHARS = 400


class Orchestrator:
    """V3 agentic loop implementing Plan-Act-Observe-Reflect (PAOR).

    The orchestrator coordinates the reasoning engine, tool execution,
    structured memory, and attack graph.  It is provider-agnostic -- all
    LLM interaction goes through the ``BaseLLMProvider`` abstraction.
    """

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def __init__(
        self,
        provider: BaseLLMProvider,
        config: dict[str, Any],
        scope_checker: Any = None,
    ) -> None:
        # LLM provider (Anthropic, OpenAI, Ollama, etc.)
        self.provider = provider

        # Configuration
        self.config = config
        self.max_turns: int = config.get("max_turns", _DEFAULT_MAX_TURNS)
        self.max_parallel: int = config.get("max_parallel_tools", _DEFAULT_MAX_PARALLEL)
        self.strategist_interval: int = config.get("strategist_interval", _DEFAULT_STRATEGIST_INTERVAL)
        self.reflect_interval: int = config.get("reflect_interval", _DEFAULT_REFLECT_INTERVAL)
        self.compact_max_chars: int = config.get("compact_max_chars", _DEFAULT_COMPACT_MAX_CHARS)
        self.session_dir: str = config.get("session_dir", "")
        self.mission_id: str = config.get("mission_id", "")

        # Scope enforcement
        self.scope_checker = scope_checker

        # ------ Reasoning components (lazy-imported to tolerate missing modules) ------
        self._planner = self._safe_import_component("PlanningLayer")
        self._reflector = self._safe_import_component("ReflectionLayer", self.reflect_interval)
        self._strategist = self._safe_import_component("Strategist")
        self._context_manager = self._safe_import_component("ContextManager")

        # ------ Memory ------
        self._mission_memory = self._safe_import_memory("MissionMemory")
        self._mission_db = self._safe_import_persistence()
        self._timeline = self._safe_import_timeline()

        # ------ Attack graph ------
        self.attack_graph = AttackGraph()

        # ------ Event bus ------
        self.event_bus = EventBus()

        # ------ Cognitive state ------
        self.attack_state = AttackState()

        # ------ Mission state machine ------
        self.mission_state = MissionState(mission_id=self.mission_id)

        # ------ Tool registry (lazy import to avoid circular deps) ------
        self._tool_registry: dict[str, Any] = {}
        self._tool_specs: list[dict] = []
        self._init_tools()

        # ------ Conversation history for LLM ------
        self._messages: list[dict] = []

        # ------ System prompt (loaded from file, with placeholder injection) ------
        self._system_prompt_template = self._load_system_prompt()

        # ------ Runtime bookkeeping ------
        self._turn: int = 0
        self._pause_requested: bool = False
        self._mission_complete: bool = False

    # ------------------------------------------------------------------
    # Component initialization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_import_component(class_name: str, *args: Any) -> Any:
        """Import a reasoning component, returning None if not yet implemented."""
        try:
            mod = __import__("agent.reasoning", fromlist=[class_name])
            cls = getattr(mod, class_name)
            return cls(*args)
        except (ImportError, AttributeError) as exc:
            logger.warning("Reasoning component %s not available: %s", class_name, exc)
            return None

    @staticmethod
    def _safe_import_memory(class_name: str) -> Any:
        try:
            mod = __import__("agent.memory", fromlist=[class_name])
            cls = getattr(mod, class_name)
            return cls()
        except (ImportError, AttributeError) as exc:
            logger.warning("Memory component %s not available: %s", class_name, exc)
            return None

    @staticmethod
    def _safe_import_persistence() -> Any:
        try:
            from agent.memory.persistence import MissionDB
            return MissionDB
        except (ImportError, AttributeError) as exc:
            logger.warning("MissionDB not available: %s", exc)
            return None

    @staticmethod
    def _safe_import_timeline() -> Any:
        try:
            from agent.memory.timeline import TimelineBuilder
            return TimelineBuilder()
        except (ImportError, AttributeError) as exc:
            logger.warning("TimelineBuilder not available: %s", exc)
            return None

    def _init_tools(self) -> None:
        """Load the tool registry -- isolated to handle import errors gracefully."""
        try:
            from agent.tools import ALL_TOOLS, get_tool_mapping
            self._tool_specs = ALL_TOOLS
            self._tool_registry = get_tool_mapping()
        except ImportError as exc:
            logger.error("Failed to load tool registry: %s", exc)

    def _load_system_prompt(self) -> str:
        """Load the v3 system prompt template from disk."""
        candidates = [
            os.path.join(os.path.dirname(__file__), "..", "prompts", "system_prompt_v3.txt"),
            os.path.join("prompts", "system_prompt_v3.txt"),
        ]
        for path in candidates:
            resolved = os.path.normpath(path)
            if os.path.isfile(resolved):
                with open(resolved, encoding="utf-8") as f:
                    return f.read()
        logger.warning("system_prompt_v3.txt not found; using minimal fallback")
        return (
            "You are Phantom, an autonomous penetration testing agent.\n"
            "Reason about what to do next. Use available tools.\n"
            "{tool_list}\n{state_summary}\n{graph_summary}\n{hypotheses}\n{last_plan}"
        )

    # ------------------------------------------------------------------
    # System prompt assembly
    # ------------------------------------------------------------------

    def _build_system_prompt(self) -> str:
        """Inject dynamic state into the system prompt template."""
        tool_list = self._format_tool_list()
        state_summary = self._format_state_summary()
        graph_summary = self._format_graph_summary()
        hypotheses = self._format_hypotheses()
        last_plan = self._format_last_plan()

        prompt = self._system_prompt_template.format(
            tool_list=tool_list,
            state_summary=state_summary,
            graph_summary=graph_summary,
            hypotheses=hypotheses,
            last_plan=last_plan,
        )
        return prompt

    def _format_tool_list(self) -> str:
        """Produce a compact tool list for the system prompt."""
        lines = []
        for spec in self._tool_specs:
            name = spec.get("name", "?")
            desc = spec.get("description", "")
            # Truncate long descriptions for token efficiency
            if len(desc) > 120:
                desc = desc[:117] + "..."
            lines.append(f"- {name}: {desc}")
        return "\n".join(lines) if lines else "(no tools loaded)"

    def _format_state_summary(self) -> str:
        """Produce a compact summary of mission state for context injection."""
        if self._context_manager is not None:
            try:
                return self._context_manager.build_state_summary(
                    self.attack_state, self._mission_memory
                )
            except Exception as exc:
                logger.debug("ContextManager.build_state_summary failed: %s", exc)

        # Fallback: build summary directly from attack_state
        lines = [f"Turn: {self._turn}/{self.max_turns}"]
        lines.append(f"Phase: {self.mission_state.phase.value}")

        findings_count = len(self.attack_state.findings)
        if findings_count:
            lines.append(f"Findings: {findings_count} total")
            for f in self.attack_state.findings[-5:]:
                sev = f.get("severity", "?")
                title = f.get("title", "")[:80]
                lines.append(f"  [{sev}] {title}")

        if self.attack_state.target_model:
            lines.append(f"Targets: {json.dumps(self.attack_state.target_model, separators=(',', ':'))}")

        return "\n".join(lines)

    def _format_graph_summary(self) -> str:
        """Produce a compact attack graph summary."""
        nodes = self.attack_graph.nodes
        edges = self.attack_graph.edges
        if not nodes:
            return "(no graph nodes yet)"

        lines = [f"Nodes: {len(nodes)} | Edges: {len(edges)}"]
        # Show node type counts
        type_counts: dict[str, int] = {}
        for n in nodes:
            t = n.node_type.value
            type_counts[t] = type_counts.get(t, 0) + 1
        lines.append(" | ".join(f"{t}:{c}" for t, c in type_counts.items()))

        # Show attack chains if any
        chains = self.attack_graph.get_chains()
        if chains:
            lines.append(f"Attack chains found: {len(chains)}")
            for i, chain in enumerate(chains[:3]):
                path_str = " -> ".join(n.label[:30] for n in chain)
                lines.append(f"  Chain {i + 1}: {path_str}")

        return "\n".join(lines)

    def _format_hypotheses(self) -> str:
        """Format active hypotheses for context injection."""
        active = [
            h for h in self.attack_state.hypotheses
            if h.confidence != HypothesisConfidence.DISPROVED
        ]
        if not active:
            return "(no active hypotheses)"

        lines = []
        for h in active:
            lines.append(f"[{h.id}] {h.confidence.value}: {h.statement}")
        return "\n".join(lines)

    def _format_last_plan(self) -> str:
        """Format the current/most recent active plan."""
        active = self.attack_state.active_plans()
        if not active:
            return "(no active plan -- create one)"

        lines = []
        for plan in sorted(active, key=lambda p: -p.priority)[:3]:
            pending = [a for a in plan.actions if a.status == "pending"]
            done = [a for a in plan.actions if a.status == "done"]
            lines.append(
                f"Plan [{plan.id}] pri={plan.priority:.1f}: {plan.objective} "
                f"({len(done)} done, {len(pending)} pending)"
            )
            for a in pending[:3]:
                desc = a.description or a.tool_name or "?"
                lines.append(f"  -> {desc}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Main mission loop
    # ------------------------------------------------------------------

    def run_mission(self, scope_targets: list[str]) -> dict[str, Any]:
        """Execute the full PAOR mission loop.

        Args:
            scope_targets: List of authorized targets (hosts, URLs, CIDRs).

        Returns:
            A debrief dict containing timeline, graph, findings, and report path.
        """
        self._install_signal_handler()
        self._emit_event(EventType.SESSION_START, reasoning=f"Mission started with targets: {scope_targets}")

        # Transition to RECON phase
        try:
            self.mission_state.transition(MissionPhase.RECON)
        except Exception as exc:
            logger.warning("Phase transition failed: %s", exc)

        # Seed the initial user message with scope targets
        initial_message = self._build_initial_message(scope_targets)
        self._messages.append({"role": "user", "content": initial_message})

        # ---- Main PAOR loop ----
        while not self._mission_complete and self._turn < self.max_turns:
            if self._pause_requested:
                self._handle_pause()
                continue

            self._turn += 1
            self.attack_state.turn = self._turn
            logger.info("=== Turn %d/%d ===", self._turn, self.max_turns)

            try:
                # 1. PLAN -- inject state, get LLM response with plan + tool calls
                text_blocks, tool_calls = self._plan_phase()

                # 2. ACT -- execute tool calls
                tool_results = self._act_phase(tool_calls)

                # 3. OBSERVE -- parse results, update memory + graph
                self._observe_phase(tool_calls, tool_results, text_blocks)

                # 4. REFLECT -- evaluate progress, handle pivots
                self._reflect_phase()

                # Periodic strategist run
                if self._turn % self.strategist_interval == 0:
                    self._run_strategist()

                # Check mission completion
                if self._check_mission_complete():
                    self._mission_complete = True

                # Persist state after every turn
                self._save_state()

            except KeyboardInterrupt:
                logger.info("KeyboardInterrupt received at turn %d", self._turn)
                self._pause_requested = True
            except Exception as exc:
                logger.error("Error in turn %d: %s", self._turn, exc, exc_info=True)
                self._emit_event(
                    EventType.TOOL_FAILED,
                    reasoning=f"Turn {self._turn} failed: {exc}",
                )
                # Continue to next turn unless it's a fatal error
                if self._turn >= self.max_turns:
                    break

        # ---- Debrief ----
        return self._debrief()

    def _build_initial_message(self, scope_targets: list[str]) -> str:
        """Build the initial user message with scope targets."""
        targets_str = "\n".join(f"  - {t}" for t in scope_targets)
        return (
            f"Mission scope targets:\n{targets_str}\n\n"
            "Assess these targets. Create an initial plan, form hypotheses, "
            "and begin reconnaissance. You have full autonomy within scope."
        )

    # ------------------------------------------------------------------
    # Phase 1: PLAN
    # ------------------------------------------------------------------

    def _plan_phase(self) -> tuple[list[str], list[dict]]:
        """Call the LLM with injected state context.

        Returns:
            (text_blocks, tool_calls) from the LLM response.
        """
        # Build system prompt with current state injected
        system_prompt = self._build_system_prompt()

        # Inject reflection prompt if the reflector says it's time
        if self._reflector is not None:
            try:
                if self._reflector.should_reflect(self.attack_state):
                    reflection_prompt = self._reflector.build_reflection_prompt(self.attack_state)
                    system_prompt += "\n\n" + reflection_prompt
            except Exception as exc:
                logger.debug("Reflector.should_reflect failed: %s", exc)

        # Compact old tool results to manage context window
        messages = self._compact_old_tool_results(self._messages)

        # Convert tools for the provider
        converted_tools = self.provider.convert_tools(self._tool_specs)

        # Call LLM
        text_blocks, tool_calls = self.provider.call_with_retry(
            messages, system_prompt, converted_tools
        )

        # Parse planning XML blocks from LLM text and update attack state
        cleaned_texts = []
        for text in text_blocks:
            cleaned = self._parse_plan_blocks(text)
            cleaned_texts.append(cleaned)
            # Display to operator
            print(f"\n{'=' * 60}")
            print(f"Phantom [Turn {self._turn}]: {cleaned}")
            print(f"{'=' * 60}")
            logger.info("Reasoning: %s", cleaned[:300])

        # Build assistant message for conversation history
        assistant_blocks: list[dict] = []
        for text in text_blocks:
            assistant_blocks.append({"type": "text", "text": text})
        for tc in tool_calls:
            assistant_blocks.append({
                "type": "tool_use",
                "id": tc["id"],
                "name": tc["name"],
                "input": tc["input"],
            })

        if assistant_blocks:
            self._messages.append({"role": "assistant", "content": assistant_blocks})

        return cleaned_texts, tool_calls

    def _parse_plan_blocks(self, llm_text: str) -> str:
        """Parse plan/hypothesis XML blocks from LLM output and update state.

        Returns the cleaned text with XML blocks removed for display.
        """
        if self._planner is not None:
            try:
                return self._planner.parse_plan_actions(llm_text)
            except Exception as exc:
                logger.debug("PlanningLayer.parse_plan_actions failed: %s", exc)

        # Fallback: inline parsing
        return self._inline_parse_plan_blocks(llm_text)

    def _inline_parse_plan_blocks(self, llm_text: str) -> str:
        """Fallback plan block parser when PlanningLayer is unavailable."""
        # Parse <plan_create> blocks
        for match in re.finditer(
            r'<plan_create\s+objective="([^"]+)"'
            r'(?:\s+priority="([^"]*)")?'
            r'(?:\s+hypothesis="([^"]*)")?'
            r'>(.*?)</plan_create>',
            llm_text,
            re.DOTALL,
        ):
            objective = match.group(1)
            priority = float(match.group(2) or "0.5")
            hypothesis_id = match.group(3) or None

            plan = AttackPlan(
                objective=objective,
                priority=priority,
                hypothesis=hypothesis_id,
                created_turn=self._turn,
                status=PlanStatus.ACTIVE,
            )

            prev_action_id: Optional[str] = None
            for action_match in re.finditer(
                r"<action\s+(.*?)/>", match.group(4), re.DOTALL
            ):
                attrs = self._parse_xml_attrs(action_match.group(1))
                action = AttackAction(
                    description=attrs.get("description", ""),
                    tool_name=attrs.get("tool") if attrs.get("tool") else None,
                    tool_args=self._safe_json_parse(attrs.get("args", "{}")),
                    priority=float(attrs.get("priority", "0.5")),
                    status=ActionStatus.PENDING,
                )
                if attrs.get("depends_on") == "prev" and prev_action_id:
                    action.depends_on = [prev_action_id]
                elif attrs.get("depends_on"):
                    action.depends_on = [
                        d.strip() for d in attrs["depends_on"].split(",")
                    ]
                plan.actions.append(action)
                prev_action_id = action.id

            self.attack_state.plans.append(plan)
            logger.info("Plan created: [%s] %s (pri=%.1f)", plan.id, objective, priority)

        # Parse <plan_update> blocks
        for match in re.finditer(
            r'<plan_update\s+id="([^"]+)">(.*?)</plan_update>',
            llm_text,
            re.DOTALL,
        ):
            plan = self.attack_state.get_plan(match.group(1))
            if plan is None:
                continue
            for status_match in re.finditer(
                r'<action_status\s+id="([^"]+)"\s+status="([^"]+)"'
                r'(?:\s+summary="([^"]*)")?\s*/?>',
                match.group(2),
            ):
                for action in plan.actions:
                    if action.id == status_match.group(1):
                        try:
                            action.status = ActionStatus(status_match.group(2))
                        except ValueError:
                            action.status = ActionStatus.DONE
                        action.result_summary = status_match.group(3) or ""
            for pri_match in re.finditer(
                r'<reprioritize\s+priority="([^"]+)"\s*/?>', match.group(2)
            ):
                plan.priority = float(pri_match.group(1))

        # Parse <plan_abandon> blocks
        for match in re.finditer(
            r'<plan_abandon\s+id="([^"]+)"\s+reason="([^"]+)"\s*/?>',
            llm_text,
        ):
            plan = self.attack_state.get_plan(match.group(1))
            if plan is not None:
                plan.status = PlanStatus.ABANDONED
                plan.abandoned_reason = match.group(2)
                logger.info("Plan abandoned: [%s] reason=%s", plan.id, match.group(2))

        # Parse <hypothesis_update> blocks
        for match in re.finditer(
            r'<hypothesis_update\s+id="([^"]+)"\s+confidence="([^"]+)"'
            r'(?:\s+evidence="([^"]*)")?\s*/?>',
            llm_text,
        ):
            hyp = self.attack_state.get_hypothesis(match.group(1))
            if hyp is not None:
                try:
                    hyp.confidence = HypothesisConfidence(match.group(2))
                except ValueError:
                    pass
                if match.group(3):
                    hyp.evidence_for.append(match.group(3))
                hyp.last_updated_turn = self._turn

        # Strip all plan/hypothesis blocks from display text
        cleaned = re.sub(
            r"<(?:plan_create|plan_update|plan_abandon|hypothesis_update)\b[^>]*>"
            r"(?:.*?</(?:plan_create|plan_update|plan_abandon|hypothesis_update)>)?",
            "",
            llm_text,
            flags=re.DOTALL,
        )
        # Also strip self-closing variants
        cleaned = re.sub(
            r"<(?:plan_abandon|hypothesis_update)\b[^/]*/\s*>",
            "",
            cleaned,
        )
        return cleaned.strip()

    # ------------------------------------------------------------------
    # Phase 2: ACT
    # ------------------------------------------------------------------

    def _act_phase(self, tool_calls: list[dict]) -> list[dict]:
        """Execute tool calls, in parallel when possible.

        Returns:
            List of tool_result dicts in the same order as tool_calls.
        """
        if not tool_calls:
            return []

        tool_names = [tc["name"] for tc in tool_calls]
        logger.info(
            "Executing %d tool(s): %s", len(tool_calls), tool_names
        )
        print(f"  >> Running: {', '.join(tool_names)}")

        results = self._execute_tools_parallel(tool_calls)

        # Append tool results to conversation history
        if results:
            self._messages.append({"role": "user", "content": results})

        return results

    def _execute_tool(self, tc: dict) -> dict:
        """Execute a single tool call and return the result block."""
        tool_func = self._tool_registry.get(tc["name"])
        if not tool_func:
            logger.warning("Unknown tool: %s", tc["name"])
            return {
                "type": "tool_result",
                "tool_use_id": tc["id"],
                "content": f"Unknown tool: {tc['name']}",
            }

        tool_input = tc.get("input")
        if not isinstance(tool_input, dict):
            logger.warning(
                "Tool %s received non-dict input: %s", tc["name"], type(tool_input)
            )
            return {
                "type": "tool_result",
                "tool_use_id": tc["id"],
                "content": f"Error: tool input must be a dict, got {type(tool_input).__name__}",
            }

        start_time = time.monotonic()
        try:
            result = tool_func(**tool_input)
            duration_ms = int((time.monotonic() - start_time) * 1000)
            logger.debug(
                "AUDIT tool=%s params=%s status=ok duration=%dms",
                tc["name"],
                list(tool_input.keys()),
                duration_ms,
            )

            # Emit tool_completed event
            self._emit_event(
                EventType.TOOL_COMPLETED,
                tool_name=tc["name"],
                tool_input=tool_input,
                tool_output=str(result)[:500],
                tool_duration_ms=duration_ms,
            )

            return {
                "type": "tool_result",
                "tool_use_id": tc["id"],
                "content": str(result),
            }
        except Exception as exc:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            error_msg = f"Error {tc['name']}: {exc}"
            logger.error("AUDIT tool=%s status=error error=%s", tc["name"], exc)

            self._emit_event(
                EventType.TOOL_FAILED,
                tool_name=tc["name"],
                tool_input=tool_input,
                tool_output=error_msg,
                tool_duration_ms=duration_ms,
            )

            return {
                "type": "tool_result",
                "tool_use_id": tc["id"],
                "content": error_msg,
            }

    def _execute_tools_parallel(self, tool_calls: list[dict]) -> list[dict]:
        """Execute multiple tool calls in parallel using ThreadPoolExecutor."""
        if len(tool_calls) == 1:
            return [self._execute_tool(tool_calls[0])]

        results: list[Optional[dict]] = [None] * len(tool_calls)
        with ThreadPoolExecutor(
            max_workers=min(len(tool_calls), self.max_parallel)
        ) as executor:
            future_to_idx = {
                executor.submit(self._execute_tool, tc): i
                for i, tc in enumerate(tool_calls)
            }
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    results[idx] = future.result()
                except Exception as exc:
                    results[idx] = {
                        "type": "tool_result",
                        "tool_use_id": tool_calls[idx]["id"],
                        "content": f"Execution error: {exc}",
                    }
        return [r for r in results if r is not None]

    # ------------------------------------------------------------------
    # Phase 3: OBSERVE
    # ------------------------------------------------------------------

    def _observe_phase(
        self,
        tool_calls: list[dict],
        tool_results: list[dict],
        text_blocks: list[str],
    ) -> None:
        """Parse tool results, extract findings, update memory and attack graph."""
        for tc, tr in zip(tool_calls, tool_results):
            content = str(tr.get("content", ""))
            tool_name = tc["name"]

            # Extract findings from raw output using severity regex
            findings = self._extract_findings(content, tool_name, tc.get("input", {}))

            # Record action in attack state
            action_record = {
                "tool": tool_name,
                "parameters": tc.get("input", {}),
                "result_summary": content[:200],
                "findings_count": len(findings),
                "turn": self._turn,
                "success": not content.startswith("Error"),
            }

            # Update mission memory if available
            if self._mission_memory is not None:
                try:
                    for finding in findings:
                        self._mission_memory.add_finding(finding)
                    self._mission_memory.add_action(
                        ActionRecord(
                            tool=tool_name,
                            parameters=tc.get("input", {}),
                            result_summary=content[:200],
                            findings_produced=[f.id for f in findings],
                            success=not content.startswith("Error"),
                        )
                    )
                except Exception as exc:
                    logger.debug("MissionMemory update failed: %s", exc)

            # Update attack graph with discovered entities
            self._update_graph_from_results(tool_name, tc.get("input", {}), content, findings)

            # Add findings to attack state for context injection
            for finding in findings:
                self.attack_state.findings.append(finding.to_dict())

            # Update timeline
            if self._timeline is not None:
                try:
                    self._timeline.add_event(
                        tool_name, tc.get("input", {}), content[:200], findings
                    )
                except Exception as exc:
                    logger.debug("Timeline update failed: %s", exc)

        # Parse reflection blocks from text if present
        for text in text_blocks:
            reflection = self._parse_reflection_block(text)
            if reflection:
                self._apply_reflection(reflection)

    def _extract_findings(
        self, content: str, tool_name: str, tool_input: dict
    ) -> list[Finding]:
        """Extract structured findings from raw tool output."""
        findings: list[Finding] = []
        target = tool_input.get("target", tool_input.get("url", ""))

        # Pattern-based extraction from severity-tagged lines
        for line in content.splitlines():
            sev_match = re.search(
                r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.*)", line, re.IGNORECASE
            )
            if sev_match:
                severity = sev_match.group(1).lower()
                title = sev_match.group(2).strip()[:120]
                finding = Finding(
                    severity=severity,
                    category=self._infer_category(title, tool_name),
                    title=title,
                    target=target,
                    evidence=line.strip()[:500],
                    tool_source=tool_name,
                )
                findings.append(finding)

                # Emit finding event
                self._emit_event(
                    EventType.FINDING_DISCOVERED,
                    severity=Severity(severity) if severity in Severity.__members__ else Severity.INFO,
                    target=target,
                    title=title,
                    evidence=line.strip()[:500],
                    tool_name=tool_name,
                )

        return findings

    @staticmethod
    def _infer_category(title: str, tool_name: str) -> str:
        """Infer finding category from title and tool name."""
        title_lower = title.lower()
        if "cve-" in title_lower:
            return "cve"
        if any(kw in title_lower for kw in ("sqli", "sql injection", "sqlmap")):
            return "injection"
        if any(kw in title_lower for kw in ("xss", "cross-site")):
            return "xss"
        if any(kw in title_lower for kw in ("cred", "password", "login", "default")):
            return "credential"
        if any(kw in title_lower for kw in ("misconfig", "misconfiguration", "header")):
            return "misconfig"
        if any(kw in title_lower for kw in ("exposure", "leak", "backup", "disclosure")):
            return "exposure"
        return "general"

    def _update_graph_from_results(
        self,
        tool_name: str,
        tool_input: dict,
        content: str,
        findings: list[Finding],
    ) -> None:
        """Update the attack graph based on tool results."""
        target = tool_input.get("target", tool_input.get("url", ""))
        if not target:
            return

        # Ensure the host node exists
        host_id = f"host_{target.replace('.', '_').replace(':', '_')[:30]}"
        if self.attack_graph.get_node(host_id) is None:
            self.attack_graph.add_node(
                GraphNode(id=host_id, node_type=NodeType.HOST, label=target)
            )

        # Add vulnerability nodes for each finding
        for finding in findings:
            if finding.severity in ("critical", "high", "medium"):
                vuln_id = f"vuln_{finding.id}"
                vuln_node = GraphNode(
                    id=vuln_id,
                    node_type=NodeType.VULNERABILITY,
                    label=finding.title[:50],
                    metadata={"severity": finding.severity, "tool": tool_name},
                )
                self.attack_graph.add_node(vuln_node)
                try:
                    self.attack_graph.add_edge(
                        GraphEdge(
                            source_id=host_id,
                            target_id=vuln_id,
                            edge_type=EdgeType.EXPOSES,
                            label=f"Found by {tool_name}",
                        )
                    )
                except ValueError:
                    pass  # Edge nodes may not exist if graph was pruned

    # ------------------------------------------------------------------
    # Phase 4: REFLECT
    # ------------------------------------------------------------------

    def _reflect_phase(self) -> None:
        """Run the reflection layer to evaluate progress and decide on pivots."""
        if self._reflector is None:
            return

        try:
            if not self._reflector.should_reflect(self.attack_state):
                return
        except Exception:
            return

        logger.info("Reflection triggered at turn %d", self._turn)
        self._emit_event(EventType.DECISION, reasoning="Reflection phase triggered")

    def _parse_reflection_block(self, text: str) -> Optional[dict]:
        """Extract <reflection> block from LLM output."""
        match = re.search(r"<reflection>(.*?)</reflection>", text, re.DOTALL)
        if not match:
            return None

        block = match.group(1)
        reflection: dict[str, str] = {}
        for line in block.strip().splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                reflection[key.strip()] = value.strip()

        return reflection

    def _apply_reflection(self, reflection: dict) -> None:
        """Apply reflection decisions to attack state."""
        decision = reflection.get("decision", "continue")

        if decision == "pivot":
            # Deprioritize all active plans to make room for new approach
            for plan in self.attack_state.active_plans():
                plan.priority = max(0.1, plan.priority - 0.3)
            logger.info("Reflection pivot: deprioritized all active plans")
            self._emit_event(EventType.PIVOT, reasoning="Reflection triggered pivot")

        elif decision == "escalate":
            logger.info("Reflection escalation: flagging for human input")
            self._emit_event(
                EventType.DECISION,
                reasoning="Reflection requested human escalation",
            )

        if reflection.get("approach_effective") == "no":
            logger.info("Current approach marked ineffective by reflection")

        # If the reflector component exists, delegate to it
        if self._reflector is not None:
            try:
                self._reflector.apply_reflection(reflection, self.attack_state)
            except Exception as exc:
                logger.debug("Reflector.apply_reflection failed: %s", exc)

    # ------------------------------------------------------------------
    # Strategist (periodic high-level analysis)
    # ------------------------------------------------------------------

    def _run_strategist(self) -> None:
        """Run the strategist for high-level attack surface analysis."""
        if self._strategist is None:
            return

        logger.info("Strategist analysis at turn %d", self._turn)
        try:
            self._strategist.analyze(self.attack_state, self.attack_graph)
        except Exception as exc:
            logger.debug("Strategist.analyze failed: %s", exc)

    # ------------------------------------------------------------------
    # Mission completion check
    # ------------------------------------------------------------------

    def _check_mission_complete(self) -> bool:
        """Determine if the mission should end."""
        # Hard stop: max turns
        if self._turn >= self.max_turns:
            logger.info("Mission complete: max turns (%d) reached", self.max_turns)
            return True

        # All hypotheses tested
        untested = [
            h
            for h in self.attack_state.hypotheses
            if h.confidence
            in (HypothesisConfidence.SPECULATIVE, HypothesisConfidence.PROBABLE)
        ]
        all_plans_done = all(
            p.status in (PlanStatus.COMPLETED, PlanStatus.ABANDONED)
            for p in self.attack_state.plans
        ) if self.attack_state.plans else False

        if all_plans_done and not untested and self._turn > 5:
            logger.info("Mission complete: all plans resolved and hypotheses tested")
            return True

        # Check if the LLM signalled completion
        if self._messages:
            last_msg = self._messages[-1]
            content = last_msg.get("content", "")
            if isinstance(content, list):
                content = " ".join(
                    b.get("text", "") for b in content if isinstance(b, dict)
                )
            if "=== MISSION COMPLETE ===" in str(content):
                logger.info("Mission complete: agent signalled completion")
                return True

        return False

    # ------------------------------------------------------------------
    # Debrief
    # ------------------------------------------------------------------

    def _debrief(self) -> dict[str, Any]:
        """Generate the mission debrief: timeline, attack graph, summary."""
        logger.info("Generating mission debrief after %d turns", self._turn)

        # Transition to DEBRIEF phase
        try:
            self.mission_state.transition(MissionPhase.DEBRIEF)
        except Exception:
            pass

        debrief: dict[str, Any] = {
            "mission_id": self.mission_id,
            "total_turns": self._turn,
            "total_findings": len(self.attack_state.findings),
            "attack_graph": self.attack_graph.to_dict(),
            "attack_graph_mermaid": self.attack_graph.to_mermaid(),
            "findings": self.attack_state.findings,
            "plans": [p.to_dict() for p in self.attack_state.plans],
            "hypotheses": [
                {
                    "id": h.id,
                    "statement": h.statement,
                    "confidence": h.confidence.value,
                }
                for h in self.attack_state.hypotheses
            ],
        }

        # Timeline
        if self._timeline is not None:
            try:
                debrief["timeline"] = self._timeline.to_json()
                debrief["timeline_markdown"] = self._timeline.to_markdown()
            except Exception as exc:
                logger.debug("Timeline export failed: %s", exc)

        # Attack chains
        chains = self.attack_graph.get_chains()
        debrief["attack_chains"] = [
            {
                "nodes": [
                    {"id": n.id, "type": n.node_type.value, "label": n.label}
                    for n in chain
                ]
            }
            for chain in chains
        ]

        # Persist debrief
        if self.session_dir:
            debrief_path = os.path.join(self.session_dir, "debrief.json")
            try:
                with open(debrief_path, "w", encoding="utf-8") as f:
                    json.dump(debrief, f, ensure_ascii=False, indent=2, default=str)
                debrief["debrief_path"] = debrief_path
                logger.info("Debrief written to %s", debrief_path)
            except Exception as exc:
                logger.error("Failed to write debrief: %s", exc)

        # Transition to COMPLETED
        try:
            self.mission_state.transition(MissionPhase.COMPLETED)
        except Exception:
            pass

        self._emit_event(
            EventType.SESSION_END,
            reasoning=f"Mission completed after {self._turn} turns, {len(self.attack_state.findings)} findings",
        )

        print(f"\n{'=' * 60}")
        print(f"  MISSION DEBRIEF")
        print(f"  Turns: {self._turn}")
        print(f"  Findings: {len(self.attack_state.findings)}")
        print(f"  Attack chains: {len(chains)}")
        print(f"  Plans: {len(self.attack_state.plans)} "
              f"({sum(1 for p in self.attack_state.plans if p.status == PlanStatus.COMPLETED)} completed, "
              f"{sum(1 for p in self.attack_state.plans if p.status == PlanStatus.ABANDONED)} abandoned)")
        print(f"{'=' * 60}\n")

        return debrief

    # ------------------------------------------------------------------
    # Signal handling (graceful pause on Ctrl+C)
    # ------------------------------------------------------------------

    def _install_signal_handler(self) -> None:
        """Install SIGINT handler for graceful pause."""
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
        except (OSError, ValueError):
            # signal.signal can fail if not called from main thread
            pass

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Handle SIGINT by requesting a pause."""
        if self._pause_requested:
            # Second Ctrl+C: hard exit
            raise KeyboardInterrupt
        print("\n  >> Pause requested. Finishing current turn...")
        self._pause_requested = True

    def _handle_pause(self) -> None:
        """Handle mission pause: save state and wait for resume or abort."""
        logger.info("Mission paused at turn %d", self._turn)
        self._save_state()

        try:
            self.mission_state.pause()
        except Exception:
            pass

        self._emit_event(
            EventType.SESSION_PAUSE,
            reasoning=f"Paused at turn {self._turn}",
        )

        print(f"\n  Mission paused at turn {self._turn}.")
        print("  State saved. Press Ctrl+C again to abort, or resume programmatically.")

        # For CLI usage, we stop the loop
        self._mission_complete = True

    # ------------------------------------------------------------------
    # Context management
    # ------------------------------------------------------------------

    def _compact_old_tool_results(
        self, messages: list[dict], keep_last_n: int = 3
    ) -> list[dict]:
        """Truncate old tool_result blocks to manage context window size."""
        tool_result_indices = [
            i
            for i, m in enumerate(messages)
            if m.get("role") == "user"
            and isinstance(m.get("content"), list)
            and any(
                isinstance(b, dict) and b.get("type") == "tool_result"
                for b in m["content"]
            )
        ]
        to_compact = (
            set(tool_result_indices[:-keep_last_n])
            if len(tool_result_indices) > keep_last_n
            else set()
        )
        if not to_compact:
            return messages

        result = []
        for i, msg in enumerate(messages):
            if i in to_compact:
                compacted = []
                for block in msg["content"]:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        content = str(block.get("content", ""))
                        if len(content) > self.compact_max_chars:
                            block = {
                                **block,
                                "content": content[: self.compact_max_chars]
                                + " [...compacted]",
                            }
                    compacted.append(block)
                result.append({**msg, "content": compacted})
            else:
                result.append(msg)
        return result

    def _estimate_tokens(self, messages: list[dict]) -> int:
        """Rough token estimate (1 token ~ 4 chars)."""
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        total += len(
                            str(block.get("content", "") or block.get("text", ""))
                        )
                    else:
                        total += len(str(block))
            else:
                total += len(str(content))
        return total // 4

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _save_state(self) -> None:
        """Persist mission state for resume capability (atomic write)."""
        if not self.session_dir:
            return

        try:
            state = {
                "turn": self._turn,
                "messages": self._messages,
                "attack_state": self.attack_state.to_dict(),
                "attack_graph": self.attack_graph.to_dict(),
                "mission_state": {
                    "phase": self.mission_state.phase.value,
                    "mission_id": self.mission_state.mission_id,
                },
            }
            state_path = os.path.join(self.session_dir, "state.json")
            # Atomic write: temp file then rename
            fd, tmp_path = tempfile.mkstemp(dir=self.session_dir, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(state, f, ensure_ascii=False, indent=1, default=str)
                os.replace(tmp_path, state_path)
            except Exception:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                raise
            logger.debug("State saved at turn %d", self._turn)
        except Exception as exc:
            logger.error("Failed to save state at turn %d: %s", self._turn, exc)

    def load_state(self, session_dir: str) -> bool:
        """Load and restore mission state from a previous session.

        Returns True if state was loaded successfully.
        """
        state_path = os.path.join(session_dir, "state.json")
        if not os.path.exists(state_path):
            return False

        try:
            with open(state_path, encoding="utf-8") as f:
                state = json.load(f)

            if not isinstance(state, dict) or "turn" not in state:
                logger.warning("Corrupted state.json -- missing required keys")
                return False

            self._turn = state["turn"]
            self._messages = state.get("messages", [])

            if "attack_state" in state:
                self.attack_state = AttackState.from_dict(state["attack_state"])

            if "attack_graph" in state:
                self.attack_graph = AttackGraph.from_dict(state["attack_graph"])

            logger.info("State loaded from %s (turn %d)", session_dir, self._turn)
            return True
        except (json.JSONDecodeError, IOError, KeyError) as exc:
            logger.error("Failed to load state: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Event emission helper
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: EventType, **kwargs: Any) -> None:
        """Emit an event to the event bus."""
        try:
            event = Event(
                mission_id=self.mission_id,
                turn=self._turn,
                event_type=event_type,
                phase=self.mission_state.phase.value,
                **kwargs,
            )
            self.event_bus.emit(event)
        except Exception as exc:
            logger.debug("Event emission failed: %s", exc)

    # ------------------------------------------------------------------
    # XML attribute parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_xml_attrs(attr_string: str) -> dict[str, str]:
        """Parse XML-like attributes from a string."""
        return dict(re.findall(r'(\w+)="([^"]*)"', attr_string))

    @staticmethod
    def _safe_json_parse(s: str) -> dict:
        """Parse JSON string, returning empty dict on failure."""
        try:
            return json.loads(s) if s else {}
        except (json.JSONDecodeError, TypeError):
            return {}
