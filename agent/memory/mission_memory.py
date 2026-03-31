"""Structured mission knowledge base -- not a conversation log.

MissionMemory holds all discovered findings, executed actions, working
hypotheses, and target intelligence.  The orchestrator injects a compact
summary of this state into the LLM context each turn so that structured
knowledge survives aggressive conversation pruning.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from agent.models.findings import (
    ActionRecord,
    Finding,
    Hypothesis,
    HypothesisConfidence,
    TargetInfo,
)

logger = logging.getLogger(__name__)

# Rough chars-per-token ratio for budget estimation.
_CHARS_PER_TOKEN = 4


class MissionMemory:
    """In-memory knowledge base for a single mission.

    Stores four primary collections, keyed by their ``id`` (or ``host``
    for targets).  Every mutation method is idempotent -- re-adding an
    item with the same key overwrites it.
    """

    def __init__(self) -> None:
        self.findings: dict[str, Finding] = {}
        self.actions: dict[str, ActionRecord] = {}
        self.hypotheses: dict[str, Hypothesis] = {}
        self.target_map: dict[str, TargetInfo] = {}

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def add_finding(self, finding: Finding) -> None:
        """Register a new finding (or update an existing one)."""
        self.findings[finding.id] = finding
        logger.debug("Finding added: %s [%s]", finding.title, finding.severity)

    def add_action(self, action: ActionRecord) -> None:
        """Record an action that was executed."""
        self.actions[action.id] = action
        logger.debug("Action recorded: %s (%s)", action.tool, action.id)

    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        """Register or update a hypothesis."""
        self.hypotheses[hypothesis.id] = hypothesis
        logger.debug(
            "Hypothesis registered: %s [%s]",
            hypothesis.statement,
            hypothesis.confidence.value,
        )

    def update_target(self, target_info: TargetInfo) -> None:
        """Upsert target information, merging with any existing data."""
        key = target_info.host
        if key in self.target_map:
            existing = self.target_map[key]
            # Merge ports (union)
            merged_ports = sorted(set(existing.ports) | set(target_info.ports))
            # Merge services (new data wins on conflict)
            merged_services = {**existing.services, **target_info.services}
            # Merge technologies (union, deduplicated)
            merged_techs = sorted(
                set(existing.technologies) | set(target_info.technologies)
            )
            os_guess = target_info.os_guess or existing.os_guess
            self.target_map[key] = TargetInfo(
                host=key,
                ports=merged_ports,
                services=merged_services,
                technologies=merged_techs,
                os_guess=os_guess,
            )
        else:
            self.target_map[key] = target_info
        logger.debug(
            "Target updated: %s (%d ports)", key, len(self.target_map[key].ports)
        )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def unanswered_hypotheses(self) -> list[Hypothesis]:
        """Return hypotheses that have not been confirmed or disproved."""
        return [
            h
            for h in self.hypotheses.values()
            if h.confidence
            in (HypothesisConfidence.SPECULATIVE, HypothesisConfidence.PROBABLE)
        ]

    def unexplored_targets(self) -> list[TargetInfo]:
        """Return targets with no associated findings yet."""
        hosts_with_findings: set[str] = set()
        for f in self.findings.values():
            if f.target:
                hosts_with_findings.add(f.target)
        return [
            t for t in self.target_map.values() if t.host not in hosts_with_findings
        ]

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by severity level, ordered critical-first."""
        severity_order = ["critical", "high", "medium", "low", "info"]
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for f in self.findings.values():
            grouped[f.severity.lower()].append(f)
        # Return only populated buckets, in severity order
        return {sev: grouped[sev] for sev in severity_order if sev in grouped}

    def findings_for_target(self, host: str) -> list[Finding]:
        """Return all findings associated with a specific target host."""
        return [f for f in self.findings.values() if f.target == host]

    # ------------------------------------------------------------------
    # Context injection
    # ------------------------------------------------------------------

    def summary_for_context(self, max_tokens: int = 4000) -> str:
        """Generate a compact state summary suitable for LLM context injection.

        The summary is assembled in priority order and truncated to fit
        within *max_tokens* (estimated via a chars-per-token heuristic).
        """
        budget = max_tokens * _CHARS_PER_TOKEN
        parts: list[str] = []

        # --- Section 1: Findings registry (highest priority) ---
        by_sev = self.findings_by_severity()
        if by_sev:
            lines = ["## Findings"]
            for sev, items in by_sev.items():
                for f in items:
                    cve = f" ({f.cve_id})" if f.cve_id else ""
                    cvss = f" CVSS:{f.cvss}" if f.cvss is not None else ""
                    lines.append(f"- [{sev.upper()}] {f.title} @ {f.target}{cve}{cvss}")
            parts.append("\n".join(lines))

        # --- Section 2: Target map ---
        if self.target_map:
            lines = ["## Targets"]
            for host, info in self.target_map.items():
                svc_str = ", ".join(
                    f"{p}/{s}" for p, s in sorted(info.services.items())
                )
                tech_str = ", ".join(info.technologies[:5]) if info.technologies else ""
                extras = []
                if svc_str:
                    extras.append(f"services=[{svc_str}]")
                if tech_str:
                    extras.append(f"tech=[{tech_str}]")
                if info.os_guess:
                    extras.append(f"os={info.os_guess}")
                detail = " | ".join(extras)
                lines.append(f"- {host}: {detail}")
            parts.append("\n".join(lines))

        # --- Section 3: Unanswered hypotheses ---
        unanswered = self.unanswered_hypotheses()
        if unanswered:
            lines = ["## Open Hypotheses"]
            for h in unanswered:
                lines.append(f"- [{h.confidence.value}] {h.statement}")
            parts.append("\n".join(lines))

        # --- Section 4: Unexplored targets ---
        unexplored = self.unexplored_targets()
        if unexplored:
            lines = ["## Unexplored Targets"]
            for t in unexplored:
                lines.append(f"- {t.host} (ports: {t.ports})")
            parts.append("\n".join(lines))

        # --- Section 5: Recent actions (last 10) ---
        recent_actions = sorted(
            self.actions.values(),
            key=lambda a: a.timestamp,
            reverse=True,
        )[:10]
        if recent_actions:
            lines = ["## Recent Actions"]
            for a in recent_actions:
                status = "OK" if a.success else "FAIL"
                lines.append(f"- [{status}] {a.tool}: {a.result_summary[:80]}")
            parts.append("\n".join(lines))

        # Assemble and truncate
        summary = "\n\n".join(parts)
        if len(summary) > budget:
            summary = summary[:budget] + "\n[...truncated]"
        return summary

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize entire memory state to a plain dict (JSON-safe)."""
        return {
            "findings": {k: v.to_dict() for k, v in self.findings.items()},
            "actions": {k: v.to_dict() for k, v in self.actions.items()},
            "hypotheses": {k: v.to_dict() for k, v in self.hypotheses.items()},
            "target_map": {k: v.to_dict() for k, v in self.target_map.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MissionMemory:
        """Reconstruct MissionMemory from a serialized dict."""
        mem = cls()
        for k, v in data.get("findings", {}).items():
            mem.findings[k] = Finding.from_dict(v)
        for k, v in data.get("actions", {}).items():
            mem.actions[k] = ActionRecord.from_dict(v)
        for k, v in data.get("hypotheses", {}).items():
            mem.hypotheses[k] = Hypothesis.from_dict(v)
        for k, v in data.get("target_map", {}).items():
            mem.target_map[k] = TargetInfo.from_dict(v)
        return mem
