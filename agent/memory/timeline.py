"""Timeline builder: converts raw event lists into structured, phase-grouped narratives.

Used for debrief reports and attack graph visualization export.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any

from agent.models.events import Event, EventType, Severity

logger = logging.getLogger(__name__)

# Severity ordering for display (most severe first).
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "none": 5,
}


class TimelineBuilder:
    """Constructs a chronological, phase-grouped timeline from raw events.

    Usage::

        builder = TimelineBuilder()
        timeline = builder.build_timeline(events)
        print(builder.to_markdown())
    """

    def __init__(self) -> None:
        self._phases: list[dict[str, Any]] = []
        self._events: list[Event] = []

    # ------------------------------------------------------------------
    # Core
    # ------------------------------------------------------------------

    def build_timeline(self, events: list[Event]) -> list[dict[str, Any]]:
        """Convert an event list into a phase-grouped timeline.

        Events are sorted chronologically, then grouped by their ``phase``
        attribute.  Each phase group records its start/end time, duration,
        event count, and findings count.

        Returns the structured timeline (also accessible via ``to_dict``).
        """
        if not events:
            self._phases = []
            self._events = []
            return []

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        self._events = sorted_events

        # Group events by phase, preserving first-seen order
        phase_order: list[str] = []
        phase_events: dict[str, list[Event]] = defaultdict(list)
        for ev in sorted_events:
            phase = ev.phase
            if phase not in phase_events:
                phase_order.append(phase)
            phase_events[phase].append(ev)

        phases: list[dict[str, Any]] = []
        for phase_name in phase_order:
            evts = phase_events[phase_name]
            start_time = evts[0].timestamp
            end_time = evts[-1].timestamp
            duration_sec = (end_time - start_time).total_seconds()

            # Count findings-related events
            finding_events = [
                e
                for e in evts
                if e.event_type
                in (EventType.FINDING_DISCOVERED, EventType.FINDING_CONFIRMED)
            ]

            # Collect tools used
            tools_used: list[str] = []
            seen_tools: set[str] = set()
            for e in evts:
                if e.tool_name and e.tool_name not in seen_tools:
                    tools_used.append(e.tool_name)
                    seen_tools.add(e.tool_name)

            # Highest severity in this phase
            max_severity = "none"
            for e in evts:
                sev = e.severity.value if e.severity else "none"
                if _SEVERITY_RANK.get(sev, 5) < _SEVERITY_RANK.get(max_severity, 5):
                    max_severity = sev

            phase_entry: dict[str, Any] = {
                "phase": phase_name,
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "duration_seconds": duration_sec,
                "event_count": len(evts),
                "findings_count": len(finding_events),
                "max_severity": max_severity,
                "tools_used": tools_used,
                "events": [self._event_to_entry(e) for e in evts],
            }
            phases.append(phase_entry)

        self._phases = phases
        return phases

    # ------------------------------------------------------------------
    # Export formats
    # ------------------------------------------------------------------

    def to_markdown(self) -> str:
        """Render the timeline as a formatted Markdown document."""
        if not self._phases:
            return "# Mission Timeline\n\nNo events recorded."

        lines: list[str] = ["# Mission Timeline", ""]

        total_events = sum(p["event_count"] for p in self._phases)
        total_findings = sum(p["findings_count"] for p in self._phases)

        if self._phases:
            mission_start = self._phases[0]["start"]
            mission_end = self._phases[-1]["end"]
            total_duration = (
                datetime.fromisoformat(mission_end)
                - datetime.fromisoformat(mission_start)
            ).total_seconds()
        else:
            total_duration = 0.0

        lines.append(
            f"**Duration:** {_format_duration(total_duration)} | "
            f"**Events:** {total_events} | "
            f"**Findings:** {total_findings} | "
            f"**Phases:** {len(self._phases)}"
        )
        lines.append("")

        for phase in self._phases:
            sev_badge = ""
            if phase["max_severity"] not in ("none", "info"):
                sev_badge = f" [{phase['max_severity'].upper()}]"

            lines.append(f"## Phase: {phase['phase'].upper()}{sev_badge}")
            lines.append(
                f"*{_format_duration(phase['duration_seconds'])} | "
                f"{phase['event_count']} events | "
                f"{phase['findings_count']} findings*"
            )
            lines.append("")

            if phase["tools_used"]:
                lines.append(f"**Tools:** {', '.join(phase['tools_used'])}")
                lines.append("")

            for entry in phase["events"]:
                timestamp = entry["timestamp"][:19]  # trim subseconds
                icon = _event_icon(entry["event_type"])
                line = f"- `{timestamp}` {icon} **{entry['event_type']}**"
                if entry.get("tool"):
                    line += f" `{entry['tool']}`"
                if entry.get("title"):
                    line += f" -- {entry['title']}"
                if entry.get("severity") and entry["severity"] not in ("none", "info"):
                    line += f" [{entry['severity'].upper()}]"
                lines.append(line)

            lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Return the structured timeline suitable for JSON serialization
        and attack graph visualization."""
        total_events = sum(p["event_count"] for p in self._phases)
        total_findings = sum(p["findings_count"] for p in self._phases)

        if self._phases:
            mission_start = self._phases[0]["start"]
            mission_end = self._phases[-1]["end"]
        else:
            now = datetime.utcnow().isoformat()
            mission_start = now
            mission_end = now

        return {
            "mission_start": mission_start,
            "mission_end": mission_end,
            "total_events": total_events,
            "total_findings": total_findings,
            "phase_count": len(self._phases),
            "phases": self._phases,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _event_to_entry(event: Event) -> dict[str, Any]:
        """Convert a single Event to a lightweight timeline entry."""
        entry: dict[str, Any] = {
            "id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type.value,
            "turn": event.turn,
        }
        if event.tool_name:
            entry["tool"] = event.tool_name
        if event.title:
            entry["title"] = event.title
        if event.severity and event.severity != Severity.NONE:
            entry["severity"] = event.severity.value
        if event.target:
            entry["target"] = event.target
        if event.reasoning:
            entry["reasoning"] = event.reasoning
        return entry


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _format_duration(seconds: float) -> str:
    """Human-readable duration string."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f}m"
    hours = minutes / 60
    return f"{hours:.1f}h"


def _event_icon(event_type: str) -> str:
    """Return a text marker for the event type (no emojis per conventions)."""
    icons: dict[str, str] = {
        "tool_invoked": "[>]",
        "tool_completed": "[+]",
        "tool_failed": "[!]",
        "finding_discovered": "[F]",
        "finding_confirmed": "[F!]",
        "finding_false_positive": "[FP]",
        "decision": "[D]",
        "pivot": "[P]",
        "hypothesis": "[H]",
        "stall_detected": "[S]",
        "phase_transition": "[>>]",
        "scope_check": "[SC]",
        "session_start": "[SS]",
        "session_end": "[SE]",
        "dynamic_tool_created": "[DT]",
    }
    return icons.get(event_type, "[-]")
