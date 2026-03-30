"""Event system: types, immutable records, and in-process pub/sub bus."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

import uuid

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    # Tool lifecycle
    TOOL_INVOKED = "tool_invoked"
    TOOL_COMPLETED = "tool_completed"
    TOOL_FAILED = "tool_failed"

    # Findings
    FINDING_DISCOVERED = "finding_discovered"
    FINDING_CONFIRMED = "finding_confirmed"
    FINDING_FALSE_POSITIVE = "finding_false_positive"

    # Agent reasoning
    DECISION = "decision"
    PIVOT = "pivot"
    HYPOTHESIS = "hypothesis"
    STALL_DETECTED = "stall_detected"

    # State
    PHASE_TRANSITION = "phase_transition"
    SCOPE_CHECK = "scope_check"
    RATE_LIMITED = "rate_limited"
    STEALTH_CHANGE = "stealth_change"

    # Session
    SESSION_START = "session_start"
    SESSION_PAUSE = "session_pause"
    SESSION_RESUME = "session_resume"
    SESSION_END = "session_end"

    # Dynamic tools
    DYNAMIC_TOOL_CREATED = "dynamic_tool_created"
    DYNAMIC_TOOL_REGISTERED = "dynamic_tool_registered"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


class Event(BaseModel):
    """Immutable event record. Never modified after creation."""

    model_config = {"frozen": True}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    mission_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    turn: int
    event_type: EventType
    phase: str  # MissionPhase value -- string to avoid circular import

    # Tool events
    tool_name: Optional[str] = None
    tool_input: Optional[dict[str, Any]] = None
    tool_output: Optional[str] = None
    tool_duration_ms: Optional[int] = None

    # Finding events
    severity: Severity = Severity.NONE
    target: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[str] = None
    cve_ids: list[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None

    # Decision / reasoning events
    reasoning: Optional[str] = None

    # Graph linkage -- which previous event(s) caused this one
    parent_event_ids: list[str] = Field(default_factory=list)

    # Arbitrary metadata
    metadata: dict[str, Any] = Field(default_factory=dict)


class EventBus:
    """In-process synchronous pub/sub for events."""

    def __init__(self) -> None:
        self._subscribers: dict[EventType, list[Callable[[Event], None]]] = defaultdict(list)
        self._global_subscribers: list[Callable[[Event], None]] = []

    def subscribe(self, event_type: EventType, handler: Callable[[Event], None]) -> None:
        self._subscribers[event_type].append(handler)

    def subscribe_all(self, handler: Callable[[Event], None]) -> None:
        self._global_subscribers.append(handler)

    def emit(self, event: Event) -> None:
        for handler in self._global_subscribers:
            try:
                handler(event)
            except Exception as e:
                logger.error("Global event handler failed: %s", e)

        for handler in self._subscribers.get(event.event_type, []):
            try:
                handler(event)
            except Exception as e:
                logger.error("Event handler for %s failed: %s", event.event_type, e)
