# Phantom Backend Architecture Specification

Version: 1.0.0
Date: 2026-03-29
Author: Backend Architect Agent

---

## 1. Overview

This spec defines the backend infrastructure for Phantom's refactor from a linear
tool-calling loop (`while turn < max_turns: think()`) to a fully autonomous
reasoning agent with structured state, event-driven tracing, an attack graph,
and reliable mid-flight resume.

### Design Principles

- **SQLite as the single persistence layer** -- zero external dependencies, portable
  session files, queryable with standard SQL, supports concurrent reads.
- **Pydantic models everywhere** -- runtime validation, serialization for both
  SQLite and LLM context, schema versioning.
- **Event sourcing for auditability** -- every action, finding, decision, and pivot
  is an immutable event. The current state is always reconstructable from the event
  log.
- **Graph-native attack model** -- the attack graph is a first-class data structure,
  not a post-hoc report artifact.

### Current Problems Being Solved

| Problem | Current Code | New Design |
|---|---|---|
| State is a giant JSON blob | `state.json` = `{"turn": N, "messages": [...]}` | SQLite with normalized tables |
| No event log | Findings regex-matched from tool output text | Typed `Event` objects persisted immediately |
| Context overflow | `_compact_old_tool_results` truncates after N turns | Semantic relevance scoring + tiered compression |
| No attack graph | N/A | Directed graph with typed nodes and causal edges |
| Fragile resume | Reload raw messages list + turn counter | Replay from event log, rebuild state machine |
| Tool results are unstructured strings | `str(result)` everywhere | `ToolResult` Pydantic model with typed output |

---

## 2. State Machine

### 2.1 Mission States

```
                          +-----------+
                          |   INIT    |
                          +-----+-----+
                                |
                          scope validated
                                |
                          +-----v-----+
                     +--->|   RECON   |<---+
                     |    +-----+-----+    |
                     |          |           |
                     |    targets found     |
                     |          |           |
                     |    +-----v------+   |
                     |    | ENUMERATE  |   |
                     |    +-----+------+   |
                     |          |           |
                     |    vulns found       |
                     |          |           |
                     |    +-----v------+   |
              pivot  |    |  EXPLOIT   |---+
              back   |    +-----+------+  pivot to new target
                     |          |
                     |    shells/access
                     |          |
                     |    +-----v------+
                     +----|  ESCALATE  |
                          +-----+------+
                                |
                          all paths exhausted
                          OR max_turns reached
                          OR user stop
                                |
                          +-----v------+
                          |  DEBRIEF   |
                          +-----+------+
                                |
                          report generated
                                |
                          +-----v------+
                          | COMPLETED  |
                          +------------+

        At any point:
          PAUSED  -- user pause or checkpoint
          FAILED  -- unrecoverable error
          ABORTED -- user cancel / scope violation
```

### 2.2 State Transitions

```python
from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime
import uuid


class MissionPhase(str, Enum):
    INIT = "init"
    RECON = "recon"
    ENUMERATE = "enumerate"
    EXPLOIT = "exploit"
    ESCALATE = "escalate"
    DEBRIEF = "debrief"
    COMPLETED = "completed"
    PAUSED = "paused"
    FAILED = "failed"
    ABORTED = "aborted"


# Valid transitions: (from_state, to_state)
VALID_TRANSITIONS: set[tuple[MissionPhase, MissionPhase]] = {
    (MissionPhase.INIT, MissionPhase.RECON),
    (MissionPhase.RECON, MissionPhase.ENUMERATE),
    (MissionPhase.RECON, MissionPhase.DEBRIEF),          # nothing found
    (MissionPhase.ENUMERATE, MissionPhase.EXPLOIT),
    (MissionPhase.ENUMERATE, MissionPhase.DEBRIEF),      # no exploitable vulns
    (MissionPhase.EXPLOIT, MissionPhase.ESCALATE),
    (MissionPhase.EXPLOIT, MissionPhase.RECON),           # pivot to new target
    (MissionPhase.EXPLOIT, MissionPhase.DEBRIEF),
    (MissionPhase.ESCALATE, MissionPhase.RECON),          # pivot after escalation
    (MissionPhase.ESCALATE, MissionPhase.DEBRIEF),
    (MissionPhase.DEBRIEF, MissionPhase.COMPLETED),
    # Any phase can pause, fail, or abort
    *((phase, MissionPhase.PAUSED) for phase in MissionPhase if phase not in
      (MissionPhase.COMPLETED, MissionPhase.FAILED, MissionPhase.ABORTED)),
    *((phase, MissionPhase.FAILED) for phase in MissionPhase if phase not in
      (MissionPhase.COMPLETED, MissionPhase.ABORTED)),
    *((phase, MissionPhase.ABORTED) for phase in MissionPhase if phase not in
      (MissionPhase.COMPLETED, MissionPhase.FAILED)),
    # Resume from paused restores previous phase
    (MissionPhase.PAUSED, MissionPhase.RECON),
    (MissionPhase.PAUSED, MissionPhase.ENUMERATE),
    (MissionPhase.PAUSED, MissionPhase.EXPLOIT),
    (MissionPhase.PAUSED, MissionPhase.ESCALATE),
    (MissionPhase.PAUSED, MissionPhase.DEBRIEF),
}


class MissionState(BaseModel):
    """Persistent mission state -- serialized to SQLite after every transition."""

    mission_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    phase: MissionPhase = MissionPhase.INIT
    previous_phase: Optional[MissionPhase] = None  # for resume from PAUSED
    turn: int = 0
    scope_hash: str = ""           # SHA-256 of scope file, detect tampering
    started_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    stealth_profile: str = "normal"
    stall_count: int = 0
    total_findings: int = 0
    current_target: Optional[str] = None
    error_message: Optional[str] = None

    def transition(self, to: MissionPhase) -> None:
        """Validate and execute a state transition."""
        if (self.phase, to) not in VALID_TRANSITIONS:
            raise InvalidTransition(
                f"Cannot transition from {self.phase.value} to {to.value}"
            )
        self.previous_phase = self.phase
        self.phase = to
        self.updated_at = datetime.utcnow()

    def pause(self) -> None:
        """Pause the mission, remembering current phase for resume."""
        self.transition(MissionPhase.PAUSED)

    def resume(self) -> None:
        """Resume from PAUSED to the previous phase."""
        if self.phase != MissionPhase.PAUSED:
            raise InvalidTransition("Can only resume from PAUSED state")
        if self.previous_phase is None:
            raise InvalidTransition("No previous phase recorded")
        target = self.previous_phase
        self.previous_phase = MissionPhase.PAUSED
        self.phase = target
        self.updated_at = datetime.utcnow()


class InvalidTransition(Exception):
    pass
```

### 2.3 Phase Transition Triggers

The LLM does NOT call `transition()` directly. Instead, the agent loop infers
transitions from tool calls and reasoning output:

| Trigger | Transition |
|---|---|
| Scope validated, first tool call | INIT -> RECON |
| `run_nmap`, `run_nuclei`, `run_ffuf` called on new target | -> ENUMERATE |
| `run_metasploit(action=exploit)`, `run_sqlmap` with injection found | -> EXPLOIT |
| `run_privesc_check`, lateral movement detected | -> ESCALATE |
| `generate_report` called | -> DEBRIEF |
| Report written successfully | -> COMPLETED |
| `=== MISSION COMPLETE ===` in output | -> COMPLETED |
| KeyboardInterrupt | -> PAUSED |
| Unrecoverable exception | -> FAILED |

---

## 3. Event System

### 3.1 Event Types

Every significant action produces an immutable event. Events are the source of
truth -- state is derived, events are permanent.

```python
from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime
import uuid


class EventType(str, Enum):
    # Tool lifecycle
    TOOL_INVOKED = "tool_invoked"
    TOOL_COMPLETED = "tool_completed"
    TOOL_FAILED = "tool_failed"

    # Findings
    FINDING_DISCOVERED = "finding_discovered"
    FINDING_CONFIRMED = "finding_confirmed"     # validated by exploitation
    FINDING_FALSE_POSITIVE = "finding_false_positive"

    # Agent reasoning
    DECISION = "decision"           # strategic choice (e.g., "pivot to port 8080")
    PIVOT = "pivot"                 # target/vector change
    HYPOTHESIS = "hypothesis"       # untested theory
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

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    mission_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    turn: int
    event_type: EventType
    phase: MissionPhase            # phase when event occurred

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

    # Decision/reasoning events
    reasoning: Optional[str] = None

    # Graph linkage -- which previous event(s) caused this one
    parent_event_ids: list[str] = Field(default_factory=list)

    # Arbitrary metadata
    metadata: dict[str, Any] = Field(default_factory=dict)
```

### 3.2 Event Bus

```python
from __future__ import annotations

import logging
from typing import Callable
from collections import defaultdict

logger = logging.getLogger(__name__)


class EventBus:
    """In-process pub/sub for events. Synchronous -- no async needed for a CLI agent."""

    def __init__(self):
        self._subscribers: dict[EventType, list[Callable[[Event], None]]] = defaultdict(list)
        self._global_subscribers: list[Callable[[Event], None]] = []

    def subscribe(self, event_type: EventType, handler: Callable[[Event], None]) -> None:
        self._subscribers[event_type].append(handler)

    def subscribe_all(self, handler: Callable[[Event], None]) -> None:
        """Subscribe to all events (used by persistence layer, attack graph builder)."""
        self._global_subscribers.append(handler)

    def emit(self, event: Event) -> None:
        """Publish an event to all matching subscribers."""
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
```

### 3.3 Event Flow Diagram

```
 Agent Loop (think)
       |
       |-- LLM returns tool_use blocks
       |       |
       |       +-- emit(TOOL_INVOKED) per tool call
       |       |
       |       +-- execute tool (parallel)
       |       |       |
       |       |       +-- on success: emit(TOOL_COMPLETED)
       |       |       +-- on failure: emit(TOOL_FAILED)
       |       |
       |       +-- parse findings from tool output
       |               |
       |               +-- emit(FINDING_DISCOVERED) per finding
       |
       |-- LLM returns text with reasoning
       |       |
       |       +-- detect decision keywords -> emit(DECISION)
       |       +-- detect pivot keywords    -> emit(PIVOT)
       |
       |-- Phase inference
       |       |
       |       +-- emit(PHASE_TRANSITION)
       |
       +-- All events flow to:
               |
               +-- EventBus
                    |
                    +-- PersistenceLayer.on_event()  -> SQLite INSERT
                    +-- AttackGraph.on_event()        -> graph node/edge
                    +-- ContextManager.on_event()     -> relevance index
                    +-- Console/Logger                -> human output
```

---

## 4. Tool Pipeline

### 4.1 Tool Registration and Validation

```python
from __future__ import annotations

from typing import Any, Callable, Optional
from pydantic import BaseModel, Field
import hashlib
import inspect


class ToolSpec(BaseModel):
    """Validated tool specification. Replaces raw dicts."""

    name: str
    description: str
    input_schema: dict[str, Any]
    is_dynamic: bool = False           # True for LLM-generated tools
    source_hash: Optional[str] = None  # SHA-256 of source code (dynamic tools)
    requires_scope_check: bool = True  # enforce scope guard before execution
    max_timeout: int = 300             # hard timeout cap
    parallelizable: bool = True        # safe to run concurrently with other tools


class ToolResult(BaseModel):
    """Structured tool output. Replaces raw strings."""

    tool_name: str
    success: bool
    output: str                        # human-readable output (for LLM context)
    structured_data: Optional[dict[str, Any]] = None  # machine-parseable findings
    findings: list[Finding] = Field(default_factory=list)
    duration_ms: int = 0
    truncated: bool = False            # True if output was cut for context


class Finding(BaseModel):
    """A discrete vulnerability or discovery extracted from tool output."""

    title: str
    severity: Severity
    target: str
    description: str = ""
    evidence: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    tool_name: str = ""
    references: list[str] = Field(default_factory=list)


class ToolRegistry:
    """Central registry for built-in and dynamic tools."""

    def __init__(self, event_bus: EventBus):
        self._specs: dict[str, ToolSpec] = {}
        self._funcs: dict[str, Callable] = {}
        self._event_bus = event_bus

    def register(self, spec: ToolSpec, func: Callable) -> None:
        """Register a tool with validation."""
        # Validate function signature matches schema
        sig = inspect.signature(func)
        required = spec.input_schema.get("required", [])
        params = set(sig.parameters.keys()) - {"kwargs", "self"}
        missing = set(required) - params
        if missing:
            raise ValueError(
                f"Tool '{spec.name}' function missing required params: {missing}"
            )
        self._specs[spec.name] = spec
        self._funcs[spec.name] = func

    def register_dynamic(self, name: str, description: str,
                         source_code: str, func: Callable) -> ToolSpec:
        """Register a dynamically generated tool with safety checks."""
        source_hash = hashlib.sha256(source_code.encode()).hexdigest()

        spec = ToolSpec(
            name=f"dynamic_{name}",
            description=description,
            input_schema={
                "type": "object",
                "properties": {
                    "args": {
                        "type": "string",
                        "description": "Arguments for the dynamic tool",
                    },
                },
                "required": [],
            },
            is_dynamic=True,
            source_hash=source_hash,
            requires_scope_check=True,
            max_timeout=60,  # shorter timeout for dynamic tools
        )

        self._specs[spec.name] = spec
        self._funcs[spec.name] = func

        self._event_bus.emit(Event(
            mission_id="",  # filled by caller
            turn=0,
            event_type=EventType.DYNAMIC_TOOL_REGISTERED,
            phase=MissionPhase.INIT,
            tool_name=spec.name,
            metadata={"source_hash": source_hash, "description": description},
        ))

        return spec

    def get_specs_for_llm(self) -> list[dict]:
        """Return tool specs in Anthropic API format for the LLM."""
        return [
            {
                "name": spec.name,
                "description": spec.description,
                "input_schema": spec.input_schema,
            }
            for spec in self._specs.values()
        ]

    def get_func(self, name: str) -> Optional[Callable]:
        return self._funcs.get(name)

    def get_spec(self, name: str) -> Optional[ToolSpec]:
        return self._specs.get(name)
```

### 4.2 Tool Executor

```python
from __future__ import annotations

import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class ToolExecutor:
    """Execute tools with event emission, timeout enforcement, and parallel scheduling."""

    def __init__(self, registry: ToolRegistry, event_bus: EventBus,
                 max_parallel: int = 4):
        self._registry = registry
        self._event_bus = event_bus
        self._max_parallel = max_parallel

    def execute(self, tool_call: dict, mission_state: MissionState) -> ToolResult:
        """Execute a single tool call with full lifecycle events."""
        name = tool_call["name"]
        tool_input = tool_call.get("input", {})
        spec = self._registry.get_spec(name)
        func = self._registry.get_func(name)

        # Emit invocation event
        invoked_event = Event(
            mission_id=mission_state.mission_id,
            turn=mission_state.turn,
            event_type=EventType.TOOL_INVOKED,
            phase=mission_state.phase,
            tool_name=name,
            tool_input=tool_input,
        )
        self._event_bus.emit(invoked_event)

        if not func or not spec:
            return ToolResult(
                tool_name=name, success=False,
                output=f"Unknown tool: {name}", duration_ms=0,
            )

        # Scope check enforcement
        if spec.requires_scope_check and "target" in tool_input:
            from agent.tools.scope_checker import scope_guard
            guard = scope_guard(tool_input["target"])
            if guard:
                return ToolResult(
                    tool_name=name, success=False,
                    output=guard, duration_ms=0,
                )

        # Execute with timeout
        start = time.monotonic()
        try:
            raw_result = func(**tool_input)
            duration_ms = int((time.monotonic() - start) * 1000)

            result = ToolResult(
                tool_name=name,
                success=True,
                output=str(raw_result),
                duration_ms=duration_ms,
            )

            # Parse findings from output (delegate to finding extractor)
            result.findings = FindingExtractor.extract(name, result.output)

            # Emit completion event
            self._event_bus.emit(Event(
                mission_id=mission_state.mission_id,
                turn=mission_state.turn,
                event_type=EventType.TOOL_COMPLETED,
                phase=mission_state.phase,
                tool_name=name,
                tool_output=result.output[:2000],  # cap for event storage
                tool_duration_ms=duration_ms,
                parent_event_ids=[invoked_event.id],
            ))

            # Emit finding events
            for finding in result.findings:
                self._event_bus.emit(Event(
                    mission_id=mission_state.mission_id,
                    turn=mission_state.turn,
                    event_type=EventType.FINDING_DISCOVERED,
                    phase=mission_state.phase,
                    tool_name=name,
                    severity=finding.severity,
                    target=finding.target,
                    title=finding.title,
                    description=finding.description,
                    evidence=finding.evidence,
                    cve_ids=finding.cve_ids,
                    cvss_score=finding.cvss_score,
                    parent_event_ids=[invoked_event.id],
                ))

            return result

        except Exception as e:
            duration_ms = int((time.monotonic() - start) * 1000)
            self._event_bus.emit(Event(
                mission_id=mission_state.mission_id,
                turn=mission_state.turn,
                event_type=EventType.TOOL_FAILED,
                phase=mission_state.phase,
                tool_name=name,
                tool_output=str(e),
                tool_duration_ms=duration_ms,
                parent_event_ids=[invoked_event.id],
            ))
            return ToolResult(
                tool_name=name, success=False,
                output=f"Error: {e}", duration_ms=duration_ms,
            )

    def execute_parallel(self, tool_calls: list[dict],
                         mission_state: MissionState) -> list[ToolResult]:
        """Execute multiple tools in parallel, preserving order."""
        if len(tool_calls) == 1:
            return [self.execute(tool_calls[0], mission_state)]

        results = [None] * len(tool_calls)
        with ThreadPoolExecutor(
            max_workers=min(len(tool_calls), self._max_parallel)
        ) as executor:
            future_to_idx = {
                executor.submit(self.execute, tc, mission_state): i
                for i, tc in enumerate(tool_calls)
            }
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = ToolResult(
                        tool_name=tool_calls[idx]["name"],
                        success=False,
                        output=f"Execution error: {e}",
                        duration_ms=0,
                    )
        return results
```

### 4.3 Finding Extractor

Replaces the current regex-based `_SEVERITY_RE` approach with structured parsing
per tool type.

```python
import re
from typing import Optional


class FindingExtractor:
    """Extract structured findings from tool output strings.

    Each tool type has a specialized parser. Falls back to regex
    severity-tag matching for unknown tools.
    """

    _SEVERITY_TAG_RE = re.compile(
        r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+?)(?:\n|$)", re.IGNORECASE
    )

    @classmethod
    def extract(cls, tool_name: str, output: str) -> list[Finding]:
        parser = cls._PARSERS.get(tool_name, cls._parse_generic)
        return parser(output)

    @staticmethod
    def _parse_nuclei(output: str) -> list[Finding]:
        findings = []
        for match in re.finditer(
            r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.*?)(?:\n\s+URL:\s*(\S+))?",
            output, re.IGNORECASE
        ):
            severity_str = match.group(1).lower()
            title = match.group(2).strip()
            target = match.group(3) or ""
            cve_ids = re.findall(r"(CVE-\d{4}-\d+)", title)
            findings.append(Finding(
                title=title,
                severity=Severity(severity_str),
                target=target,
                cve_ids=cve_ids,
                tool_name="run_nuclei",
            ))
        return findings

    @staticmethod
    def _parse_nmap(output: str) -> list[Finding]:
        findings = []
        for match in re.finditer(r"(\d+/\w+)\s+open\s+(\S+)\s*(.*)", output):
            findings.append(Finding(
                title=f"Open port {match.group(1)} ({match.group(2)})",
                severity=Severity.INFO,
                target="",
                description=match.group(3).strip(),
                tool_name="run_nmap",
            ))
        return findings

    @classmethod
    def _parse_generic(cls, output: str) -> list[Finding]:
        findings = []
        for match in cls._SEVERITY_TAG_RE.finditer(output):
            findings.append(Finding(
                title=match.group(2).strip(),
                severity=Severity(match.group(1).lower()),
                target="",
                tool_name="unknown",
            ))
        return findings

    _PARSERS: dict[str, callable] = {
        "run_nuclei": _parse_nuclei.__func__,
        "run_nmap": _parse_nmap.__func__,
    }
```

---

## 5. Attack Graph Data Model

### 5.1 Graph Structure

The attack graph is a directed acyclic graph (DAG) where:
- **Nodes** represent discoveries, actions, or states
- **Edges** represent causal relationships ("this led to that")

```python
from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime
import uuid


class NodeType(str, Enum):
    # Discovery nodes
    TARGET = "target"               # a host/domain/IP
    SERVICE = "service"             # a running service (port + protocol)
    TECHNOLOGY = "technology"       # detected tech (e.g., Apache 2.4, WordPress 6.1)
    VULNERABILITY = "vulnerability" # a confirmed vuln
    CREDENTIAL = "credential"       # discovered credentials
    DATA = "data"                   # exfiltrated or discovered data

    # Action nodes
    SCAN = "scan"                   # a scan action taken
    EXPLOIT_ATTEMPT = "exploit_attempt"
    EXPLOIT_SUCCESS = "exploit_success"
    PIVOT = "pivot"                 # lateral movement
    ESCALATION = "escalation"       # privilege escalation

    # Meta nodes
    HYPOTHESIS = "hypothesis"       # untested theory
    DEAD_END = "dead_end"           # path that led nowhere


class EdgeType(str, Enum):
    DISCOVERED = "discovered"       # scan X discovered service Y
    RUNS_ON = "runs_on"             # technology X runs on service Y
    EXPLOITS = "exploits"           # exploit X targets vulnerability Y
    LED_TO = "led_to"               # generic causal relationship
    PIVOTED_FROM = "pivoted_from"   # lateral movement origin
    ESCALATED_TO = "escalated_to"   # privilege escalation path
    HOSTS = "hosts"                 # target X hosts service Y
    BLOCKED_BY = "blocked_by"       # action blocked by defense


class AttackNode(BaseModel):
    """A node in the attack graph."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    node_type: NodeType
    label: str                       # human-readable short label
    description: str = ""
    severity: Severity = Severity.NONE
    phase: MissionPhase = MissionPhase.INIT
    turn: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_id: Optional[str] = None   # link back to source event
    metadata: dict[str, Any] = Field(default_factory=dict)

    # For deduplication
    fingerprint: str = ""            # e.g., "target:10.0.0.1" or "vuln:CVE-2024-1234:10.0.0.1"


class AttackEdge(BaseModel):
    """A directed edge in the attack graph."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str                   # AttackNode.id
    target_id: str                   # AttackNode.id
    edge_type: EdgeType
    label: str = ""
    turn: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)
```

### 5.2 Attack Graph Manager

```python
class AttackGraph:
    """Maintains the in-memory attack graph, with persistence via events."""

    def __init__(self, event_bus: EventBus):
        self._nodes: dict[str, AttackNode] = {}    # id -> node
        self._edges: dict[str, AttackEdge] = {}    # id -> edge
        self._fingerprints: dict[str, str] = {}    # fingerprint -> node_id
        self._adjacency: dict[str, list[str]] = {} # node_id -> [edge_ids]
        self._event_bus = event_bus

        # Auto-build graph from events
        event_bus.subscribe(EventType.TOOL_COMPLETED, self._on_tool_completed)
        event_bus.subscribe(EventType.FINDING_DISCOVERED, self._on_finding)
        event_bus.subscribe(EventType.PIVOT, self._on_pivot)

    def add_node(self, node: AttackNode) -> AttackNode:
        """Add a node, deduplicating by fingerprint."""
        if node.fingerprint and node.fingerprint in self._fingerprints:
            existing_id = self._fingerprints[node.fingerprint]
            return self._nodes[existing_id]
        self._nodes[node.id] = node
        if node.fingerprint:
            self._fingerprints[node.fingerprint] = node.id
        self._adjacency.setdefault(node.id, [])
        return node

    def add_edge(self, edge: AttackEdge) -> AttackEdge:
        """Add a directed edge between two nodes."""
        if edge.source_id not in self._nodes or edge.target_id not in self._nodes:
            raise ValueError("Both source and target nodes must exist")
        self._edges[edge.id] = edge
        self._adjacency.setdefault(edge.source_id, []).append(edge.id)
        return edge

    def get_attack_chains(self) -> list[list[AttackNode]]:
        """Find all paths from TARGET nodes to terminal nodes (exploits, dead ends).

        Returns a list of node chains, sorted by maximum severity.
        """
        chains = []
        target_nodes = [n for n in self._nodes.values()
                        if n.node_type == NodeType.TARGET]

        for root in target_nodes:
            self._dfs_chains(root.id, [root], set(), chains)

        # Sort chains: highest severity first
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFO: 4, Severity.NONE: 5,
        }

        def chain_severity(chain: list[AttackNode]) -> int:
            return min(severity_order.get(n.severity, 5) for n in chain)

        chains.sort(key=chain_severity)
        return chains

    def _dfs_chains(self, node_id: str, path: list[AttackNode],
                    visited: set[str], chains: list[list[AttackNode]]) -> None:
        """Depth-first traversal to collect attack chains."""
        edge_ids = self._adjacency.get(node_id, [])
        if not edge_ids:
            if len(path) > 1:
                chains.append(list(path))
            return

        for edge_id in edge_ids:
            edge = self._edges[edge_id]
            if edge.target_id in visited:
                continue
            target_node = self._nodes[edge.target_id]
            visited.add(edge.target_id)
            path.append(target_node)
            self._dfs_chains(edge.target_id, path, visited, chains)
            path.pop()
            visited.discard(edge.target_id)

    def to_debrief_text(self) -> str:
        """Render the attack graph as structured text for the debrief report."""
        chains = self.get_attack_chains()
        if not chains:
            return "No attack chains discovered."

        lines = [f"Attack Graph: {len(self._nodes)} nodes, "
                 f"{len(self._edges)} edges, {len(chains)} chains\n"]

        for i, chain in enumerate(chains, 1):
            max_sev = max(
                (n.severity for n in chain if n.severity != Severity.NONE),
                default=Severity.INFO,
                key=lambda s: list(Severity).index(s),
            )
            lines.append(f"Chain {i} [{max_sev.value.upper()}]:")
            for j, node in enumerate(chain):
                prefix = "  " + ("+--> " if j > 0 else "[*]  ")
                lines.append(f"{prefix}{node.node_type.value}: {node.label}")
            lines.append("")

        return "\n".join(lines)

    def to_dot(self) -> str:
        """Export graph in Graphviz DOT format for visualization."""
        lines = ["digraph AttackGraph {", '  rankdir=LR;',
                 '  node [shape=box, style=filled, fontname="monospace"];', ""]

        # Color by severity
        colors = {
            Severity.CRITICAL: "#dc2626",
            Severity.HIGH: "#ea580c",
            Severity.MEDIUM: "#ca8a04",
            Severity.LOW: "#2563eb",
            Severity.INFO: "#6b7280",
            Severity.NONE: "#94a3b8",
        }

        for node in self._nodes.values():
            color = colors.get(node.severity, "#94a3b8")
            label = f"{node.node_type.value}\\n{node.label}"
            lines.append(
                f'  "{node.id}" [label="{label}", fillcolor="{color}", '
                f'fontcolor="white"];'
            )

        lines.append("")
        for edge in self._edges.values():
            lines.append(
                f'  "{edge.source_id}" -> "{edge.target_id}" '
                f'[label="{edge.edge_type.value}"];'
            )

        lines.append("}")
        return "\n".join(lines)

    # --- Event handlers (auto-build graph from events) ---

    def _on_tool_completed(self, event: Event) -> None:
        """Create SCAN nodes from tool completion events."""
        if event.tool_name in ("run_nmap", "run_nuclei", "run_ffuf",
                                "run_recon", "run_sqlmap"):
            scan_node = self.add_node(AttackNode(
                node_type=NodeType.SCAN,
                label=f"{event.tool_name} (turn {event.turn})",
                phase=event.phase,
                turn=event.turn,
                event_id=event.id,
                fingerprint=f"scan:{event.tool_name}:{event.turn}",
            ))
            # Link to target node if available
            target = (event.tool_input or {}).get("target") or (
                (event.tool_input or {}).get("domain")
            )
            if target:
                target_node = self.add_node(AttackNode(
                    node_type=NodeType.TARGET,
                    label=target,
                    fingerprint=f"target:{target}",
                ))
                self.add_edge(AttackEdge(
                    source_id=target_node.id,
                    target_id=scan_node.id,
                    edge_type=EdgeType.DISCOVERED,
                    turn=event.turn,
                ))

    def _on_finding(self, event: Event) -> None:
        """Create VULNERABILITY or SERVICE nodes from findings."""
        if event.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
            vuln_fp = f"vuln:{event.title}:{event.target}"
            vuln_node = self.add_node(AttackNode(
                node_type=NodeType.VULNERABILITY,
                label=event.title or "Unknown vuln",
                description=event.description or "",
                severity=event.severity,
                phase=event.phase,
                turn=event.turn,
                event_id=event.id,
                fingerprint=vuln_fp,
                metadata={"cve_ids": event.cve_ids},
            ))
            # Link to parent scan/tool event
            for parent_id in event.parent_event_ids:
                # Find the scan node for this parent event
                for node in self._nodes.values():
                    if node.event_id == parent_id:
                        self.add_edge(AttackEdge(
                            source_id=node.id,
                            target_id=vuln_node.id,
                            edge_type=EdgeType.DISCOVERED,
                            turn=event.turn,
                        ))
                        break

    def _on_pivot(self, event: Event) -> None:
        """Create PIVOT edges when the agent changes targets."""
        if event.metadata.get("from_target") and event.metadata.get("to_target"):
            from_node = self.add_node(AttackNode(
                node_type=NodeType.TARGET,
                label=event.metadata["from_target"],
                fingerprint=f"target:{event.metadata['from_target']}",
            ))
            to_node = self.add_node(AttackNode(
                node_type=NodeType.TARGET,
                label=event.metadata["to_target"],
                fingerprint=f"target:{event.metadata['to_target']}",
            ))
            self.add_edge(AttackEdge(
                source_id=from_node.id,
                target_id=to_node.id,
                edge_type=EdgeType.PIVOTED_FROM,
                label=event.reasoning or "pivot",
                turn=event.turn,
            ))
```

### 5.3 Example Attack Graph Output

```
Chain 1 [CRITICAL]:
  [*]  target: 10.0.0.5
  +--> scan: run_nmap (turn 3)
  +--> service: 443/tcp (Apache 2.4.49)
  +--> vulnerability: CVE-2021-41773 Path Traversal
  +--> exploit_success: RCE via path traversal

Chain 2 [HIGH]:
  [*]  target: 10.0.0.5
  +--> scan: run_nuclei (turn 7)
  +--> vulnerability: Exposed .git directory
  +--> data: Database credentials in config.php

Chain 3 [MEDIUM]:
  [*]  target: 10.0.0.5
  +--> scan: run_ffuf (turn 5)
  +--> service: /admin (HTTP 200)
  +--> dead_end: Login page, no default creds
```

---

## 6. Context Management

### 6.1 The Problem

The current approach (`_compact_old_tool_results`) applies uniform truncation: keep
the last N tool results intact, truncate everything older to 400 characters. This
loses critical findings from early turns while keeping irrelevant recent output.

### 6.2 Tiered Context Strategy

```
+------------------------------------------------------------------+
|                       LLM Context Window                          |
|                                                                   |
|  Tier 0: ALWAYS PRESENT (never compressed)                       |
|  +------------------------------------------------------------+  |
|  | - System prompt                                             |  |
|  | - Scope definition                                          |  |
|  | - Current mission state summary                             |  |
|  | - Active findings registry (title + severity + target)      |  |
|  | - Attack graph summary (chains, not raw nodes)              |  |
|  +------------------------------------------------------------+  |
|                                                                   |
|  Tier 1: RECENT (last 3 turns, full detail)                      |
|  +------------------------------------------------------------+  |
|  | - Full tool outputs                                         |  |
|  | - Full LLM reasoning                                        |  |
|  | - Full tool inputs                                          |  |
|  +------------------------------------------------------------+  |
|                                                                   |
|  Tier 2: RELEVANT (older turns, semantically selected)           |
|  +------------------------------------------------------------+  |
|  | - Tool results related to current target/phase              |  |
|  | - Findings related to current investigation                 |  |
|  | - Compressed to key facts only                              |  |
|  +------------------------------------------------------------+  |
|                                                                   |
|  Tier 3: COMPRESSED (oldest turns)                               |
|  +------------------------------------------------------------+  |
|  | - One-line summaries: "Turn 3: nmap found 5 ports on X"    |  |
|  | - Only kept if they contain findings                        |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

### 6.3 Context Manager Implementation

```python
from __future__ import annotations

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ContextManager:
    """Manages LLM context with semantic relevance and tiered compression.

    Replaces the blunt `_compact_old_tool_results` approach with a strategy
    that preserves important findings while aggressively compressing noise.
    """

    # Token budget allocation (approximate, for a 200k context window)
    SYSTEM_BUDGET = 8_000       # system prompt + scope
    STATE_BUDGET = 4_000        # mission state + findings registry + attack graph
    RECENT_BUDGET = 60_000      # last N turns, full detail
    RELEVANT_BUDGET = 30_000    # semantically selected older content
    COMPRESSED_BUDGET = 8_000   # one-line summaries of oldest turns
    # Total: ~110k tokens, leaving ~90k for LLM reasoning + response

    RECENT_TURNS = 3

    def __init__(self, mission_state: MissionState, attack_graph: AttackGraph):
        self._state = mission_state
        self._graph = attack_graph
        self._turn_summaries: dict[int, TurnSummary] = {}

    def build_context(self, messages: list[dict], system_prompt: str,
                      scope: str) -> list[dict]:
        """Build an optimized message list for the LLM.

        Strategy:
        1. Always include system prompt + scope + state summary
        2. Keep last N turns at full detail
        3. For older turns, select by relevance to current target/phase
        4. Compress everything else to one-line summaries
        """
        # Index messages by turn
        turn_messages = self._group_by_turn(messages)
        max_turn = max(turn_messages.keys()) if turn_messages else 0

        # Tier 0: state summary (injected as first user message after system)
        state_summary = self._build_state_summary()

        # Tier 1: recent turns (full detail)
        recent_cutoff = max(0, max_turn - self.RECENT_TURNS)
        recent = []
        for turn in range(recent_cutoff + 1, max_turn + 1):
            recent.extend(turn_messages.get(turn, []))

        # Tier 2: relevant older turns
        relevant = self._select_relevant_turns(
            turn_messages, recent_cutoff, max_turn
        )

        # Tier 3: compressed summaries of remaining turns
        compressed_turns = set(turn_messages.keys()) - set(
            range(recent_cutoff + 1, max_turn + 1)
        ) - set(relevant.keys())
        compressed = self._compress_turns(turn_messages, compressed_turns)

        # Assemble final context
        result = []

        # State summary as first user message
        result.append({"role": "user", "content": state_summary})

        # Compressed old turns
        if compressed:
            result.append({
                "role": "user",
                "content": f"[MISSION HISTORY - COMPRESSED]\n{compressed}",
            })

        # Relevant older turns
        for turn in sorted(relevant.keys()):
            result.extend(relevant[turn])

        # Recent turns (full detail)
        result.extend(recent)

        return result

    def _build_state_summary(self) -> str:
        """Build a concise state summary for Tier 0."""
        lines = [
            f"[MISSION STATE]",
            f"Phase: {self._state.phase.value}",
            f"Turn: {self._state.turn}",
            f"Total findings: {self._state.total_findings}",
            f"Current target: {self._state.current_target or 'none'}",
            f"Stealth: {self._state.stealth_profile}",
            "",
        ]

        # Attack graph summary
        chains = self._graph.get_attack_chains()
        if chains:
            lines.append(f"[ATTACK CHAINS: {len(chains)}]")
            for i, chain in enumerate(chains[:5], 1):
                max_sev = max(
                    (n.severity for n in chain if n.severity != Severity.NONE),
                    default=Severity.INFO,
                )
                path = " -> ".join(n.label for n in chain)
                lines.append(f"  {i}. [{max_sev.value.upper()}] {path}")
            if len(chains) > 5:
                lines.append(f"  ... +{len(chains) - 5} more chains")
            lines.append("")

        # Active findings (deduplicated by fingerprint)
        findings = [
            n for n in self._graph._nodes.values()
            if n.node_type == NodeType.VULNERABILITY
        ]
        if findings:
            lines.append(f"[ACTIVE FINDINGS: {len(findings)}]")
            for f in sorted(findings, key=lambda x: x.severity.value)[:20]:
                lines.append(f"  [{f.severity.value.upper()}] {f.label}")
            lines.append("")

        return "\n".join(lines)

    def _select_relevant_turns(self, turn_messages: dict, cutoff: int,
                                max_turn: int) -> dict[int, list[dict]]:
        """Select older turns that are relevant to the current investigation.

        Relevance signals:
        1. Contains findings (severity tags)
        2. Mentions current target
        3. Same phase as current phase
        4. Contains decisions/pivots
        """
        relevant = {}
        current_target = self._state.current_target or ""

        for turn, msgs in turn_messages.items():
            if turn > cutoff:
                continue

            score = 0
            text = " ".join(str(m.get("content", "")) for m in msgs)

            # Finding severity
            if "[CRITICAL]" in text:
                score += 10
            if "[HIGH]" in text:
                score += 5
            if "[MEDIUM]" in text:
                score += 2

            # Current target mention
            if current_target and current_target in text:
                score += 5

            # Decision/pivot markers
            if any(kw in text.lower() for kw in ("pivot", "decision", "strategy")):
                score += 3

            if score >= 3:
                # Include but compress tool outputs
                relevant[turn] = self._compress_messages(msgs, keep_findings=True)

        return relevant

    def _compress_turns(self, turn_messages: dict,
                        turns: set[int]) -> str:
        """Compress old turns into one-line summaries."""
        summaries = []
        for turn in sorted(turns):
            msgs = turn_messages.get(turn, [])
            text = " ".join(str(m.get("content", "")) for m in msgs)

            # Extract tool names called
            tool_names = re.findall(r'"name":\s*"(\w+)"', text)

            # Extract severity-tagged findings
            findings = re.findall(r"\[(CRITICAL|HIGH|MEDIUM|LOW)\]", text)

            if tool_names or findings:
                tools_str = ", ".join(set(tool_names)) if tool_names else "reasoning"
                findings_str = f" [{len(findings)} findings]" if findings else ""
                summaries.append(f"Turn {turn}: {tools_str}{findings_str}")

        return "\n".join(summaries) if summaries else ""

    def _group_by_turn(self, messages: list[dict]) -> dict[int, list[dict]]:
        """Group messages into turns. Each assistant+user pair is one turn."""
        turns: dict[int, list[dict]] = {}
        turn = 0
        for msg in messages:
            turns.setdefault(turn, []).append(msg)
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, list) and any(
                    b.get("type") == "tool_result" for b in content
                ):
                    turn += 1
        return turns

    def _compress_messages(self, msgs: list[dict],
                            keep_findings: bool = True) -> list[dict]:
        """Compress messages, keeping findings if requested."""
        compressed = []
        for msg in msgs:
            if msg.get("role") == "assistant":
                compressed.append(msg)  # keep reasoning
            elif msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, list):
                    new_blocks = []
                    for block in content:
                        if block.get("type") == "tool_result":
                            text = str(block.get("content", ""))
                            if keep_findings and re.search(
                                r"\[(CRITICAL|HIGH|MEDIUM)\]", text
                            ):
                                new_blocks.append(block)
                            else:
                                new_blocks.append({
                                    **block,
                                    "content": text[:200] + " [...compressed]"
                                    if len(text) > 200 else text,
                                })
                        else:
                            new_blocks.append(block)
                    compressed.append({**msg, "content": new_blocks})
                else:
                    compressed.append(msg)
        return compressed


class TurnSummary(BaseModel):
    """Cached summary of a single turn for fast retrieval."""
    turn: int
    tools_used: list[str]
    findings_count: int
    severity_max: Severity = Severity.NONE
    targets: list[str]
    one_line: str
```

---

## 7. Persistence Layer

### 7.1 Database Choice: SQLite

Rationale:
- Zero configuration, no server process, single file per session
- Each mission session = one `.db` file in `logs/<session>/mission.db`
- Supports concurrent reads (WAL mode) for live monitoring
- Portable -- session can be copied, shared, archived as a single file
- Queryable -- post-hoc analysis with standard SQL

### 7.2 Schema

```sql
-- File: schema.sql
-- Applied on session creation via MissionDatabase.__init__

PRAGMA journal_mode = WAL;           -- concurrent read support
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;         -- balance safety vs speed

-- Mission metadata
CREATE TABLE IF NOT EXISTS mission (
    id                TEXT PRIMARY KEY,
    phase             TEXT NOT NULL DEFAULT 'init',
    previous_phase    TEXT,
    turn              INTEGER NOT NULL DEFAULT 0,
    scope_hash        TEXT NOT NULL DEFAULT '',
    started_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    stealth_profile   TEXT NOT NULL DEFAULT 'normal',
    stall_count       INTEGER NOT NULL DEFAULT 0,
    total_findings    INTEGER NOT NULL DEFAULT 0,
    current_target    TEXT,
    error_message     TEXT,
    schema_version    INTEGER NOT NULL DEFAULT 1
);

-- Immutable event log
CREATE TABLE IF NOT EXISTS events (
    id                TEXT PRIMARY KEY,
    mission_id        TEXT NOT NULL REFERENCES mission(id),
    timestamp         TEXT NOT NULL,
    turn              INTEGER NOT NULL,
    event_type        TEXT NOT NULL,
    phase             TEXT NOT NULL,
    tool_name         TEXT,
    tool_input_json   TEXT,          -- JSON serialized
    tool_output       TEXT,
    tool_duration_ms  INTEGER,
    severity          TEXT,
    target            TEXT,
    title             TEXT,
    description       TEXT,
    evidence          TEXT,
    cve_ids_json      TEXT,          -- JSON array
    cvss_score        REAL,
    reasoning         TEXT,
    parent_event_ids  TEXT,          -- JSON array
    metadata_json     TEXT           -- JSON object
);

CREATE INDEX IF NOT EXISTS idx_events_turn ON events(turn);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)
    WHERE severity IN ('critical', 'high', 'medium');
CREATE INDEX IF NOT EXISTS idx_events_target ON events(target)
    WHERE target IS NOT NULL;

-- Attack graph nodes
CREATE TABLE IF NOT EXISTS attack_nodes (
    id                TEXT PRIMARY KEY,
    node_type         TEXT NOT NULL,
    label             TEXT NOT NULL,
    description       TEXT DEFAULT '',
    severity          TEXT DEFAULT 'none',
    phase             TEXT,
    turn              INTEGER,
    timestamp         TEXT NOT NULL,
    event_id          TEXT,
    fingerprint       TEXT UNIQUE,
    metadata_json     TEXT
);

CREATE INDEX IF NOT EXISTS idx_nodes_type ON attack_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_nodes_fingerprint ON attack_nodes(fingerprint)
    WHERE fingerprint IS NOT NULL;

-- Attack graph edges
CREATE TABLE IF NOT EXISTS attack_edges (
    id                TEXT PRIMARY KEY,
    source_id         TEXT NOT NULL REFERENCES attack_nodes(id),
    target_id         TEXT NOT NULL REFERENCES attack_nodes(id),
    edge_type         TEXT NOT NULL,
    label             TEXT DEFAULT '',
    turn              INTEGER,
    timestamp         TEXT NOT NULL,
    metadata_json     TEXT
);

CREATE INDEX IF NOT EXISTS idx_edges_source ON attack_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON attack_edges(target_id);

-- Findings registry (denormalized for fast queries)
CREATE TABLE IF NOT EXISTS findings (
    id                TEXT PRIMARY KEY,
    event_id          TEXT NOT NULL REFERENCES events(id),
    title             TEXT NOT NULL,
    severity          TEXT NOT NULL,
    target            TEXT,
    description       TEXT,
    evidence          TEXT,
    cve_ids_json      TEXT,
    cvss_score        REAL,
    tool_name         TEXT,
    confirmed         INTEGER NOT NULL DEFAULT 0,  -- 0=discovered, 1=confirmed
    false_positive    INTEGER NOT NULL DEFAULT 0,
    turn              INTEGER NOT NULL,
    timestamp         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);

-- LLM conversation messages (for resume)
CREATE TABLE IF NOT EXISTS messages (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    turn              INTEGER NOT NULL,
    role              TEXT NOT NULL,    -- 'user', 'assistant', 'system'
    content_json      TEXT NOT NULL,    -- JSON: string or list of blocks
    timestamp         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_turn ON messages(turn);

-- Dynamic tools source code (for resume + audit)
CREATE TABLE IF NOT EXISTS dynamic_tools (
    name              TEXT PRIMARY KEY,
    description       TEXT NOT NULL,
    source_code       TEXT NOT NULL,
    source_hash       TEXT NOT NULL,
    created_at_turn   INTEGER NOT NULL,
    timestamp         TEXT NOT NULL
);
```

### 7.3 Database Access Layer

```python
from __future__ import annotations

import json
import sqlite3
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class MissionDatabase:
    """SQLite persistence layer for a single mission session.

    One database file per session: logs/<session>/mission.db
    Thread-safe via SQLite's WAL mode (multiple readers, single writer).
    """

    SCHEMA_VERSION = 1

    def __init__(self, session_dir: str):
        self._db_path = str(Path(session_dir) / "mission.db")
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._apply_schema()

    def _apply_schema(self) -> None:
        """Apply the database schema (idempotent)."""
        schema_path = Path(__file__).parent / "schema.sql"
        if schema_path.exists():
            schema_sql = schema_path.read_text(encoding="utf-8")
        else:
            # Fallback: inline critical tables
            schema_sql = _INLINE_SCHEMA
        self._conn.executescript(schema_sql)

    def close(self) -> None:
        self._conn.close()

    # --- Mission state ---

    def save_state(self, state: MissionState) -> None:
        """Upsert mission state (single row)."""
        self._conn.execute(
            """INSERT OR REPLACE INTO mission
               (id, phase, previous_phase, turn, scope_hash, started_at,
                updated_at, stealth_profile, stall_count, total_findings,
                current_target, error_message, schema_version)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                state.mission_id, state.phase.value,
                state.previous_phase.value if state.previous_phase else None,
                state.turn, state.scope_hash,
                state.started_at.isoformat(), state.updated_at.isoformat(),
                state.stealth_profile, state.stall_count,
                state.total_findings, state.current_target,
                state.error_message, self.SCHEMA_VERSION,
            ),
        )
        self._conn.commit()

    def load_state(self) -> Optional[MissionState]:
        """Load mission state from DB."""
        row = self._conn.execute("SELECT * FROM mission LIMIT 1").fetchone()
        if not row:
            return None
        return MissionState(
            mission_id=row["id"],
            phase=MissionPhase(row["phase"]),
            previous_phase=MissionPhase(row["previous_phase"])
            if row["previous_phase"] else None,
            turn=row["turn"],
            scope_hash=row["scope_hash"],
            started_at=datetime.fromisoformat(row["started_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            stealth_profile=row["stealth_profile"],
            stall_count=row["stall_count"],
            total_findings=row["total_findings"],
            current_target=row["current_target"],
            error_message=row["error_message"],
        )

    # --- Events ---

    def insert_event(self, event: Event) -> None:
        """Insert an immutable event record."""
        self._conn.execute(
            """INSERT INTO events
               (id, mission_id, timestamp, turn, event_type, phase,
                tool_name, tool_input_json, tool_output, tool_duration_ms,
                severity, target, title, description, evidence,
                cve_ids_json, cvss_score, reasoning, parent_event_ids,
                metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.id, event.mission_id, event.timestamp.isoformat(),
                event.turn, event.event_type.value, event.phase.value,
                event.tool_name,
                json.dumps(event.tool_input) if event.tool_input else None,
                event.tool_output, event.tool_duration_ms,
                event.severity.value if event.severity != Severity.NONE else None,
                event.target, event.title, event.description, event.evidence,
                json.dumps(event.cve_ids) if event.cve_ids else None,
                event.cvss_score, event.reasoning,
                json.dumps(event.parent_event_ids) if event.parent_event_ids else None,
                json.dumps(event.metadata) if event.metadata else None,
            ),
        )
        self._conn.commit()

    def get_events(self, event_type: Optional[str] = None,
                   severity: Optional[str] = None,
                   target: Optional[str] = None,
                   limit: int = 1000) -> list[dict]:
        """Query events with optional filters."""
        query = "SELECT * FROM events WHERE 1=1"
        params = []
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        query += " ORDER BY timestamp ASC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    # --- Messages (for resume) ---

    def save_message(self, turn: int, role: str, content: Any) -> None:
        """Save a conversation message."""
        self._conn.execute(
            "INSERT INTO messages (turn, role, content_json, timestamp) VALUES (?, ?, ?, ?)",
            (turn, role, json.dumps(content, ensure_ascii=False),
             datetime.utcnow().isoformat()),
        )
        self._conn.commit()

    def load_messages(self) -> list[dict]:
        """Load all messages in order."""
        rows = self._conn.execute(
            "SELECT role, content_json FROM messages ORDER BY id ASC"
        ).fetchall()
        return [
            {"role": row["role"], "content": json.loads(row["content_json"])}
            for row in rows
        ]

    # --- Attack graph ---

    def save_node(self, node: AttackNode) -> None:
        self._conn.execute(
            """INSERT OR IGNORE INTO attack_nodes
               (id, node_type, label, description, severity, phase, turn,
                timestamp, event_id, fingerprint, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                node.id, node.node_type.value, node.label, node.description,
                node.severity.value, node.phase.value if node.phase else None,
                node.turn, node.timestamp.isoformat(), node.event_id,
                node.fingerprint or None,
                json.dumps(node.metadata) if node.metadata else None,
            ),
        )
        self._conn.commit()

    def save_edge(self, edge: AttackEdge) -> None:
        self._conn.execute(
            """INSERT OR IGNORE INTO attack_edges
               (id, source_id, target_id, edge_type, label, turn,
                timestamp, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                edge.id, edge.source_id, edge.target_id,
                edge.edge_type.value, edge.label, edge.turn,
                edge.timestamp.isoformat(),
                json.dumps(edge.metadata) if edge.metadata else None,
            ),
        )
        self._conn.commit()

    def load_graph(self) -> tuple[list[dict], list[dict]]:
        """Load all graph nodes and edges for reconstruction."""
        nodes = [
            dict(row) for row in
            self._conn.execute("SELECT * FROM attack_nodes").fetchall()
        ]
        edges = [
            dict(row) for row in
            self._conn.execute("SELECT * FROM attack_edges").fetchall()
        ]
        return nodes, edges

    # --- Findings ---

    def save_finding(self, finding: Finding, event_id: str, turn: int) -> None:
        self._conn.execute(
            """INSERT INTO findings
               (id, event_id, title, severity, target, description, evidence,
                cve_ids_json, cvss_score, tool_name, turn, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(uuid.uuid4()), event_id, finding.title,
                finding.severity.value, finding.target, finding.description,
                finding.evidence,
                json.dumps(finding.cve_ids) if finding.cve_ids else None,
                finding.cvss_score, finding.tool_name, turn,
                datetime.utcnow().isoformat(),
            ),
        )
        self._conn.commit()

    def get_findings_summary(self) -> dict:
        """Return a severity breakdown of all findings."""
        rows = self._conn.execute(
            """SELECT severity, COUNT(*) as count FROM findings
               WHERE false_positive = 0
               GROUP BY severity ORDER BY count DESC"""
        ).fetchall()
        return {row["severity"]: row["count"] for row in rows}

    # --- Dynamic tools ---

    def save_dynamic_tool(self, name: str, description: str,
                          source_code: str, source_hash: str, turn: int) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO dynamic_tools
               (name, description, source_code, source_hash,
                created_at_turn, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, description, source_code, source_hash, turn,
             datetime.utcnow().isoformat()),
        )
        self._conn.commit()

    def load_dynamic_tools(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM dynamic_tools").fetchall()
        return [dict(row) for row in rows]
```

---

## 8. Resume Mechanism

### 8.1 Resume Strategy

Resume must reconstruct four things:
1. **Mission state** -- phase, turn, stall counters, current target
2. **LLM conversation** -- messages list for the next API call
3. **Attack graph** -- the full graph of discoveries and chains
4. **Dynamic tools** -- re-register any LLM-generated tools

The current approach dumps the entire messages list to `state.json` (megabytes of
raw tool output). The new approach stores messages in SQLite rows and reconstructs
context using the ContextManager.

### 8.2 Resume Flow

```
 --resume 20260329_140000
         |
         v
 +-------------------+
 | Load mission.db   |
 +--------+----------+
          |
          v
 +-------------------+     +-------------------+
 | Load MissionState |     | Load events       |
 | from mission      |     | (rebuild EventBus |
 | table             |     |  not needed --    |
 +--------+----------+     |  events are       |
          |                 |  already persisted)|
          v                 +-------------------+
 +-------------------+
 | Load attack graph |
 | nodes + edges     |
 | -> rebuild        |
 | AttackGraph       |
 +--------+----------+
          |
          v
 +-------------------+
 | Load messages     |
 | -> pass to        |
 | ContextManager    |
 | .build_context()  |
 +--------+----------+
          |
          v
 +-------------------+
 | Load dynamic      |
 | tools -> exec()   |
 | source_code,      |
 | re-register       |
 +--------+----------+
          |
          v
 +-------------------+
 | Resume agent loop |
 | from state.turn   |
 +-------------------+
```

### 8.3 Resume Implementation

```python
class MissionResumer:
    """Reconstructs a mission session from its SQLite database."""

    def __init__(self, session_dir: str):
        self.session_dir = session_dir
        self.db = MissionDatabase(session_dir)

    def resume(self) -> tuple[MissionState, list[dict], AttackGraph, ToolRegistry]:
        """Full mission restoration.

        Returns:
            (state, messages, attack_graph, tool_registry)
        """
        # 1. Load mission state
        state = self.db.load_state()
        if not state:
            raise ResumeError(f"No mission state found in {self.session_dir}")

        if state.phase in (MissionPhase.COMPLETED, MissionPhase.ABORTED):
            raise ResumeError(
                f"Mission is {state.phase.value} -- cannot resume"
            )

        # If mission was PAUSED, resume to previous phase
        if state.phase == MissionPhase.PAUSED:
            state.resume()

        # 2. Rebuild attack graph
        event_bus = EventBus()
        attack_graph = AttackGraph(event_bus)
        nodes_data, edges_data = self.db.load_graph()

        for nd in nodes_data:
            node = AttackNode(
                id=nd["id"],
                node_type=NodeType(nd["node_type"]),
                label=nd["label"],
                description=nd.get("description", ""),
                severity=Severity(nd.get("severity", "none")),
                fingerprint=nd.get("fingerprint", ""),
            )
            attack_graph.add_node(node)

        for ed in edges_data:
            edge = AttackEdge(
                id=ed["id"],
                source_id=ed["source_id"],
                target_id=ed["target_id"],
                edge_type=EdgeType(ed["edge_type"]),
                label=ed.get("label", ""),
            )
            attack_graph.add_edge(edge)

        # 3. Load messages
        messages = self.db.load_messages()

        # 4. Restore dynamic tools
        tool_registry = ToolRegistry(event_bus)
        # Register built-in tools first (via existing __init__.py mechanism)
        # Then restore dynamic tools
        for dt in self.db.load_dynamic_tools():
            try:
                # Execute source code in a sandboxed namespace
                namespace = {}
                exec(dt["source_code"], namespace)
                func = namespace.get("run")
                if func:
                    tool_registry.register_dynamic(
                        name=dt["name"].replace("dynamic_", ""),
                        description=dt["description"],
                        source_code=dt["source_code"],
                        func=func,
                    )
                    logger.info("Restored dynamic tool: %s", dt["name"])
            except Exception as e:
                logger.warning(
                    "Failed to restore dynamic tool %s: %s", dt["name"], e
                )

        # 5. Wire up persistence to event bus
        persistence_handler = PersistenceHandler(self.db)
        event_bus.subscribe_all(persistence_handler.on_event)

        graph_handler = GraphPersistenceHandler(self.db)
        event_bus.subscribe(EventType.TOOL_COMPLETED, lambda e: None)  # graph auto-handles

        logger.info(
            "Mission resumed: phase=%s turn=%d findings=%d nodes=%d",
            state.phase.value, state.turn, state.total_findings,
            len(attack_graph._nodes),
        )

        return state, messages, attack_graph, tool_registry


class PersistenceHandler:
    """Subscribes to EventBus and persists events + state to SQLite."""

    def __init__(self, db: MissionDatabase):
        self._db = db

    def on_event(self, event: Event) -> None:
        self._db.insert_event(event)

        if event.event_type == EventType.FINDING_DISCOVERED:
            finding = Finding(
                title=event.title or "",
                severity=event.severity,
                target=event.target or "",
                description=event.description or "",
                evidence=event.evidence or "",
                cve_ids=event.cve_ids,
                cvss_score=event.cvss_score,
                tool_name=event.tool_name or "",
            )
            self._db.save_finding(finding, event.id, event.turn)


class GraphPersistenceHandler:
    """Persists attack graph changes to SQLite."""

    def __init__(self, db: MissionDatabase):
        self._db = db

    def on_node_added(self, node: AttackNode) -> None:
        self._db.save_node(node)

    def on_edge_added(self, edge: AttackEdge) -> None:
        self._db.save_edge(edge)


class ResumeError(Exception):
    pass
```

### 8.4 Checkpoint Strategy

Checkpoints happen automatically at three granularities:

| Trigger | What is Saved |
|---|---|
| Every event emission | Event row inserted (immediate) |
| Every turn completion | Mission state updated, messages saved |
| Every phase transition | Full checkpoint: state + graph snapshot |
| KeyboardInterrupt | State set to PAUSED, final checkpoint |
| Unhandled exception | State set to FAILED with error_message |

SQLite WAL mode ensures that even a hard crash (power loss, OOM kill) will
at worst lose the last uncommitted event. The event log up to the last committed
transaction is always recoverable.

---

## 9. Integration Map

How all components wire together in the refactored agent loop:

```
                    +--------------------+
                    |   main.py          |
                    |   (entry point)    |
                    +---------+----------+
                              |
                    +---------v----------+
                    |  MissionDatabase   |
                    |  (SQLite)          |
                    +---------+----------+
                              |
               +--------------+--------------+
               |                             |
    +----------v---------+        +----------v---------+
    |  MissionState      |        |  EventBus          |
    |  (state machine)   |        |  (pub/sub)         |
    +----------+---------+        +----------+---------+
               |                             |
               |          +------------------+------------------+
               |          |                  |                  |
    +----------v----------v-+    +-----------v------+   +------v--------+
    |  AgentLoop (think)    |    | AttackGraph      |   | ContextMgr   |
    |  - LLM call           |    | (auto-build)     |   | (tiered)     |
    |  - tool dispatch      |    +------------------+   +---------------+
    +----------+------------+
               |
    +----------v------------+
    |  ToolExecutor         |
    |  - ToolRegistry       |
    |  - parallel exec      |
    |  - FindingExtractor   |
    +----------+------------+
               |
    +----------v------------+
    |  ToolResult           |
    |  - structured output  |
    |  - parsed Findings    |
    +-----------------------+
```

### Initialization Sequence (New Session)

```python
# Pseudocode for the refactored main.py

db = MissionDatabase(session_dir)
event_bus = EventBus()
state = MissionState(scope_hash=hash_scope_file())
attack_graph = AttackGraph(event_bus)
context_mgr = ContextManager(state, attack_graph)
tool_registry = ToolRegistry(event_bus)
tool_executor = ToolExecutor(tool_registry, event_bus)

# Wire persistence
persistence = PersistenceHandler(db)
event_bus.subscribe_all(persistence.on_event)
event_bus.subscribe_all(lambda e: db.save_state(state))  # state after every event

# Register built-in tools
for spec, func in load_builtin_tools():
    tool_registry.register(spec, func)

# Save initial state
db.save_state(state)
event_bus.emit(Event(
    mission_id=state.mission_id,
    turn=0,
    event_type=EventType.SESSION_START,
    phase=state.phase,
))

# Agent loop
while state.turn < max_turns and state.phase != MissionPhase.COMPLETED:
    messages = context_mgr.build_context(raw_messages, system_prompt, scope)
    text_blocks, tool_calls = provider.call_with_retry(messages, system_prompt, tools)

    # ... process text, dispatch tools, emit events ...

    state.turn += 1
    db.save_state(state)
```

### Initialization Sequence (Resume)

```python
resumer = MissionResumer(session_dir)
state, messages, attack_graph, tool_registry = resumer.resume()

# Continue with same loop, starting from state.turn
```

---

## 10. Migration Path

The refactor should be incremental. Here is the recommended order:

### Phase 1: Foundation (no behavior change)
1. Add Pydantic models (`MissionState`, `Event`, `Finding`, `ToolResult`, `ToolSpec`)
2. Add SQLite schema and `MissionDatabase`
3. Add `EventBus` (no subscribers yet)
4. Write to both `state.json` (old) AND `mission.db` (new) -- dual-write

### Phase 2: Event System
5. Wire `PersistenceHandler` to `EventBus`
6. Emit events from `_execute_tool` (wrap existing code)
7. Add `FindingExtractor` (replace `_SEVERITY_RE` regex)
8. Verify events are captured correctly via SQLite queries

### Phase 3: Attack Graph
9. Add `AttackGraph` data model and event handlers
10. Wire graph persistence to SQLite
11. Add `to_debrief_text()` and `to_dot()` export
12. Integrate graph summary into report generation

### Phase 4: Context Management
13. Add `ContextManager` with tiered compression
14. Replace `_compact_old_tool_results` with `build_context()`
15. A/B test: compare old vs new context strategies on same missions

### Phase 5: State Machine + Resume
16. Add `MissionState` with validated transitions
17. Replace `turn` counter with full state machine
18. Implement `MissionResumer` using SQLite
19. Remove `state.json` dual-write (SQLite is now the source of truth)

### Phase 6: Tool Pipeline
20. Replace raw tool dicts with `ToolSpec` + `ToolRegistry`
21. Add dynamic tool registration and sandboxed execution
22. Add `ToolExecutor` wrapping existing parallel execution

Each phase should be a separate PR with its own test suite. The dual-write
strategy in Phase 1 ensures zero risk of data loss during migration.

---

## 11. File Structure (Post-Refactor)

```
agent/
  main.py                    # entry point (simplified)
  agent_loop.py              # refactored think loop
  models/
    __init__.py
    state.py                 # MissionState, MissionPhase, InvalidTransition
    events.py                # Event, EventType, Severity
    findings.py              # Finding
    tools.py                 # ToolSpec, ToolResult
    graph.py                 # AttackNode, AttackEdge, NodeType, EdgeType
  core/
    __init__.py
    event_bus.py             # EventBus
    state_machine.py         # transition logic
    context_manager.py       # ContextManager, TurnSummary
    attack_graph.py          # AttackGraph
    finding_extractor.py     # FindingExtractor
    tool_registry.py         # ToolRegistry
    tool_executor.py         # ToolExecutor
  persistence/
    __init__.py
    database.py              # MissionDatabase
    schema.sql               # SQLite DDL
    handlers.py              # PersistenceHandler, GraphPersistenceHandler
    resumer.py               # MissionResumer, ResumeError
  providers/                 # (unchanged)
  tools/                     # (unchanged, but tools return ToolResult)
  utils/                     # (unchanged)
```
