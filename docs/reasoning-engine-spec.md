# Phantom Reasoning Engine -- Technical Specification

Version: 1.0 | Date: 2026-03-29 | Status: Draft

---

## Problem Statement

Phantom v2.7.8 runs a linear agentic loop: the LLM picks a tool, executes it, reads the
result, picks the next tool. The system prompt hardcodes a phase-ordered kill chain
(`recon -> nmap -> whatweb -> nuclei -> ffuf -> exploit -> report`). This produces
predictable, scripted behavior. A real pentester does not work this way. A real pentester:

- Forms hypotheses ("this looks like a misconfigured Tomcat -- let me check for manager
  access before finishing the full port scan")
- Abandons dead-end approaches fast
- Writes custom scripts when no existing tool fits
- Maintains a mental model of the target that evolves with each finding
- Adapts depth of investigation to the significance of what was found

This spec defines the architecture that enables that behavior.

---

## Architecture Overview

```
+------------------------------------------------------------------+
|                        ReasoningEngine                            |
|                                                                   |
|  +------------------+    +-------------------+    +-----------+   |
|  |  PlanningLayer   |<-->| ReflectionLayer   |<-->| MemoryMgr |   |
|  |  (attack plans,  |    | (metacognition,   |    | (findings,|   |
|  |   hypotheses,    |    |  approach eval,   |    |  state,   |   |
|  |   prioritized    |    |  pivot decisions) |    |  context  |   |
|  |   action queue)  |    |                   |    |  window)  |   |
|  +--------+---------+    +--------+----------+    +-----+-----+   |
|           |                       |                      |        |
|           v                       v                      v        |
|  +------------------+    +-------------------+                    |
|  | DynamicToolForge |    |  ProviderAdapter  |                    |
|  | (script gen,     |    |  (capability-     |                    |
|  |  sandbox exec,   |    |   aware routing,  |                    |
|  |  result capture) |    |   graceful degrad)|                    |
|  +------------------+    +-------------------+                    |
+------------------------------------------------------------------+
         |                          |
         v                          v
  [Subprocess Sandbox]      [LLM Provider APIs]
```

The `ReasoningEngine` replaces the current `AgentClient.think()` method. It does not
replace `AgentClient` itself -- it composes into it.

---

## 1. Planning Layer

### 1.1 Core Data Structures

```python
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time
import uuid


class PlanStatus(Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ABANDONED = "abandoned"
    BLOCKED = "blocked"


class HypothesisConfidence(Enum):
    SPECULATIVE = "speculative"   # "maybe this is vulnerable"
    PROBABLE = "probable"         # "evidence suggests this"
    CONFIRMED = "confirmed"       # "exploitation proved it"
    DISPROVED = "disproved"       # "tested and not vulnerable"


@dataclass
class Hypothesis:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    statement: str = ""            # "Target runs Tomcat 9.0.30 with default manager creds"
    confidence: HypothesisConfidence = HypothesisConfidence.SPECULATIVE
    evidence_for: list[str] = field(default_factory=list)   # finding IDs that support it
    evidence_against: list[str] = field(default_factory=list)
    created_turn: int = 0
    last_updated_turn: int = 0


@dataclass
class AttackAction:
    """A single step in an attack plan."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    description: str = ""          # human-readable: "Nmap service scan on 10.0.0.1"
    tool_name: Optional[str] = None     # existing tool, or None if dynamic script
    tool_args: dict = field(default_factory=dict)
    script_code: Optional[str] = None   # Python code if dynamic tool
    depends_on: list[str] = field(default_factory=list)  # action IDs that must complete first
    status: str = "pending"        # pending | running | done | failed | skipped
    result_summary: str = ""
    priority: float = 0.0         # higher = more urgent


@dataclass
class AttackPlan:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    objective: str = ""            # "Gain access to admin panel on target.com"
    hypothesis: Optional[str] = None  # hypothesis ID this plan tests
    actions: list[AttackAction] = field(default_factory=list)
    status: PlanStatus = PlanStatus.ACTIVE
    priority: float = 0.0
    created_turn: int = 0
    abandoned_reason: str = ""


@dataclass
class AttackState:
    """The full cognitive state of the agent."""
    plans: list[AttackPlan] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    current_plan_id: Optional[str] = None
    turn: int = 0
    target_model: dict = field(default_factory=dict)  # structured understanding of target

    def active_plans(self) -> list[AttackPlan]:
        return [p for p in self.plans if p.status == PlanStatus.ACTIVE]

    def get_plan(self, plan_id: str) -> Optional[AttackPlan]:
        return next((p for p in self.plans if p.id == plan_id), None)

    def next_action(self) -> Optional[tuple[AttackPlan, AttackAction]]:
        """Return the highest-priority pending action across all active plans."""
        best = None
        for plan in sorted(self.active_plans(), key=lambda p: -p.priority):
            for action in plan.actions:
                if action.status == "pending":
                    deps_met = all(
                        any(a.id == dep and a.status == "done"
                            for p2 in self.plans for a in p2.actions)
                        for dep in action.depends_on
                    )
                    if deps_met:
                        if best is None or action.priority > best[1].priority:
                            best = (plan, action)
        return best
```

### 1.2 How Planning Works

The planning layer is NOT a separate LLM call. It is part of the agent's reasoning
within each turn. The system prompt instructs the LLM to output structured plan
updates alongside its tool calls.

Each turn, the LLM receives the current `AttackState` (serialized compactly) and
produces one of these planning actions embedded in its text response:

```
<plan_create objective="..." priority="0.8" hypothesis="h_abc123">
  <action tool="run_nmap" args='{"target":"10.0.0.1","scan_type":"service"}' priority="0.9"/>
  <action description="Check for Tomcat manager" tool="run_ffuf" args='{"target":"http://10.0.0.1:8080","wordlist":"tomcat-paths.txt"}' depends_on="prev" priority="0.85"/>
  <action description="Write custom script to test manager default creds" script="true" priority="0.8" depends_on="prev"/>
</plan_create>

<plan_update id="p_abc123">
  <action_status id="a_def456" status="done" summary="Found 3 open ports: 22, 80, 8080"/>
  <reprioritize priority="0.95"/>  <!-- bump priority based on findings -->
</plan_update>

<plan_abandon id="p_xyz789" reason="Tomcat not detected, hypothesis disproved"/>

<hypothesis_update id="h_abc123" confidence="probable" evidence="Port 8080 running Tomcat/9.0.30"/>
```

The `ReasoningEngine` parses these structured blocks from the LLM's text output, updates
`AttackState`, and strips them before displaying to the user.

### 1.3 Plan Lifecycle

```python
class PlanningLayer:
    """Manages attack plans, hypotheses, and action prioritization."""

    def __init__(self):
        self.state = AttackState()

    def inject_state_into_prompt(self, messages: list[dict]) -> list[dict]:
        """Add a compact state summary to the conversation context.

        This is injected as a system-adjacent user message so the LLM
        knows what plans exist, what has been tried, and what remains.
        """
        summary = self._serialize_state_compact()
        # Inject before the last user/tool_result message
        state_msg = {
            "role": "user",
            "content": f"[PHANTOM_STATE]\n{summary}\n[/PHANTOM_STATE]",
        }
        # Place it just before the final message so it's fresh in context
        return messages[:-1] + [state_msg] + messages[-1:]

    def _serialize_state_compact(self) -> str:
        """Produce a token-efficient summary of current attack state."""
        lines = []
        lines.append(f"Turn: {self.state.turn}")

        # Active hypotheses (skip disproved ones to save tokens)
        active_hyps = [h for h in self.state.hypotheses
                       if h.confidence != HypothesisConfidence.DISPROVED]
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
            for a in pending[:3]:  # show at most 3 pending actions
                lines.append(f"  -> {a.description or a.tool_name}")

        # Recent findings (last 10)
        if self.state.findings:
            lines.append(f"Findings: {len(self.state.findings)} total")
            for f in self.state.findings[-5:]:
                lines.append(f"  [{f.get('severity','?')}] {f.get('title','')[:80]}")

        # Target model
        if self.state.target_model:
            lines.append(f"Target model: {_compact_json(self.state.target_model)}")

        return "\n".join(lines)

    def parse_plan_actions(self, llm_text: str) -> str:
        """Parse structured plan commands from LLM output, update state,
        return cleaned text with plan blocks removed."""
        import re

        # Parse <plan_create> blocks
        for match in re.finditer(
            r'<plan_create\s+objective="([^"]+)"(?:\s+priority="([^"]*)")?'
            r'(?:\s+hypothesis="([^"]*)")?>(.*?)</plan_create>',
            llm_text, re.DOTALL
        ):
            objective = match.group(1)
            priority = float(match.group(2) or 0.5)
            hypothesis_id = match.group(3)
            actions_block = match.group(4)

            plan = AttackPlan(
                objective=objective,
                priority=priority,
                hypothesis=hypothesis_id,
                created_turn=self.state.turn,
            )

            prev_id = None
            for action_match in re.finditer(
                r'<action\s+(.*?)/>', actions_block, re.DOTALL
            ):
                attrs = _parse_attrs(action_match.group(1))
                action = AttackAction(
                    description=attrs.get("description", ""),
                    tool_name=attrs.get("tool") if attrs.get("tool") else None,
                    tool_args=_safe_json(attrs.get("args", "{}")),
                    script_code=None,  # filled in later if script="true"
                    priority=float(attrs.get("priority", 0.5)),
                )
                if attrs.get("depends_on") == "prev" and prev_id:
                    action.depends_on = [prev_id]
                elif attrs.get("depends_on"):
                    action.depends_on = attrs["depends_on"].split(",")
                plan.actions.append(action)
                prev_id = action.id

            self.state.plans.append(plan)

        # Parse <plan_abandon> blocks
        for match in re.finditer(
            r'<plan_abandon\s+id="([^"]+)"\s+reason="([^"]+)"\s*/?>',
            llm_text
        ):
            plan = self.state.get_plan(match.group(1))
            if plan:
                plan.status = PlanStatus.ABANDONED
                plan.abandoned_reason = match.group(2)

        # Parse <hypothesis_update> blocks
        for match in re.finditer(
            r'<hypothesis_update\s+id="([^"]+)"\s+confidence="([^"]+)"'
            r'(?:\s+evidence="([^"]*)")?\s*/?>',
            llm_text
        ):
            hyp = next((h for h in self.state.hypotheses
                        if h.id == match.group(1)), None)
            if hyp:
                hyp.confidence = HypothesisConfidence(match.group(2))
                if match.group(3):
                    hyp.evidence_for.append(match.group(3))
                hyp.last_updated_turn = self.state.turn

        # Strip all plan/hypothesis XML blocks from display text
        cleaned = re.sub(
            r'<(?:plan_create|plan_update|plan_abandon|hypothesis_update)\b.*?(?:/>|</\1>)',
            '', llm_text, flags=re.DOTALL
        ).strip()

        return cleaned


def _parse_attrs(attr_string: str) -> dict:
    """Parse XML-like attributes from a string."""
    import re
    return dict(re.findall(r'(\w+)="([^"]*)"', attr_string))


def _safe_json(s: str) -> dict:
    import json
    try:
        return json.loads(s) if s else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _compact_json(obj: dict) -> str:
    import json
    return json.dumps(obj, separators=(",", ":"))
```

### 1.4 Plan Creation Triggers

The LLM creates plans when:

1. **Initial reconnaissance reveals the attack surface** -- e.g., after nmap + whatweb
   results arrive, create plans per technology stack discovered.
2. **A finding suggests a new attack vector** -- e.g., SQLi parameter found -> create a
   plan to exploit it with sqlmap + custom verification.
3. **A hypothesis forms** -- e.g., "this service might be running a vulnerable version" ->
   plan to verify.
4. **The reflection layer suggests pivoting** -- e.g., current approach is stalled, create
   a plan for an alternative vector.

Plans are abandoned when:

1. The hypothesis they test is disproved.
2. All actions fail or return nothing useful.
3. A higher-priority plan supersedes them.
4. The reflection layer decides diminishing returns.

---

## 2. Reflection / Metacognition Layer

### 2.1 Design

The reflection layer runs every N turns (configurable, default 3) and at critical
decision points. It is implemented as a **structured self-evaluation injected into
the LLM prompt**, not a separate LLM call (to save tokens and latency).

```python
class ReflectionLayer:
    """Metacognitive evaluation of agent performance and approach effectiveness."""

    def __init__(self, reflect_every: int = 3):
        self.reflect_every = reflect_every
        self._last_reflect_turn = 0

    def should_reflect(self, state: AttackState) -> bool:
        """Determine if reflection is needed this turn."""
        turns_since = state.turn - self._last_reflect_turn

        # Periodic reflection
        if turns_since >= self.reflect_every:
            return True

        # Trigger-based reflection
        # After a significant finding (CRITICAL/HIGH)
        if state.findings and state.findings[-1].get("severity") in ("CRITICAL", "HIGH"):
            return True

        # After a plan is abandoned
        if any(p.status == PlanStatus.ABANDONED
               and p.created_turn > self._last_reflect_turn
               for p in state.plans):
            return True

        # After 2+ consecutive action failures
        recent_actions = []
        for plan in state.active_plans():
            recent_actions.extend(
                a for a in plan.actions
                if a.status == "failed"
            )
        if len(recent_actions) >= 2:
            return True

        return False

    def build_reflection_prompt(self, state: AttackState) -> str:
        """Build the metacognitive reflection prompt.

        This is appended to the system prompt on reflection turns.
        The LLM produces a <reflection> block in its output.
        """
        self._last_reflect_turn = state.turn

        active_plans = state.active_plans()
        completed = [p for p in state.plans if p.status == PlanStatus.COMPLETED]
        abandoned = [p for p in state.plans if p.status == PlanStatus.ABANDONED]

        # Compute efficiency metrics
        total_actions = sum(len(p.actions) for p in state.plans)
        done_actions = sum(
            1 for p in state.plans for a in p.actions if a.status == "done"
        )
        failed_actions = sum(
            1 for p in state.plans for a in p.actions if a.status == "failed"
        )

        return f"""
[REFLECTION REQUIRED]
Before choosing your next action, evaluate your approach:

Metrics:
- Turn {state.turn} | Plans: {len(active_plans)} active, {len(completed)} completed, {len(abandoned)} abandoned
- Actions: {done_actions}/{total_actions} done, {failed_actions} failed
- Findings: {len(state.findings)} total

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

    def parse_reflection(self, llm_text: str) -> dict | None:
        """Extract and parse the reflection block from LLM output."""
        import re
        match = re.search(r'<reflection>(.*?)</reflection>', llm_text, re.DOTALL)
        if not match:
            return None

        block = match.group(1)
        reflection = {}
        for line in block.strip().splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                reflection[key.strip()] = value.strip()

        return reflection

    def apply_reflection(self, reflection: dict, state: AttackState) -> list[str]:
        """Translate reflection decisions into concrete state changes.

        Returns a list of action descriptions for logging.
        """
        actions_taken = []

        decision = reflection.get("decision", "continue")

        if decision == "pivot":
            # Demote all active plans to low priority
            for plan in state.active_plans():
                plan.priority = max(0.1, plan.priority - 0.3)
            actions_taken.append("Deprioritized all active plans for pivot")

        if decision == "escalate":
            # Mark that human input is needed
            actions_taken.append("Flagged for human input escalation")

        if reflection.get("approach_effective") == "no":
            # Increment stall indicators -- the planning layer will react
            actions_taken.append("Approach marked ineffective -- plans will be reassessed")

        return actions_taken
```

### 2.2 Reflection Triggers Summary

| Trigger | When | Purpose |
|---|---|---|
| Periodic | Every 3 turns (configurable) | Regular self-assessment |
| Critical finding | CRITICAL or HIGH severity detected | Decide whether to chain exploit or continue scanning |
| Plan abandoned | A plan was just abandoned | Reassess overall strategy |
| Consecutive failures | 2+ actions failed in a row | Detect broken approach |
| Context pressure | Estimated tokens > 60% of window | Force summarization and plan pruning |

---

## 3. Dynamic Tool Generation (Core Feature)

### 3.1 Design Principles

1. The LLM writes Python code in a `<script>` block within its response.
2. The code executes in a sandboxed subprocess with strict constraints.
3. Results flow back into the conversation as a tool result.
4. Scripts have access to a curated standard library and `requests`, but NO access to
   the agent's own internals, API keys, or the filesystem outside the session directory.

### 3.2 Sandbox Architecture

```python
import subprocess
import tempfile
import os
import sys
import json
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Maximum execution time for generated scripts
SCRIPT_TIMEOUT = 60  # seconds
SCRIPT_MAX_OUTPUT = 50_000  # characters


class ScriptSandbox:
    """Execute agent-generated Python scripts in an isolated subprocess."""

    # Modules the script is ALLOWED to import
    ALLOWED_MODULES = {
        "requests", "urllib.parse", "urllib.request",
        "re", "json", "base64", "hashlib", "hmac",
        "html", "xml.etree.ElementTree",
        "socket", "ssl", "struct", "binascii",
        "itertools", "collections", "functools",
        "time", "datetime",
        "string", "textwrap",
        "ipaddress", "http.client",
        "csv", "io",
    }

    # Patterns that are NEVER allowed in generated code
    FORBIDDEN_PATTERNS = [
        r'\bos\.system\b',
        r'\bsubprocess\b',
        r'\b__import__\b',
        r'\beval\b',
        r'\bexec\b',
        r'\bcompile\b',
        r'\bopen\s*\([^)]*["\']/',         # open() with absolute paths
        r'\bopen\s*\([^)]*\.\.',            # open() with path traversal
        r'\bglobals\b',
        r'\blocals\b',
        r'\bgetattr\b.*\b__\b',
        r'\bimportlib\b',
        r'\bpickle\b',
        r'\bshelve\b',
        r'\bctypes\b',
        r'\bmultiprocessing\b',
        r'\bthreading\.Thread\b',
        r'ANTHROPIC_API_KEY|OPENAI_API_KEY|XAI_API_KEY',
    ]

    def __init__(self, session_dir: str, scope_targets: list[str]):
        self.session_dir = session_dir
        self.scope_targets = scope_targets
        self.script_dir = os.path.join(session_dir, "scripts")
        os.makedirs(self.script_dir, exist_ok=True)

    def validate_code(self, code: str) -> tuple[bool, str]:
        """Static analysis of generated code before execution.

        Returns (is_safe, reason).
        """
        for pattern in self.FORBIDDEN_PATTERNS:
            match = re.search(pattern, code)
            if match:
                return False, f"Forbidden pattern detected: {match.group()}"

        # Check imports against allowlist
        import_pattern = re.compile(
            r'^\s*(?:import|from)\s+([\w.]+)', re.MULTILINE
        )
        for match in import_pattern.finditer(code):
            module = match.group(1).split(".")[0]
            # Allow top-level of dotted imports (e.g., "urllib" from "urllib.parse")
            root_module = match.group(1).split(".")[0]
            full_module = match.group(1)
            if full_module not in self.ALLOWED_MODULES and root_module not in {
                m.split(".")[0] for m in self.ALLOWED_MODULES
            }:
                return False, f"Import not allowed: {match.group(1)}"

        # Check for network calls to non-scope targets
        # This is a heuristic -- the scope_checker enforces at runtime too
        url_pattern = re.compile(r'https?://([^/\s\'"]+)')
        for match in url_pattern.finditer(code):
            host = match.group(1).split(":")[0].lower()
            if not any(
                host == t or host.endswith("." + t)
                for t in self.scope_targets
            ):
                return False, f"URL target '{host}' may be out of scope"

        return True, "OK"

    def execute(self, code: str, description: str = "") -> dict:
        """Execute a Python script in a sandboxed subprocess.

        Returns:
            {
                "success": bool,
                "stdout": str,
                "stderr": str,
                "script_path": str,   # where the script was saved
                "duration": float,
            }
        """
        # Step 1: Validate
        is_safe, reason = self.validate_code(code)
        if not is_safe:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"SANDBOX BLOCKED: {reason}",
                "script_path": "",
                "duration": 0.0,
            }

        # Step 2: Wrap the code with scope enforcement and output capture
        wrapped = self._wrap_code(code)

        # Step 3: Write to temp file
        script_name = f"script_{len(os.listdir(self.script_dir)):03d}.py"
        script_path = os.path.join(self.script_dir, script_name)
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(f"# Dynamic script: {description}\n")
            f.write(f"# Generated at turn {self._current_turn}\n\n")
            f.write(wrapped)

        logger.info("Executing dynamic script: %s (%s)", script_name, description)

        # Step 4: Execute in subprocess with restricted environment
        env = self._build_restricted_env()

        import time
        start = time.monotonic()
        try:
            result = subprocess.run(
                [sys.executable, script_path],
                capture_output=True,
                text=True,
                timeout=SCRIPT_TIMEOUT,
                env=env,
                cwd=self.session_dir,  # working dir is the session dir
            )
            duration = time.monotonic() - start

            stdout = result.stdout[:SCRIPT_MAX_OUTPUT]
            stderr = result.stderr[:SCRIPT_MAX_OUTPUT]

            if result.returncode != 0:
                logger.warning("Script %s exited with code %d", script_name, result.returncode)

            return {
                "success": result.returncode == 0,
                "stdout": stdout,
                "stderr": stderr,
                "script_path": script_path,
                "duration": duration,
            }

        except subprocess.TimeoutExpired:
            duration = time.monotonic() - start
            logger.warning("Script %s timed out after %ds", script_name, SCRIPT_TIMEOUT)
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Script timed out after {SCRIPT_TIMEOUT}s",
                "script_path": script_path,
                "duration": duration,
            }

    def _wrap_code(self, code: str) -> str:
        """Wrap user code with safety harness."""
        scope_list = json.dumps(self.scope_targets)
        return f'''
import sys
import json

# Scope enforcement -- injected by sandbox
_SCOPE_TARGETS = {scope_list}

def _check_scope(url):
    """Verify a URL target is in scope before making requests."""
    from urllib.parse import urlparse
    host = urlparse(url).hostname or url.split("/")[0].split(":")[0]
    host = host.lower()
    for t in _SCOPE_TARGETS:
        if host == t or host.endswith("." + t):
            return True
    raise RuntimeError(f"SCOPE VIOLATION: {{host}} is not in scope. Authorized: {{_SCOPE_TARGETS}}")

# Patch requests to enforce scope
try:
    import requests as _requests
    _original_request = _requests.Session.request

    def _scoped_request(self, method, url, **kwargs):
        _check_scope(url)
        kwargs.setdefault("timeout", 15)
        kwargs.setdefault("verify", False)
        return _original_request(self, method, url, **kwargs)

    _requests.Session.request = _scoped_request
except ImportError:
    pass

# --- Agent script begins ---
try:
{_indent(code, 4)}
except Exception as _e:
    print(f"SCRIPT ERROR: {{type(_e).__name__}}: {{_e}}", file=sys.stderr)
    sys.exit(1)
'''

    def _build_restricted_env(self) -> dict:
        """Build environment variables for the subprocess.

        Strips all API keys and sensitive variables.
        """
        env = {}
        # Only pass through safe variables
        safe_vars = {"PATH", "PYTHONPATH", "HOME", "USERPROFILE", "TEMP", "TMP",
                     "SYSTEMROOT", "COMSPEC", "PHANTOM_SESSION_DIR"}
        for key in safe_vars:
            if key in os.environ:
                env[key] = os.environ[key]
        env["PHANTOM_SESSION_DIR"] = self.session_dir
        # Explicitly prevent API key leakage
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return env

    _current_turn: int = 0


def _indent(text: str, spaces: int) -> str:
    """Indent every line of text by N spaces."""
    prefix = " " * spaces
    return "\n".join(prefix + line for line in text.splitlines())
```

### 3.3 How the LLM Requests Dynamic Scripts

The LLM embeds a `<script>` block in its text output:

```
I need to test for HTTP request smuggling, which none of my built-in tools support.
Let me write a custom script.

<script description="Test for HTTP request smuggling (CL.TE variant)">
import requests
import socket

target = "http://10.0.0.1"
_check_scope(target)  # mandatory scope check

# CL.TE smuggling test
sock = socket.create_connection(("10.0.0.1", 80), timeout=10)
payload = (
    "POST / HTTP/1.1\r\n"
    "Host: 10.0.0.1\r\n"
    "Content-Length: 13\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET /admin HTTP/1.1\r\n"
    "\r\n"
)
sock.sendall(payload.encode())
response = sock.recv(4096).decode(errors="replace")
sock.close()

if "admin" in response.lower() or "200" in response:
    print("[HIGH] HTTP Request Smuggling (CL.TE) -- server processed smuggled request")
    print(f"Response preview: {response[:500]}")
else:
    print("[INFO] CL.TE smuggling test negative")
    print(f"Response: {response[:300]}")
</script>
```

### 3.4 DynamicToolForge Integration

```python
class DynamicToolForge:
    """Parses script blocks from LLM output and executes them via the sandbox."""

    def __init__(self, sandbox: ScriptSandbox):
        self.sandbox = sandbox
        self.executed_scripts: list[dict] = []  # audit trail

    def extract_and_execute(self, llm_text: str) -> tuple[str, list[dict]]:
        """Find <script> blocks in LLM output, execute them, return results.

        Returns:
            (cleaned_text, script_results)
            - cleaned_text: LLM text with <script> blocks replaced by result summaries
            - script_results: list of execution result dicts
        """
        results = []
        cleaned = llm_text

        script_pattern = re.compile(
            r'<script\s+description="([^"]*)">(.*?)</script>',
            re.DOTALL
        )

        for match in script_pattern.finditer(llm_text):
            description = match.group(1)
            code = match.group(2).strip()

            result = self.sandbox.execute(code, description)
            result["description"] = description
            results.append(result)
            self.executed_scripts.append(result)

            # Replace the script block with a summary
            if result["success"]:
                replacement = f"\n[Script executed: {description}]\n{result['stdout']}\n"
            else:
                replacement = (
                    f"\n[Script FAILED: {description}]\n"
                    f"Error: {result['stderr']}\n"
                )
            cleaned = cleaned.replace(match.group(0), replacement)

        return cleaned, results

    def format_as_tool_results(self, results: list[dict]) -> list[dict]:
        """Format script results as tool_result blocks for the conversation."""
        formatted = []
        for i, r in enumerate(results):
            content = f"Script: {r['description']}\n"
            if r["success"]:
                content += f"Output:\n{r['stdout']}"
                if r["stderr"]:
                    content += f"\nWarnings:\n{r['stderr']}"
            else:
                content += f"FAILED:\n{r['stderr']}"
            content += f"\nDuration: {r['duration']:.1f}s"
            content += f"\nSaved: {r['script_path']}"

            formatted.append({
                "type": "tool_result",
                "tool_use_id": f"script-{i}-{id(r)}",
                "content": content,
            })
        return formatted
```

### 3.5 Security Layers (Defense in Depth)

| Layer | Mechanism | What it prevents |
|---|---|---|
| 1. Static analysis | `FORBIDDEN_PATTERNS` regex scan | os.system, subprocess, eval, import hijacking |
| 2. Import allowlist | Only `ALLOWED_MODULES` can be imported | Arbitrary module loading (pickle, ctypes, etc.) |
| 3. Scope enforcement | URL check injected into requests | Attacking out-of-scope targets |
| 4. Environment isolation | Stripped env vars, no API keys | Credential exfiltration |
| 5. Subprocess isolation | Separate Python process | No access to agent memory or state |
| 6. Timeout | `SCRIPT_TIMEOUT` (60s default) | Infinite loops, DoS |
| 7. Output cap | `SCRIPT_MAX_OUTPUT` (50K chars) | Memory exhaustion |
| 8. Filesystem isolation | `cwd` set to session dir | Reading arbitrary files |
| 9. Audit trail | All scripts saved to `scripts/` dir | Post-mission forensic review |

### 3.6 What Dynamic Scripts Are For

Scripts are for situations where no built-in tool fits:

- Custom protocol fuzzing (WebSocket, gRPC, binary protocols)
- HTTP request smuggling tests
- Race condition / TOCTOU exploitation
- Custom deserialization payload generation
- Business logic abuse testing (e.g., price manipulation, coupon stacking)
- Writing exploit chains that combine multiple findings
- Custom credential stuffing with application-specific logic
- Parsing and correlating data from previous tool outputs in novel ways
- Generating encoded/obfuscated payloads

The system prompt makes clear: **built-in tools are preferred**. Scripts are the escape
hatch for when the 26 built-in tools cannot express the needed action.

---

## 4. Memory / Context Management

### 4.1 The Problem

The current system stuffs raw tool output into the message history and uses a crude
truncation (`_compact_old_tool_results`) to prevent context overflow. This loses
important findings and makes it impossible for the agent to correlate data across
many turns.

### 4.2 Three-Tier Memory Architecture

```
+-------------------------------------------------------------------+
|                      Context Window (LLM)                         |
|                                                                    |
|  Tier 1: HOT MEMORY (always in context)                           |
|  - Current attack state (plans, hypotheses, active findings)      |
|  - Last 3 tool results (full)                                     |
|  - Target model (structured)                                      |
|  ~2,000-4,000 tokens                                              |
|                                                                    |
|  Tier 2: WARM MEMORY (summarized in context)                      |
|  - Older tool results (compacted to key findings only)            |
|  - Completed/abandoned plan summaries                             |
|  - Historical finding summaries                                   |
|  ~1,000-2,000 tokens                                              |
|                                                                    |
+-------------------------------------------------------------------+
|                                                                    |
|  Tier 3: COLD MEMORY (on disk, retrievable)                       |
|  - Full tool output logs                                          |
|  - All executed scripts + outputs                                 |
|  - Complete finding database                                      |
|  - Accessible via read_log tool or explicit recall                |
|                                                                    |
+-------------------------------------------------------------------+
```

### 4.3 Implementation

```python
class MemoryManager:
    """Three-tier memory system for managing context across turns."""

    def __init__(
        self,
        session_dir: str,
        hot_results: int = 3,        # keep last N tool results in full
        warm_max_chars: int = 300,    # max chars per compacted result
        target_context_tokens: int = 30_000,  # target budget for managed content
    ):
        self.session_dir = session_dir
        self.hot_results = hot_results
        self.warm_max_chars = warm_max_chars
        self.target_context_tokens = target_context_tokens

        # Tier 3: cold storage
        self.findings_db: list[dict] = []
        self.target_model: dict = {}
        self._findings_file = os.path.join(session_dir, "findings.json")
        self._target_model_file = os.path.join(session_dir, "target_model.json")

    def record_finding(self, finding: dict) -> None:
        """Store a finding in the database (Tier 3) and keep a summary in state (Tier 1)."""
        finding.setdefault("id", uuid.uuid4().hex[:8])
        finding.setdefault("turn", 0)
        self.findings_db.append(finding)
        self._persist_findings()

    def update_target_model(self, updates: dict) -> None:
        """Merge new information into the structured target model.

        The target model is a dict like:
        {
            "hosts": {
                "10.0.0.1": {
                    "ports": {22: "OpenSSH 8.9", 80: "nginx 1.18", 8080: "Tomcat 9.0.30"},
                    "os": "Ubuntu 22.04",
                    "technologies": ["nginx", "PHP 8.1", "WordPress 6.4"],
                }
            },
            "subdomains": ["www.target.com", "api.target.com", "admin.target.com"],
            "credentials": [],      # found credentials
            "attack_surface": {},    # endpoints, parameters, forms
        }
        """
        _deep_merge(self.target_model, updates)
        self._persist_target_model()

    def compact_messages(self, messages: list[dict], state: AttackState) -> list[dict]:
        """Apply three-tier memory management to the message history.

        This replaces the current _compact_old_tool_results with a smarter approach.
        """
        estimated_tokens = self._estimate_tokens(messages)

        if estimated_tokens <= self.target_context_tokens:
            return messages  # within budget, no action needed

        result = []

        # Find all tool_result message indices
        tool_result_indices = [
            i for i, m in enumerate(messages)
            if m.get("role") == "user"
            and isinstance(m.get("content"), list)
            and any(b.get("type") == "tool_result" for b in m["content"])
        ]

        # Tier 1: keep last N tool results intact
        hot_set = set(tool_result_indices[-self.hot_results:])

        # Tier 2: summarize older tool results
        warm_set = set(tool_result_indices[:-self.hot_results])

        for i, msg in enumerate(messages):
            if i in warm_set:
                # Compact: extract only severity-tagged lines and key data
                compacted_blocks = []
                for block in msg["content"]:
                    if block.get("type") == "tool_result":
                        content = str(block.get("content", ""))
                        summary = self._extract_key_lines(content)
                        compacted_blocks.append({
                            **block,
                            "content": summary,
                        })
                    else:
                        compacted_blocks.append(block)
                result.append({**msg, "content": compacted_blocks})
            elif i in hot_set:
                result.append(msg)
            else:
                # Non-tool messages: keep assistant reasoning but trim if huge
                if msg.get("role") == "assistant" and isinstance(msg.get("content"), list):
                    trimmed = []
                    for block in msg["content"]:
                        if block.get("type") == "text":
                            text = block["text"]
                            if len(text) > 500:
                                # Keep first and last 200 chars
                                text = text[:200] + "\n[...trimmed...]\n" + text[-200:]
                            trimmed.append({**block, "text": text})
                        else:
                            trimmed.append(block)
                    result.append({**msg, "content": trimmed})
                else:
                    result.append(msg)

        # If STILL over budget after warm compaction, drop oldest warm messages entirely
        while self._estimate_tokens(result) > self.target_context_tokens * 1.2:
            # Find oldest warm message and remove it
            for i, msg in enumerate(result):
                if (msg.get("role") == "user"
                    and isinstance(msg.get("content"), list)
                    and any(b.get("type") == "tool_result"
                            and "[...compacted]" in str(b.get("content", ""))
                            for b in msg["content"])):
                    result.pop(i)
                    break
            else:
                break  # nothing left to remove

        return result

    def _extract_key_lines(self, content: str) -> str:
        """Extract the most important lines from a tool result."""
        lines = content.splitlines()
        key_lines = []

        for line in lines:
            lower = line.lower()
            # Keep severity-tagged lines
            if any(tag in lower for tag in ["[critical]", "[high]", "[medium]",
                                             "[low]", "[info]", "[+]", "[!]"]):
                key_lines.append(line)
            # Keep lines with port/service info
            elif re.search(r'\d+/(tcp|udp)\s+open', lower):
                key_lines.append(line)
            # Keep lines with CVE references
            elif "cve-" in lower:
                key_lines.append(line)
            # Keep error/warning lines
            elif any(w in lower for w in ["error", "warning", "denied", "forbidden"]):
                key_lines.append(line)

        if not key_lines:
            # Fallback: first and last few lines
            key_lines = lines[:3] + (["..."] if len(lines) > 6 else []) + lines[-3:]

        summary = "\n".join(key_lines[:20])  # cap at 20 key lines
        if len(summary) > self.warm_max_chars:
            summary = summary[:self.warm_max_chars] + " [...compacted]"
        return summary

    def build_state_context(self, state: AttackState) -> str:
        """Build the Tier 1 hot memory block for injection into the prompt."""
        parts = []

        # Target model (always included -- this is the agent's "mental map")
        if self.target_model:
            parts.append("TARGET MODEL:")
            parts.append(_compact_json(self.target_model))

        # Recent findings
        recent = self.findings_db[-10:]
        if recent:
            parts.append(f"\nFINDINGS ({len(self.findings_db)} total, showing last {len(recent)}):")
            for f in recent:
                parts.append(
                    f"  [{f.get('severity','?')}] {f.get('title','')[:60]} "
                    f"(turn {f.get('turn','?')})"
                )

        return "\n".join(parts)

    def _persist_findings(self) -> None:
        with open(self._findings_file, "w", encoding="utf-8") as f:
            json.dump(self.findings_db, f, indent=1)

    def _persist_target_model(self) -> None:
        with open(self._target_model_file, "w", encoding="utf-8") as f:
            json.dump(self.target_model, f, indent=1)

    @staticmethod
    def _estimate_tokens(messages: list[dict]) -> int:
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, list):
                for block in content:
                    total += len(str(block.get("content", "") or block.get("text", "")))
            else:
                total += len(str(content))
        return total // 4


def _deep_merge(base: dict, updates: dict) -> None:
    """Recursively merge updates into base dict."""
    for key, value in updates.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        elif key in base and isinstance(base[key], list) and isinstance(value, list):
            # Deduplicate when merging lists
            existing = set(str(x) for x in base[key])
            base[key].extend(x for x in value if str(x) not in existing)
        else:
            base[key] = value
```

### 4.4 Memory Budget by Provider

| Provider | Context Window | Hot Budget | Warm Budget | Notes |
|---|---|---|---|---|
| Claude Sonnet | 200K | 8K tokens | 4K tokens | Can afford generous context |
| GPT-5.4 | 128K | 6K tokens | 3K tokens | Plenty of room |
| Gemini 3.0 Pro | 1M | 10K tokens | 5K tokens | Massive context, less compaction needed |
| Ollama (llama3.1 8B) | 8K | 2K tokens | 1K tokens | Aggressive compaction mandatory |
| Ollama (qwen2.5 32B) | 32K | 4K tokens | 2K tokens | Moderate compaction |

These budgets are configured per-provider and the `MemoryManager` automatically adjusts
its compaction aggressiveness.

---

## 5. Multi-Provider Support and Graceful Degradation

### 5.1 The Problem

A Claude Sonnet or GPT-5 can handle complex planning XML, multi-step reasoning, and
structured reflection prompts. A llama3.1:8b running on a laptop GPU cannot. The
reasoning engine must work with both.

### 5.2 Provider Capability Profiles

```python
from dataclasses import dataclass


@dataclass
class ProviderCapabilities:
    """Describes what a specific model can handle."""

    # Context window size in tokens
    context_window: int = 128_000

    # Can the model reliably produce structured XML in its output?
    structured_output: bool = True

    # Can it handle multi-step planning with 5+ concurrent plans?
    complex_planning: bool = True

    # Can it write correct Python scripts?
    code_generation: bool = True

    # Can it do meaningful self-reflection?
    metacognition: bool = True

    # How many tools can it reliably choose from?
    max_tools: int = 26

    # Should we use simplified prompts?
    simplified_prompts: bool = False

    # Temperature override (lower for weaker models = more predictable)
    temperature: float = 0.0

    # Planning mode: "full" | "simplified" | "none"
    planning_mode: str = "full"


# Pre-configured profiles
CAPABILITY_PROFILES = {
    # Cloud models -- full capability
    "claude-sonnet-4-6": ProviderCapabilities(
        context_window=200_000,
        planning_mode="full",
    ),
    "gpt-5.4": ProviderCapabilities(
        context_window=128_000,
        planning_mode="full",
    ),
    "gemini-3.0-pro": ProviderCapabilities(
        context_window=1_000_000,
        planning_mode="full",
    ),
    "grok-4-20-beta": ProviderCapabilities(
        context_window=128_000,
        planning_mode="full",
    ),

    # Mid-tier -- simplified planning
    "mistral-large-latest": ProviderCapabilities(
        context_window=128_000,
        complex_planning=False,
        planning_mode="simplified",
    ),
    "deepseek-chat-v3.2": ProviderCapabilities(
        context_window=64_000,
        complex_planning=False,
        planning_mode="simplified",
    ),

    # Local models -- minimal planning
    "llama3.1": ProviderCapabilities(
        context_window=8_000,
        structured_output=False,
        complex_planning=False,
        code_generation=False,     # 8B models write buggy scripts
        metacognition=False,
        max_tools=12,              # reduce tool confusion
        simplified_prompts=True,
        planning_mode="none",
    ),
    "qwen2.5:32b": ProviderCapabilities(
        context_window=32_000,
        structured_output=True,    # Qwen is decent at structured output
        complex_planning=False,
        code_generation=True,      # 32B can write basic scripts
        metacognition=False,
        max_tools=20,
        planning_mode="simplified",
    ),
    "deepseek-v3.2:cloud": ProviderCapabilities(
        context_window=64_000,
        planning_mode="simplified",
    ),
}

# Fallback for unknown models
DEFAULT_CAPABILITIES = ProviderCapabilities(
    context_window=32_000,
    complex_planning=False,
    planning_mode="simplified",
)


def get_capabilities(model_name: str) -> ProviderCapabilities:
    """Look up capabilities for a model, with fuzzy matching."""
    if model_name in CAPABILITY_PROFILES:
        return CAPABILITY_PROFILES[model_name]

    # Fuzzy: check if model name starts with a known prefix
    for known, caps in CAPABILITY_PROFILES.items():
        if model_name.startswith(known.split("-")[0]):
            return caps

    return DEFAULT_CAPABILITIES
```

### 5.3 Graceful Degradation Strategy

```python
class ProviderAdapter:
    """Adapts the reasoning engine behavior to model capabilities."""

    def __init__(self, model_name: str, provider: BaseLLMProvider):
        self.capabilities = get_capabilities(model_name)
        self.provider = provider
        self.model_name = model_name

    def adapt_system_prompt(self, full_prompt: str, simplified_prompt: str) -> str:
        """Return the appropriate system prompt based on model capability."""
        if self.capabilities.simplified_prompts:
            return simplified_prompt
        return full_prompt

    def adapt_tools(self, all_tools: list[dict]) -> list[dict]:
        """Reduce tool count for models that get confused with too many options."""
        if len(all_tools) <= self.capabilities.max_tools:
            return all_tools

        # Priority order: keep the most essential tools
        priority_tools = {
            "check_scope", "run_nmap", "run_recon", "run_nuclei", "run_ffuf",
            "run_whatweb", "run_sqlmap", "run_hydra", "run_metasploit",
            "take_screenshot", "read_log", "generate_report",
        }

        essential = [t for t in all_tools if t["name"] in priority_tools]
        remaining = [t for t in all_tools if t["name"] not in priority_tools]

        slots_left = self.capabilities.max_tools - len(essential)
        return essential + remaining[:slots_left]

    def should_enable_planning(self) -> bool:
        return self.capabilities.planning_mode != "none"

    def should_enable_reflection(self) -> bool:
        return self.capabilities.metacognition

    def should_enable_dynamic_scripts(self) -> bool:
        return self.capabilities.code_generation

    def get_planning_instructions(self) -> str:
        """Return planning instructions appropriate for the model's capability."""
        mode = self.capabilities.planning_mode

        if mode == "full":
            return PLANNING_INSTRUCTIONS_FULL

        if mode == "simplified":
            return PLANNING_INSTRUCTIONS_SIMPLIFIED

        # mode == "none": no planning, just sequential tool calls
        return ""


# Planning instructions by complexity level

PLANNING_INSTRUCTIONS_FULL = """
PLANNING PROTOCOL:
You maintain attack plans as structured objectives. Use these XML blocks in your responses:

To create a plan:
<plan_create objective="description" priority="0.0-1.0" hypothesis="h_id">
  <action tool="tool_name" args='{"key":"value"}' priority="0.9"/>
  <action description="what to do" tool="another_tool" args='{}' depends_on="prev"/>
</plan_create>

To abandon a plan:
<plan_abandon id="p_xxx" reason="why"/>

To update a hypothesis:
<hypothesis_update id="h_xxx" confidence="speculative|probable|confirmed|disproved" evidence="what changed"/>

RULES:
- Create plans when you discover new attack vectors
- Abandon plans immediately when the hypothesis is disproved
- Prioritize plans by potential impact (RCE > SQLi > XSS > Info)
- You can have multiple active plans; work on the highest-priority one
- Scripts: when no built-in tool fits, write a <script> block (see DYNAMIC SCRIPTS section)
"""

PLANNING_INSTRUCTIONS_SIMPLIFIED = """
PLANNING:
Before each action, state:
- GOAL: what you are trying to achieve
- WHY: why this is the best next step
- FALLBACK: what you will try if this fails

If an approach is not working after 2 attempts, switch to a different technique.
"""
```

### 5.4 Degradation Behavior Table

| Feature | Cloud (full) | Mid-tier (simplified) | Local small (none) |
|---|---|---|---|
| Attack planning | XML-structured plans with hypotheses, dependencies, priorities | Text-based GOAL/WHY/FALLBACK per action | Linear tool calls (current behavior) |
| Reflection | Full `<reflection>` block every 3 turns | No structured reflection; stall detection only | Stall detection only (current) |
| Dynamic scripts | Full script generation and execution | Script generation (may need retry on errors) | Disabled (scripts would be too buggy) |
| Memory | 3-tier with generous budget | 3-tier with aggressive compaction | Simple truncation (current behavior) |
| Tools | All 26 tools | All 26 tools | Top 12 essential tools only |
| System prompt | Full prompt with planning/reflection protocol | Simplified prompt with basic instructions | Minimal prompt with tool list only |

---

## 6. Prompt Engineering

### 6.1 System Prompt Structure (Full Mode)

The new system prompt replaces the current `prompts/system_prompt.txt`. It is divided
into sections that can be conditionally included based on model capabilities.

```
prompts/
  system_prompt_core.txt         # identity, scope rules, tool list (always included)
  system_prompt_planning.txt     # planning protocol (full mode only)
  system_prompt_reflection.txt   # reflection protocol (full mode only)
  system_prompt_scripts.txt      # dynamic script protocol (code_generation=True only)
  system_prompt_simplified.txt   # combined simplified version for mid-tier models
  system_prompt_minimal.txt      # bare minimum for small local models
```

### 6.2 Core Prompt (Always Included)

```
You are Phantom, an autonomous penetration testing agent. You reason like an expert
red teamer: you form hypotheses, test them, adapt based on results, and chain findings
into attack paths.

ABSOLUTE RULES:
1. Act ONLY within the authorized scope. Every action is scope-checked.
2. Log everything. Take screenshots for CRITICAL/HIGH findings.
3. Never repeat a failed action with identical parameters.
4. When reporting, group findings into attack chains, not isolated items.

IDENTITY:
- You are not a scripted scanner. You THINK about what you find.
- After each tool result, analyze: what does this MEAN? What hypothesis does it
  support or disprove? What should you investigate next?
- You can run multiple tools in parallel when they are independent.
- You can write custom Python scripts when no built-in tool fits the need.

TARGET MODEL:
You maintain a mental model of the target that evolves with each finding.
Update it continuously: hosts, ports, services, technologies, credentials,
vulnerabilities, attack surface.

AVAILABLE TOOLS:
[tool table -- same as current, dynamically generated from TOOL_SPECS]

COMPLETION:
End your mission with === MISSION COMPLETE === when all vectors are exhausted
or a critical compromise is confirmed and documented.
```

### 6.3 Planning Section (Full Mode)

```
REASONING PROTOCOL:

You maintain ATTACK PLANS -- structured objectives with prioritized actions.

Each plan:
- Tests a HYPOTHESIS about the target
- Contains ordered ACTIONS (tool calls or scripts)
- Has a PRIORITY (0.0-1.0) based on potential impact
- Can be ABANDONED when the hypothesis is disproved

You can have multiple concurrent plans. Always work on the highest-priority
pending action across all plans.

PLAN LIFECYCLE:
1. DISCOVER: Recon reveals attack surface
2. HYPOTHESIZE: "This Tomcat instance might have default manager credentials"
3. PLAN: Create a plan with specific actions to test the hypothesis
4. EXECUTE: Run actions, collect evidence
5. EVALUATE: Did results confirm or disprove the hypothesis?
6. ADAPT: Update plan priority, create new plans, abandon dead ends

When you create, update, or abandon plans, use the structured XML format
described in your planning protocol.

PRIORITY GUIDELINES:
- 0.9-1.0: RCE, authentication bypass, data exfiltration paths
- 0.7-0.8: SQL injection, privilege escalation vectors
- 0.5-0.6: XSS, information disclosure, misconfigurations
- 0.3-0.4: Low-severity issues, informational findings
- 0.1-0.2: Speculative hypotheses, unlikely vectors
```

### 6.4 Dynamic Script Section

```
DYNAMIC SCRIPTS:

When no built-in tool can perform the action you need, write a Python script.
Place your code in a <script description="what this tests"> block.

Your script has access to: requests, socket, ssl, re, json, base64, hashlib,
urllib.parse, html, xml, ipaddress, collections, itertools, struct, binascii,
csv, io, time, datetime, string, http.client.

Your script does NOT have access to: os.system, subprocess, eval, exec, pickle,
ctypes, the filesystem outside the session directory, or any API keys.

MANDATORY: Call _check_scope(url) before any network request. This function is
injected automatically and will raise an error if the target is out of scope.

OUTPUT FORMAT: Print findings with severity tags:
  print("[CRITICAL] Remote code execution via ...")
  print("[HIGH] SQL injection in parameter ...")
  print("[MEDIUM] Reflected XSS in ...")
  print("[INFO] Server version disclosed: ...")

WHEN TO USE SCRIPTS:
- Custom protocol testing (WebSocket, gRPC, raw TCP)
- HTTP request smuggling
- Race condition exploitation
- Business logic testing
- Custom payload generation/encoding
- Parsing/correlating data from previous tool outputs
- Anything the 26 built-in tools cannot express

WHEN NOT TO USE SCRIPTS:
- When a built-in tool already does the job (use the tool instead)
- For basic HTTP requests (use run_ffuf or run_nuclei)
- For port scanning (use run_nmap)
```

### 6.5 Reflection Section

```
SELF-REFLECTION:

Every few turns, you will be prompted to reflect on your approach.
When you see [REFLECTION REQUIRED], produce a <reflection> block:

<reflection>
progress: Am I making meaningful progress?
approach_effective: yes | no | partial
blind_spots: Attack vectors I have NOT tried yet
decision: continue | modify | pivot | escalate
next_priority: What to do next and why
custom_tool_needed: yes | no (if yes, describe what)
</reflection>

This is not optional. Reflection prevents tunnel vision and wasted turns.
```

---

## 7. Integration: The New `think()` Method

This is how all the pieces compose together inside `AgentClient`:

```python
class ReasoningEngine:
    """Orchestrates planning, reflection, memory, scripts, and provider adaptation."""

    def __init__(self, config: dict, provider: BaseLLMProvider, model_name: str):
        session_dir = config.get("session_dir", "logs/session")
        scope_targets = _load_scope_targets()

        self.adapter = ProviderAdapter(model_name, provider)
        self.planning = PlanningLayer() if self.adapter.should_enable_planning() else None
        self.reflection = ReflectionLayer() if self.adapter.should_enable_reflection() else None
        self.memory = MemoryManager(
            session_dir=session_dir,
            target_context_tokens=self.adapter.capabilities.context_window // 4,
        )
        self.forge = DynamicToolForge(
            ScriptSandbox(session_dir, scope_targets)
        ) if self.adapter.should_enable_dynamic_scripts() else None

        self.provider = provider
        self.tools_raw = ALL_TOOLS
        self.tools = provider.convert_tools(
            self.adapter.adapt_tools(ALL_TOOLS)
        )
        self.mapping = get_tool_mapping()

    def think(self, messages: list[dict], system_prompt: str) -> list[dict]:
        """One turn of the reasoning loop.

        This replaces AgentClient.think() with the full reasoning engine.
        """
        # 1. Memory management: compact old messages
        messages = self.memory.compact_messages(messages, self._get_state())

        # 2. Build the system prompt for this turn
        effective_prompt = self._build_prompt(system_prompt)

        # 3. Inject attack state into messages (if planning is enabled)
        augmented = messages
        if self.planning:
            augmented = self.planning.inject_state_into_prompt(messages)

        # 4. Call the LLM
        text_blocks, tool_calls = self.provider.call_with_retry(
            augmented, effective_prompt, self.tools
        )

        # 5. Process LLM output
        new_messages = messages.copy()
        assistant_blocks = []

        for text in text_blocks:
            # 5a. Parse planning actions (if enabled)
            if self.planning:
                text = self.planning.parse_plan_actions(text)

            # 5b. Parse reflection (if enabled)
            if self.reflection:
                reflection = self.reflection.parse_reflection(text)
                if reflection:
                    actions = self.reflection.apply_reflection(
                        reflection, self._get_state()
                    )
                    for action_desc in actions:
                        logger.info("Reflection action: %s", action_desc)

            # 5c. Extract and execute dynamic scripts (if enabled)
            script_results = []
            if self.forge:
                text, script_results = self.forge.extract_and_execute(text)

            # 5d. Parse findings from text and update memory
            self._extract_findings(text)

            # Display cleaned text
            print(f"\n{'--' * 30}")
            print(f"Phantom: {text}")
            print(f"{'--' * 30}")

            assistant_blocks.append({"type": "text", "text": text})

            # 5e. Add script results as tool results
            if script_results:
                script_tool_results = self.forge.format_as_tool_results(script_results)
                # These get appended after the tool results below

        # 6. Add tool_use blocks and execute tools (same as current)
        for tc in tool_calls:
            assistant_blocks.append({
                "type": "tool_use",
                "id": tc["id"],
                "name": tc["name"],
                "input": tc["input"],
            })

        if assistant_blocks:
            new_messages.append({"role": "assistant", "content": assistant_blocks})

        if tool_calls:
            tool_results = self._execute_tools_parallel(tool_calls)

            # Extract findings from tool results
            for tr in tool_results:
                self._extract_findings(str(tr.get("content", "")))

            # Update target model from tool results
            self._update_target_model_from_results(tool_calls, tool_results)

            new_messages.append({"role": "user", "content": tool_results})

        # 7. Add script results to conversation (if any)
        if self.forge and script_results:
            formatted = self.forge.format_as_tool_results(script_results)
            if formatted:
                new_messages.append({"role": "user", "content": formatted})

        # 8. Inject reflection prompt if needed
        if self.reflection and self.reflection.should_reflect(self._get_state()):
            reflection_prompt = self.reflection.build_reflection_prompt(self._get_state())
            new_messages.append({"role": "user", "content": reflection_prompt})

        # 9. Update turn counter
        if self.planning:
            self.planning.state.turn += 1

        return new_messages

    def _build_prompt(self, base_prompt: str) -> str:
        """Assemble the system prompt based on model capabilities."""
        parts = [base_prompt]

        planning_instructions = self.adapter.get_planning_instructions()
        if planning_instructions:
            parts.append(planning_instructions)

        if self.reflection and self.adapter.should_enable_reflection():
            parts.append(REFLECTION_PROMPT_SECTION)

        if self.forge and self.adapter.should_enable_dynamic_scripts():
            parts.append(SCRIPT_PROMPT_SECTION)

        # Add memory context
        state_context = self.memory.build_state_context(self._get_state())
        if state_context:
            parts.append(f"\n[CURRENT STATE]\n{state_context}\n[/CURRENT STATE]")

        return "\n\n".join(parts)

    def _get_state(self) -> AttackState:
        if self.planning:
            return self.planning.state
        return AttackState()

    def _extract_findings(self, text: str) -> None:
        """Parse severity-tagged findings from text and record them."""
        import re
        pattern = re.compile(r'\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+?)(?:\n|$)')
        for match in pattern.finditer(text):
            self.memory.record_finding({
                "severity": match.group(1),
                "title": match.group(2).strip()[:120],
                "turn": self.planning.state.turn if self.planning else 0,
            })

    def _update_target_model_from_results(
        self, tool_calls: list[dict], results: list[dict]
    ) -> None:
        """Parse structured data from tool results to update the target model."""
        for tc, result in zip(tool_calls, results):
            content = str(result.get("content", ""))

            if tc["name"] == "run_nmap":
                # Parse open ports
                ports = {}
                for match in re.finditer(
                    r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', content
                ):
                    ports[int(match.group(1))] = f"{match.group(3)} {match.group(4)}".strip()
                if ports:
                    target = tc["input"].get("target", "unknown")
                    self.memory.update_target_model({
                        "hosts": {target: {"ports": ports}}
                    })

            elif tc["name"] == "run_whatweb":
                # Parse technologies
                techs = re.findall(r'\[([^\]]+)\]', content)
                if techs:
                    target = tc["input"].get("target", "unknown")
                    self.memory.update_target_model({
                        "hosts": {target: {"technologies": techs[:20]}}
                    })

            elif tc["name"] == "run_recon":
                # Parse subdomains
                subs = re.findall(r'[\w.-]+\.\w{2,}', content)
                if subs:
                    self.memory.update_target_model({"subdomains": subs})

    def _execute_tools_parallel(self, tool_calls: list[dict]) -> list[dict]:
        """Execute tools (delegated to the existing parallel executor)."""
        # This reuses the existing AgentClient._execute_tools_parallel logic
        results = []
        for tc in tool_calls:
            tool_func = self.mapping.get(tc["name"])
            if not tool_func:
                results.append({
                    "type": "tool_result",
                    "tool_use_id": tc["id"],
                    "content": f"Unknown tool: {tc['name']}",
                })
                continue
            try:
                result = tool_func(**tc.get("input", {}))
                results.append({
                    "type": "tool_result",
                    "tool_use_id": tc["id"],
                    "content": str(result),
                })
            except Exception as e:
                results.append({
                    "type": "tool_result",
                    "tool_use_id": tc["id"],
                    "content": f"Error: {e}",
                })
        return results
```

---

## 8. Migration Path

### Phase 1: Foundation (non-breaking)
1. Implement `MemoryManager` and wire it into the existing `AgentClient.think()`,
   replacing `_compact_old_tool_results`.
2. Implement `ProviderCapabilities` and `ProviderAdapter`.
3. Split the system prompt into modular sections.
4. Add the `findings.json` and `target_model.json` persistence.

### Phase 2: Dynamic Scripts
1. Implement `ScriptSandbox` and `DynamicToolForge`.
2. Add `<script>` block parsing to the think loop.
3. Add the script protocol section to the system prompt.
4. Test with cloud models first (best code generation quality).

### Phase 3: Planning + Reflection
1. Implement `PlanningLayer` with `AttackState`.
2. Implement `ReflectionLayer`.
3. Add plan/hypothesis XML parsing.
4. Add the planning and reflection prompt sections.
5. Wire everything together in `ReasoningEngine`.

### Phase 4: Compose
1. Replace `AgentClient.think()` with `ReasoningEngine.think()`.
2. Run full integration tests against test targets.
3. Tune reflection frequency, memory budgets, and plan priorities.

---

## 9. File Layout

```
agent/
  reasoning/
    __init__.py
    engine.py              # ReasoningEngine (the main orchestrator)
    planning.py            # PlanningLayer, AttackState, AttackPlan, Hypothesis
    reflection.py          # ReflectionLayer
    memory.py              # MemoryManager (3-tier context management)
    sandbox.py             # ScriptSandbox (code validation + subprocess execution)
    forge.py               # DynamicToolForge (script extraction + execution)
    capabilities.py        # ProviderCapabilities, ProviderAdapter, profiles
  agent_client.py          # Updated to compose ReasoningEngine
  providers/               # Unchanged
  tools/                   # Unchanged (new tools can still be added normally)

prompts/
  system_prompt_core.txt
  system_prompt_planning.txt
  system_prompt_reflection.txt
  system_prompt_scripts.txt
  system_prompt_simplified.txt
  system_prompt_minimal.txt
```

---

## 10. Key Design Decisions

**Why XML blocks instead of separate tool calls for planning?**
Planning is part of the agent's REASONING, not a tool invocation. Making it a tool call
would force an extra round-trip and break the flow. XML blocks are parsed from the
same response that contains the agent's analysis and tool calls.

**Why not a separate LLM call for reflection?**
Cost and latency. Reflection is a prompt injection that costs zero extra API calls.
The LLM reflects as part of its normal response. For models that cannot reflect
meaningfully (small local models), the feature is simply disabled.

**Why subprocess isolation for scripts instead of exec()?**
Security. `exec()` in the agent process would give scripts access to API keys, the
agent's memory, and the full Python environment. A subprocess with a stripped
environment is the minimum viable isolation. Future work could add Docker containers
or WASM sandboxes.

**Why not just give the LLM a "run_python" tool?**
Because the script needs to appear inline with the agent's reasoning, not as a
separate tool call. The agent thinks "I need to test for request smuggling" and
immediately writes the code in the same response. A tool call would require the
LLM to first decide to call `run_python`, then write the code as a string argument,
which is clunkier and less natural for the reasoning flow. However, a `run_python`
tool COULD be offered as a compatibility shim for models that struggle with `<script>`
blocks -- this is a valid future extension.

**Why reduce tool count for small models?**
Empirical observation: models under 14B parameters become unreliable when presented
with 20+ tools. They hallucinate tool names, mix up parameters, or call tools in
nonsensical sequences. Reducing to 12 essential tools dramatically improves accuracy.
