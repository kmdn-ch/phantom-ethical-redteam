# Phantom v3 Architecture -- From Linear Kill Chain to Autonomous Reasoning Agent

**Status:** Proposed
**Date:** 2026-03-29
**Author:** Architecture review of existing codebase + forward design

---

## Table of Contents

1. [Diagnosis of v2](#1-diagnosis-of-v2)
2. [Design Principles](#2-design-principles)
3. [Component Diagram](#3-component-diagram)
4. [Module Breakdown](#4-module-breakdown)
5. [Reasoning Engine](#5-reasoning-engine)
6. [Dynamic Tool Generation](#6-dynamic-tool-generation)
7. [State and Memory Model](#7-state-and-memory-model)
8. [Attack Graph and Timeline](#8-attack-graph-and-timeline)
9. [Scope and Safety Architecture](#9-scope-and-safety-architecture)
10. [Provider Abstraction](#10-provider-abstraction)
11. [Migration Path](#11-migration-path)
12. [File-by-File Change Plan](#12-file-by-file-change-plan)
13. [ADRs](#13-architectural-decision-records)

---

## 1. Diagnosis of v2

### What works

- **Tool registry** (`agent/tools/__init__.py`): clean decorator-based registration with auto-discovery. The Anthropic-native tool spec format is a reasonable lingua franca.
- **Provider abstraction** (`agent/providers/base.py`): the `BaseLLMProvider` contract (convert_tools, call, call_with_retry) is simple and correct. Ollama's XML-fallback parser is a pragmatic hack that works.
- **Scope enforcement** (`agent/tools/scope_checker.py`): defense-in-depth -- tools call `scope_guard()` individually, and the checker handles CIDR, subdomain matching, and userinfo bypass prevention.
- **Stealth module** (`agent/tools/stealth.py`): profiles that propagate to all HTTP tools via `stealth_headers()` and `stealth_delay()`. Rate limiter with token bucket and auto-degradation on 429s.
- **Session persistence** (`agent_client.py` save_state/load_state): atomic writes with tmp+rename, resume capability.
- **Parallel tool execution**: ThreadPoolExecutor with configurable parallelism.
- **Log analysis** (`agent/tools/read_log.py`): the agent reads its own output files. This is a form of self-reflection, even if the agent does not understand it that way.

### What is broken

1. **The system prompt IS the strategy.** The 318-line `prompts/system_prompt.txt` encodes a fixed kill chain: "Always start with recon -> nmap -> whatweb -> nuclei -> ffuf. Never skip phases." The LLM follows instructions, it does not reason about what to do. Technology-aware branching is a decision tree, not adaptive reasoning.

2. **The initial user message IS the plan.** `main.py` lines 183-208 inject a rigid mission brief with "Follow phase order: Recon -> Fingerprint -> Scan -> Enumerate -> Exploit -> Report." The agent has no mechanism to deviate from this.

3. **No memory between turns beyond raw conversation.** The conversation history is the only state. There is no structured representation of what has been discovered, what has been tried, what failed, or what hypotheses exist. The stall detector counts severity tags in text -- it has no semantic understanding of progress.

4. **No attack graph.** The system prompt mentions "correlate findings into attack chains" but there is no data structure for this. The LLM is asked to do correlation in prose, which is unreliable, especially with smaller local models.

5. **No dynamic tool generation.** All 26 tools are static Python functions wrapping CLI binaries. When the agent encounters something novel (custom API, unusual protocol, non-standard auth flow), it has no way to adapt.

6. **Context window is the ceiling.** The compaction logic (`_compact_old_tool_results`) truncates old results after N turns. For a long mission, the agent literally forgets what it discovered. There is no summarization, no external memory.

7. **No exploitation depth.** Metasploit integration blocks post-exploitation modules (`post/`, `persistence`, `bind_shell`). The vision calls for persistence, lateral movement, exfiltration. The safety checks need to be scope-aware, not category-blocked.

8. **Single-turn thinking.** Each `think()` call is one LLM inference. There is no planning step, no reflection step, no ability to think multiple steps ahead before acting.

9. **Report is the only output artifact.** No structured timeline, no attack graph visualization, no machine-readable findings format.

---

## 2. Design Principles

1. **The LLM reasons; the framework remembers.** The agent's job is to think about what to do next. The framework's job is to maintain structured state (findings, graph, timeline) and present it back to the LLM in a digestible form.

2. **Planning and execution are separate phases.** The agent plans before it acts. Plans are explicit, reviewable, and revisable. This is how human pentesters work.

3. **Tools are a spectrum, not a fixed set.** Built-in tools are the starting point. The agent can generate, validate, and execute custom tools when built-in ones are insufficient. This is the essence of the project.

4. **State lives outside the conversation.** Structured memory (findings database, attack graph, tried-actions log) is persisted independently and injected into context as needed. The conversation can be pruned aggressively without losing knowledge.

5. **Safety is structural, not prompt-based.** Scope enforcement happens in code, not in instructions the LLM might ignore. Dynamic tools run in sandboxes. Exploitation depth is gated by explicit human authorization levels, not blanket module blocklists.

6. **Ollama is a first-class citizen.** Every architectural decision must work with a 7B-13B parameter local model. This means: shorter prompts, structured state injection, explicit tool schemas, and tolerance for imperfect tool-calling.

---

## 3. Component Diagram

```
                                    +---------------------------+
                                    |       CLI / main.py       |
                                    |  (session init, config,   |
                                    |   human interaction)      |
                                    +------------+--------------+
                                                 |
                                                 v
                              +------------------+------------------+
                              |          Orchestrator               |
                              |  (replaces AgentClient)             |
                              |                                     |
                              |  +-------------------------------+  |
                              |  |      Reasoning Engine         |  |
                              |  |  Plan -> Act -> Observe ->    |  |
                              |  |  Reflect -> Replan            |  |
                              |  +-------------------------------+  |
                              |                                     |
                              |  +-------------------------------+  |
                              |  |      Context Manager          |  |
                              |  |  - Builds LLM prompt from     |  |
                              |  |    structured state           |  |
                              |  |  - Manages token budget       |  |
                              |  |  - Injects relevant memory    |  |
                              |  +-------------------------------+  |
                              |                                     |
                              +---+----------+----------+----------++
                                  |          |          |           |
                     +------------+   +------+------+   |    +-----+--------+
                     |                |             |   |    |              |
                     v                v             |   |    v              v
              +-----------+   +------------+       |   | +---------+ +----------+
              |  Tool     |   |  Dynamic   |       |   | | Attack  | | Mission  |
              |  Registry |   |  Tool      |       |   | | Graph   | | Memory   |
              |           |   |  Forge     |       |   | |         | |          |
              | 26 built- |   |            |       |   | | Nodes:  | | Findings |
              | in tools  |   | Generate   |       |   | | hosts,  | | Actions  |
              |           |   | Validate   |       |   | | services| | Hypothe- |
              | + scope   |   | Sandbox    |       |   | | vulns,  | | ses      |
              | guard on  |   | Execute    |       |   | | creds,  | | Timeline |
              | each      |   |            |       |   | | paths   | |          |
              +-----------+   +-----+------+       |   | +---------+ +----------+
                                    |              |   |
                                    v              |   |
                              +------------+       |   |
                              |  Sandbox   |       |   |
                              |  Runtime   |       |   |
                              |            |       |   |
                              | subprocess |       |   |
                              | + seccomp  |       |   |
                              | + timeout  |       |   |
                              | + network  |       |   |
                              |   filter   |       |   |
                              +------------+       |   |
                                                   |   |
                                                   v   v
                                            +------+---+------+
                                            |   LLM Provider  |
                                            |   Abstraction   |
                                            |                 |
                                            | Anthropic       |
                                            | OpenAI / Grok   |
                                            | Ollama          |
                                            | Gemini          |
                                            | Mistral         |
                                            | DeepSeek        |
                                            +-----------------+
```

---

## 4. Module Breakdown

### 4.1 `agent/orchestrator.py` -- replaces `agent_client.py`

**Responsibility:** Runs the reasoning loop. Coordinates planning, execution, observation, and reflection. Manages turn budget and mission completion logic.

Key changes from `AgentClient`:
- No longer a thin wrapper around "call LLM, execute tools, append results."
- Implements the Plan-Act-Observe-Reflect (PAOR) loop explicitly.
- Holds references to `ContextManager`, `MissionMemory`, `AttackGraph`, `ToolRegistry`, and `DynamicToolForge`.
- Stall detection is replaced by the reflection phase, which has access to structured memory instead of regex-counting severity tags in raw text.

### 4.2 `agent/reasoning/` -- new package

#### `agent/reasoning/planner.py`

Asks the LLM: "Given what you know (injected state summary), what should you do next and why?" Returns a structured plan (list of intended actions with rationale).

The plan is NOT a full mission plan. It is a 1-3 step tactical plan for the next cycle. The agent replans after observing results.

For local LLMs (Ollama), the planner uses a constrained output format (JSON with known keys) to compensate for weaker instruction-following.

#### `agent/reasoning/reflector.py`

After observing tool results, asks the LLM: "What did you learn? Did results match expectations? Should you change approach?" Returns structured observations that update mission memory.

This is the mechanism that replaces both the stall detector and the hardcoded "ADAPTIVE INTELLIGENCE" branching rules. The LLM does the reasoning; the framework captures it.

#### `agent/reasoning/strategist.py`

Higher-level reasoning invoked periodically (every N turns or on significant events). Asks: "Looking at the full attack surface and all findings so far, what attack chains are emerging? What high-value targets remain unexplored?"

This replaces the "FINDING CORRELATION -- CHAIN ANALYSIS" section of the system prompt. Instead of hoping the LLM correlates findings in prose, the strategist explicitly asks for correlation and writes results into the attack graph.

### 4.3 `agent/memory/` -- new package

#### `agent/memory/mission_memory.py`

Structured storage for everything discovered during a mission. Not a conversation log -- a knowledge base.

```python
@dataclass
class Finding:
    id: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str          # e.g., "cve", "misconfig", "credential", "exposure"
    title: str
    target: str            # host, URL, or service
    evidence: str          # raw proof
    tool_source: str       # which tool found it
    timestamp: datetime
    cvss: float | None
    cve_id: str | None
    remediation: str | None
    screenshot_path: str | None

@dataclass
class ActionRecord:
    id: str
    tool: str
    parameters: dict
    result_summary: str
    findings_produced: list[str]  # Finding IDs
    timestamp: datetime
    success: bool

@dataclass
class Hypothesis:
    id: str
    description: str       # e.g., "WordPress admin panel may have default creds"
    status: str            # untested, confirmed, refuted
    related_findings: list[str]
    actions_taken: list[str]

class MissionMemory:
    findings: dict[str, Finding]
    actions: dict[str, ActionRecord]
    hypotheses: dict[str, Hypothesis]
    target_map: dict[str, TargetInfo]  # host -> ports, services, technologies

    def summary_for_context(self, max_tokens: int) -> str:
        """Generate a state summary that fits within token budget."""

    def unanswered_hypotheses(self) -> list[Hypothesis]:
        """Return hypotheses that haven't been tested yet."""

    def unexplored_targets(self) -> list[TargetInfo]:
        """Return discovered targets that haven't been fully assessed."""
```

This replaces the pattern of "call read_log after every tool to analyze results." The framework parses tool output and updates structured memory automatically. The LLM receives a summary, not raw tool output.

#### `agent/memory/context_manager.py`

Builds the LLM prompt for each turn by combining:
1. A slim system prompt (role + rules + available tools -- NOT a kill chain)
2. Current state summary from MissionMemory (formatted for the LLM)
3. Recent conversation (last N turns of actual dialogue)
4. The current plan (what the agent said it would do)
5. Tool results from the most recent execution

The context manager is token-budget-aware. It knows the provider's context window size and allocates budget across sections. For Ollama with small context windows (4K-8K), it aggressively summarizes. For Anthropic/OpenAI with large windows (128K+), it includes more raw detail.

This replaces the crude `_compact_old_tool_results` approach.

### 4.4 `agent/tools/forge.py` -- Dynamic Tool Generation

**This is the most important new component.**

```python
class DynamicToolForge:
    """Generate, validate, and execute custom tools at runtime."""

    def request_tool(self, description: str, target: str, context: str) -> ForgedTool:
        """
        LLM generates a Python script to accomplish a specific task.

        The script is:
        1. Generated by the LLM with explicit constraints
        2. Validated by static analysis (AST parsing)
        3. Scope-checked (all targets in the script are verified)
        4. Executed in a sandboxed subprocess
        5. Results captured and returned
        """

    def validate_script(self, code: str) -> ValidationResult:
        """
        Static analysis:
        - Parse AST to detect forbidden imports (os.system, subprocess
          without allowlist, socket.connect to non-scope IPs)
        - Check for file system writes outside session directory
        - Check for network connections outside authorized scope
        - Reject scripts longer than MAX_LINES (prevent prompt injection
          via generated code)
        """

    def execute_in_sandbox(self, script_path: str, timeout: int) -> str:
        """
        Execute in isolated subprocess with:
        - Network namespace (Linux) or firewall rules limiting
          outbound to scope-only
        - Read-only filesystem except session directory
        - Memory limit
        - CPU time limit
        - No access to Phantom's own config, API keys, or state
        """
```

The forge is a tool itself -- it appears in the tool registry as `forge_tool`. The LLM calls it like any other tool, passing a description of what it needs. The forge generates the script, validates it, and runs it.

Example flow:
1. Agent encounters a custom WebSocket API
2. No built-in tool handles WebSocket enumeration
3. Agent calls `forge_tool(description="Write a Python script that connects to ws://target:8080/api, sends common fuzzing payloads, and reports responses", target="target.com")`
4. Forge generates a script using `websockets` library
5. Forge validates: target is in scope, no forbidden imports, no file writes outside session
6. Forge executes in sandbox with 60s timeout
7. Results returned to agent as tool_result

### 4.5 `agent/graph/` -- new package

#### `agent/graph/attack_graph.py`

A directed graph data structure representing the attack surface and exploitation paths.

```python
class NodeType(Enum):
    HOST = "host"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    ACCESS = "access"           # shell, admin panel, etc.
    DATA = "data"               # exfiltrated data, sensitive files

class EdgeType(Enum):
    RUNS = "runs"               # host -> service
    HAS_VULN = "has_vuln"       # service -> vulnerability
    EXPLOITS = "exploits"       # vulnerability -> access
    AUTHENTICATES = "authenticates"  # credential -> access
    PIVOTS_TO = "pivots_to"     # access -> host (lateral movement)
    EXPOSES = "exposes"         # access -> data

@dataclass
class Node:
    id: str
    type: NodeType
    label: str
    properties: dict

@dataclass
class Edge:
    source: str
    target: str
    type: EdgeType
    label: str
    evidence: str              # Finding ID that justifies this edge
    timestamp: datetime

class AttackGraph:
    nodes: dict[str, Node]
    edges: list[Edge]

    def add_host(self, host: str, properties: dict) -> str: ...
    def add_service(self, host_id: str, port: int, service: str, version: str) -> str: ...
    def add_vulnerability(self, service_id: str, finding: Finding) -> str: ...
    def add_credential(self, source_finding: Finding) -> str: ...
    def add_access(self, via_vuln_id: str, access_type: str) -> str: ...

    def find_attack_chains(self) -> list[AttackChain]:
        """
        Walk the graph to find paths from initial recon
        to impact (data exposure, access gained, etc.)
        Returns chains sorted by impact severity.
        """

    def to_dot(self) -> str:
        """Export as Graphviz DOT for visualization."""

    def to_json(self) -> dict:
        """Export as JSON for the debrief report."""

    def to_mermaid(self) -> str:
        """Export as Mermaid diagram for Markdown reports."""
```

The attack graph is updated by:
- Tool result parsers (e.g., nmap output parser adds host and service nodes)
- The reflector (which asks the LLM to identify relationships)
- The strategist (which identifies attack chains)

#### `agent/graph/timeline.py`

```python
@dataclass
class TimelineEvent:
    timestamp: datetime
    phase: str                 # recon, fingerprint, scan, exploit, etc.
    action: str                # tool call or reasoning step
    target: str
    result_summary: str
    findings: list[str]        # Finding IDs
    severity: str | None       # highest severity of findings in this event

class MissionTimeline:
    events: list[TimelineEvent]

    def add_event(self, event: TimelineEvent) -> None: ...
    def to_markdown(self) -> str: ...
    def to_json(self) -> list[dict]: ...
    def duration(self) -> timedelta: ...
    def phase_breakdown(self) -> dict[str, timedelta]: ...
```

### 4.6 `agent/tools/` -- existing tools (mostly unchanged)

The 26 existing tools keep their current interface. Changes:

1. Each tool's `run()` function returns its result as before (string).
2. A new `parse_result(raw: str) -> list[Finding]` function is added to each tool module. This extracts structured findings from the raw output. The orchestrator calls this after tool execution to update MissionMemory.
3. Tools that currently read `config.yaml` directly (metasploit, nmap) will receive config via dependency injection instead.
4. The `read_log` tool remains but becomes less critical -- the agent no longer needs to call it after every tool because the framework handles result parsing.

### 4.7 `agent/providers/` -- existing providers (minor changes)

- Add a `context_window_size` property to `BaseLLMProvider` so the context manager knows token budget.
- Add a `supports_structured_output` property to indicate whether the provider supports JSON mode / structured output (useful for planner and reflector).
- Ollama provider gets a `pull_model_if_missing()` method for better UX.
- No other changes. The provider abstraction is solid.

### 4.8 `agent/safety/` -- new package

#### `agent/safety/scope_enforcer.py`

Extracted and enhanced from `tools/scope_checker.py`. The enforcer is injected into every component that touches the network:
- Built-in tools (as today)
- Dynamic tool forge (validates scripts before execution)
- Sandbox runtime (network filtering)

#### `agent/safety/authorization.py`

Mission authorization levels, configured in the scope file:

```
Level 0 -- RECON ONLY: passive scanning, no exploitation
Level 1 -- SCAN: active scanning, no exploitation
Level 2 -- EXPLOIT: exploitation allowed, no persistence
Level 3 -- FULL: persistence, lateral movement, exfiltration allowed
```

This replaces the blanket `BLOCKED_MODULE_PATTERNS` list in `metasploit.py`. At Level 3, post-exploitation modules are allowed. At Level 0, even active nmap scans are blocked.

The authorization level is set in the scope file and enforced structurally. The LLM cannot override it.

#### `agent/safety/audit.py`

Every action (tool call, dynamic script execution, network connection) is logged to an immutable audit trail. This is separate from the session log -- it is a compliance artifact that cannot be tampered with by the agent.

---

## 5. Reasoning Engine -- How It Works

### The PAOR Loop

Each turn of the orchestrator runs through four phases:

```
  +--------+       +---------+       +-----------+       +-----------+
  |  PLAN  | ----> |   ACT   | ----> |  OBSERVE  | ----> |  REFLECT  |
  +--------+       +---------+       +-----------+       +-----------+
      ^                                                        |
      |                                                        |
      +--------------------------------------------------------+
                        (replan based on reflection)
```

#### Phase 1: PLAN

Input to LLM:
- System prompt (slim: role, rules, tool list -- no kill chain)
- State summary from MissionMemory (hosts found, ports open, vulns identified, hypotheses pending)
- Attack graph summary (what chains are forming)
- Last reflection output (what was learned, what should change)

Output from LLM:
- A plan: 1-3 specific actions with rationale
- Format: JSON list of `{tool, parameters, rationale}`

For Ollama/local models: the planner prompt is shorter and more structured, with explicit JSON schema examples to guide output format.

#### Phase 2: ACT

The orchestrator executes the planned actions:
- Validates each action (scope check, authorization level)
- Executes tools in parallel where possible (as today)
- Captures raw results
- Updates timeline

If the plan includes `forge_tool`, the dynamic tool forge handles generation, validation, and sandboxed execution.

#### Phase 3: OBSERVE

Automated (no LLM call):
- Parse tool results using per-tool parsers
- Extract findings, update MissionMemory
- Update AttackGraph (new nodes and edges)
- Detect notable events (critical finding, new access gained, tool failure)

#### Phase 4: REFLECT

Input to LLM:
- Tool results (raw, for the most recent actions)
- New findings extracted (structured)
- Updated attack graph summary
- The plan that was executed

Output from LLM:
- What was learned
- Whether the plan succeeded or failed
- What hypotheses were confirmed or refuted
- What should be tried next (feeds back into PLAN)

### Adaptation to Local LLMs

The reasoning engine detects the provider type and adjusts:

| Aspect | Cloud LLM (Anthropic, OpenAI) | Local LLM (Ollama) |
|--------|-------------------------------|---------------------|
| Plan format | Free-form JSON with rationale | Strict JSON schema with examples |
| Reflect depth | Full analysis | Key-value extraction only |
| Strategist frequency | Every 5 turns | Every 10 turns |
| Context budget | 80K tokens | 4K-8K tokens |
| State summary | Detailed | Compressed bullet points |

The system prompt for local models is radically different: shorter, more explicit, with more examples and less prose. This is a hard requirement -- a 7B model cannot follow 318 lines of instructions.

### When Does the Mission End?

The orchestrator tracks completion conditions:
1. All discovered targets have been assessed
2. All hypotheses have been tested or marked as untestable
3. The strategist has confirmed no unexplored high-value paths remain
4. The agent explicitly signals completion

OR any hard stop:
- Max turns reached
- Human abort
- Critical exploit confirmed (optional fast-path to reporting)

---

## 6. Dynamic Tool Generation -- Detailed Design

### Forge Workflow

```
  Agent calls forge_tool(description, target, constraints)
          |
          v
  +-------------------+
  |  LLM generates    |
  |  Python script    |
  |  (with template)  |
  +--------+----------+
           |
           v
  +-------------------+
  |  Static Analysis  |
  |  (AST parsing)    |
  |                   |
  |  Check:           |
  |  - Forbidden      |
  |    imports         |
  |  - Network calls  |
  |    to non-scope   |
  |  - File writes    |
  |    outside session|
  |  - Code length    |
  |    < MAX_LINES    |
  +--------+----------+
           |
       pass|fail --> return error to agent
           |
           v
  +-------------------+
  |  Scope Validation |
  |                   |
  |  Extract all IPs, |
  |  domains, URLs    |
  |  from script and  |
  |  verify against   |
  |  scope            |
  +--------+----------+
           |
       pass|fail --> return error to agent
           |
           v
  +-------------------+
  |  Sandbox Execute  |
  |                   |
  |  subprocess with: |
  |  - timeout        |
  |  - memory limit   |
  |  - restricted env |
  |  - stdout/stderr  |
  |    capture        |
  +--------+----------+
           |
           v
  Result returned as tool_result
  Script saved to session dir
  Execution logged to audit trail
```

### Static Analysis Rules

Allowed imports (allowlist):
```python
ALLOWED_IMPORTS = {
    # Network
    "requests", "urllib", "urllib.parse", "http.client",
    "socket", "ssl", "websockets", "aiohttp",
    # Data
    "json", "csv", "xml", "html", "base64", "hashlib",
    "re", "struct", "binascii",
    # Crypto
    "cryptography", "jwt", "hmac",
    # Utils
    "time", "datetime", "collections", "itertools",
    "string", "textwrap", "io", "sys",
}

FORBIDDEN_IMPORTS = {
    "os", "subprocess", "shutil", "pathlib",  # no filesystem/process access
    "ctypes", "importlib", "eval", "exec",    # no dynamic code execution
    "pickle", "shelve",                       # no deserialization
    "multiprocessing", "threading",           # no process/thread spawning
}
```

The forge template provides a `phantom_request(url, **kwargs)` helper that automatically enforces scope and rate limiting. Scripts use this instead of raw `requests.get()`.

### Sandbox Implementation

**Linux (primary target):**
- `subprocess.Popen` with `preexec_fn` setting resource limits via `resource` module
- Network namespace via `unshare` (if available) or iptables rules limiting outbound to scope IPs only
- `/tmp/phantom-sandbox-XXXX` as the only writable directory
- `PHANTOM_API_KEY`, `ANTHROPIC_API_KEY`, etc. stripped from environment

**Windows (development):**
- `subprocess.Popen` with `CREATE_SUSPENDED` + job object for memory/CPU limits
- Windows Firewall rules (if running elevated) or accept-risk-and-log
- Temp directory as only writable path
- Environment scrubbed of API keys

**Fallback (no sandboxing available):**
- Log a warning: "Dynamic tool execution without sandboxing -- accepting risk"
- Still enforce: timeout, environment scrubbing, static analysis
- This is the Ollama-on-laptop scenario. Pragmatism over purity.

### Tool Spec for forge_tool

```python
TOOL_SPEC = {
    "name": "forge_tool",
    "description": (
        "Generate and execute a custom Python script for a task that no built-in "
        "tool can handle. Describe what you need, specify the target, and the "
        "forge will generate, validate, sandbox, and execute the script. "
        "Use this for: custom API testing, protocol-specific fuzzing, "
        "data extraction, encoding/decoding, or any novel attack technique."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "description": {
                "type": "string",
                "description": (
                    "Detailed description of what the script should do. "
                    "Include: target URL/IP, expected input/output format, "
                    "specific techniques to use."
                ),
            },
            "target": {
                "type": "string",
                "description": "Primary target (must be in scope)",
            },
            "language": {
                "type": "string",
                "enum": ["python"],
                "description": "Script language (currently only Python)",
            },
            "timeout": {
                "type": "integer",
                "default": 60,
                "description": "Execution timeout in seconds",
            },
        },
        "required": ["description", "target"],
    },
}
```

---

## 7. State and Memory Flow

### Data Flow Diagram

```
  Tool Execution
       |
       | raw output (string)
       v
  Result Parser (per-tool)
       |
       | structured Findings + TargetInfo
       v
  MissionMemory
       |
       +---> Finding added to findings dict
       +---> TargetInfo updated (new ports, services, technologies)
       +---> ActionRecord added to actions dict
       |
       v
  AttackGraph
       |
       +---> New nodes (host, service, vuln) added
       +---> Edges added where relationships are clear
       |     (e.g., nmap finds port 80 -> host RUNS service)
       |
       v
  Context Manager
       |
       | Builds prompt with:
       | - State summary (from MissionMemory.summary_for_context())
       | - Graph summary (from AttackGraph.summary())
       | - Recent conversation (last 2-3 turns)
       | - Current plan
       |
       v
  LLM (Plan / Reflect / Strategize)
       |
       | Structured output
       v
  Orchestrator
       |
       +---> Updates hypotheses in MissionMemory
       +---> Updates attack chains in AttackGraph
       +---> Feeds back into next Plan phase
```

### Persistence

All structured state is persisted to the session directory:

```
logs/<session>/
    state.json          # orchestrator state (turn, phase, plan)
    memory.json         # MissionMemory (findings, actions, hypotheses)
    graph.json          # AttackGraph (nodes, edges)
    timeline.json       # MissionTimeline (events)
    audit.jsonl         # immutable audit trail (append-only)
    agent.log           # debug log (as today)

    # Tool outputs (as today)
    nmap_*.txt
    nuclei_*.json
    ffuf_*.json
    ...

    # Dynamic tool scripts
    forge/
        script_001.py
        script_001_output.txt
        script_002.py
        ...

    # Reports
    report.html
    report.md
    report.pdf
```

Resume capability: loading `state.json` + `memory.json` + `graph.json` restores the full mission state. The conversation history in `state.json` is kept minimal (last N turns) since structured state is in memory.json.

---

## 8. Attack Graph and Timeline -- Building the Debrief

### Automatic Graph Construction

The attack graph is built incrementally, not retroactively:

| Tool | Nodes Created | Edges Created |
|------|---------------|---------------|
| run_recon | HOST nodes for each subdomain | -- |
| run_nmap | SERVICE nodes for each open port | HOST --RUNS--> SERVICE |
| run_whatweb | Updates SERVICE properties (technology, version) | -- |
| run_nuclei | VULNERABILITY nodes | SERVICE --HAS_VULN--> VULNERABILITY |
| run_hydra | CREDENTIAL nodes (if creds found) | CREDENTIAL --AUTHENTICATES--> ACCESS |
| run_sqlmap | VULNERABILITY + DATA nodes | SERVICE --HAS_VULN--> VULN, VULN --EXPOSES--> DATA |
| run_metasploit | ACCESS nodes (if exploit succeeds) | VULNERABILITY --EXPLOITS--> ACCESS |
| run_privesc_check | VULNERABILITY nodes (privesc vectors) | ACCESS --HAS_VULN--> VULNERABILITY |
| forge_tool | Depends on script | Manually added by reflector |

### Attack Chain Discovery

The `find_attack_chains()` method performs a depth-first traversal of the graph to find paths that represent real exploitation scenarios:

```
Entry (HOST/SERVICE) -> Vulnerability -> Exploit/Access -> Impact (DATA/CREDENTIAL/ACCESS)
```

Each chain is scored by:
- Highest CVSS score along the path
- Number of steps (shorter = more dangerous)
- Type of impact (data exfiltration > access > information disclosure)

### Debrief Output

When the mission completes, the debrief generator produces:

1. **Timeline** (Markdown + JSON): chronological list of every action, finding, and decision.
2. **Attack Graph** (Mermaid + DOT + JSON): visual representation of the attack surface and exploitation paths.
3. **Executive Report** (HTML + Markdown + PDF): replaces current `generate_report` with graph-aware reporting.

The Mermaid output can be rendered directly in GitHub/GitLab Markdown. The DOT output can be rendered with Graphviz. Both are text-based, no external dependencies required.

---

## 9. Scope and Safety Architecture

### Defense in Depth

```
Layer 1: Scope file parsing
  |  scope_enforcer.py reads scopes/current_scope.md
  |  Extracts targets + authorization level
  |
Layer 2: Tool-level enforcement (existing)
  |  Every built-in tool calls scope_guard() before network access
  |
Layer 3: Dynamic tool validation (new)
  |  forge.py validates all network targets in generated scripts
  |  via AST analysis before execution
  |
Layer 4: Runtime network filtering (new, best-effort)
  |  Sandbox restricts outbound connections to scope IPs
  |  Falls back to logging-only if OS primitives unavailable
  |
Layer 5: Audit trail (new)
  |  Every network connection, file write, and tool execution
  |  is logged immutably to audit.jsonl
```

### Authorization Levels (from scope file)

```markdown
# Scope File Format

## Targets
- https://target.example.com
- 192.168.1.0/24

## Authorization Level
Level: 2

## Notes
- WordPress admin panel is in scope
- Do not test the /payment endpoint
- Testing window: 2026-03-29 22:00 - 2026-03-30 06:00 UTC
```

Level enforcement:

| Level | Recon | Scanning | Exploitation | Persistence | Lateral Movement | Exfiltration |
|-------|-------|----------|--------------|-------------|------------------|--------------|
| 0     | Yes   | No       | No           | No          | No               | No           |
| 1     | Yes   | Yes      | No           | No          | No               | No           |
| 2     | Yes   | Yes      | Yes          | No          | No               | No           |
| 3     | Yes   | Yes      | Yes          | Yes         | Yes              | Yes          |

At Level 2, the metasploit tool allows `exploit/` modules but blocks `post/` and persistence. At Level 3, all module types are allowed (within scope).

---

## 10. Provider Abstraction

### Changes to Base Provider

```python
class BaseLLMProvider(ABC):
    MAX_RETRIES = 3
    RETRY_BACKOFF = 2.0
    TIMEOUT = 120

    @property
    @abstractmethod
    def context_window(self) -> int:
        """Maximum context window in tokens."""

    @property
    def supports_structured_output(self) -> bool:
        """Whether the provider supports JSON mode / structured output."""
        return False

    @property
    def supports_tool_calling(self) -> bool:
        """Whether the provider natively supports tool/function calling."""
        return True

    @abstractmethod
    def convert_tools(self, tools: list) -> list: ...

    @abstractmethod
    def call(self, messages: list, system_prompt: str, tools: list) -> tuple: ...

    def call_with_retry(self, messages, system_prompt, tools) -> tuple: ...
        # unchanged
```

### Provider-Specific Context Windows

| Provider | Default Model | Context Window |
|----------|---------------|----------------|
| Anthropic | claude-sonnet-4-6 | 200,000 |
| OpenAI | gpt-5.4 | 128,000 |
| Grok | grok-4-20-beta | 131,072 |
| Gemini | gemini-3.0-pro | 1,000,000 |
| Ollama | deepseek-v3.2:cloud | 8,192 (varies by model) |
| Mistral | mistral-large-latest | 128,000 |
| DeepSeek | deepseek-chat-v3.2 | 65,536 |

For Ollama, the context window should be read from the model metadata via `ollama show <model>` at startup, since it varies wildly between models.

---

## 11. Migration Path

### Phase 1: Foundation (non-breaking)

Add new modules alongside existing code. The existing `AgentClient.think()` loop continues to work.

1. Create `agent/memory/mission_memory.py` with the data structures
2. Create `agent/graph/attack_graph.py` and `agent/graph/timeline.py`
3. Add result parsers to each tool module (`parse_result()` functions)
4. Create `agent/safety/scope_enforcer.py` (extract from `scope_checker.py`)
5. Create `agent/safety/audit.py`

**Test gate:** All existing tests pass. New unit tests for memory, graph, and parsers.

### Phase 2: Reasoning Engine (parallel path)

Build the new orchestrator alongside the old one. Config flag to switch.

1. Create `agent/reasoning/planner.py`, `reflector.py`, `strategist.py`
2. Create `agent/memory/context_manager.py`
3. Create `agent/orchestrator.py` implementing the PAOR loop
4. Add config option: `engine: "v2" | "v3"` (default v2)
5. Write a minimal system prompt for v3 (replacing the 318-line behemoth)

**Test gate:** Run both engines against a test target (e.g., DVWA, Metasploitable). Compare coverage and findings.

### Phase 3: Dynamic Tool Forge

1. Create `agent/tools/forge.py`
2. Create `agent/sandbox/` with platform-specific sandbox implementations
3. Register `forge_tool` in the tool registry
4. Add static analysis validation
5. Add scope validation for generated scripts

**Test gate:** Forge generates, validates, and executes scripts against a test target. Scope violations are caught. Timeouts work.

### Phase 4: Debrief and Reporting

1. Extend `agent/tools/report.py` to consume AttackGraph and Timeline
2. Add Mermaid and DOT export to AttackGraph
3. Add timeline export to MissionTimeline
4. Update the report HTML template with graph visualization

**Test gate:** Reports include attack chains from the graph. Timeline is accurate.

### Phase 5: Cleanup and Cut

1. Remove the v2 `AgentClient` code path
2. Remove the 318-line system prompt
3. Remove the hardcoded initial user message from `main.py`
4. Remove the regex-based stall detector
5. Update `config.yaml.example` with new options
6. Update README.md
7. Tag v3.0.0

---

## 12. File-by-File Change Plan

### New Files

| File | Purpose |
|------|---------|
| `agent/orchestrator.py` | PAOR loop, replaces `agent_client.py` |
| `agent/reasoning/__init__.py` | Package init |
| `agent/reasoning/planner.py` | Tactical planning (1-3 step plans) |
| `agent/reasoning/reflector.py` | Post-action reflection and learning |
| `agent/reasoning/strategist.py` | Periodic high-level strategy review |
| `agent/memory/__init__.py` | Package init |
| `agent/memory/mission_memory.py` | Structured findings, actions, hypotheses |
| `agent/memory/context_manager.py` | Token-budget-aware prompt construction |
| `agent/graph/__init__.py` | Package init |
| `agent/graph/attack_graph.py` | Directed graph of attack surface |
| `agent/graph/timeline.py` | Chronological mission events |
| `agent/tools/forge.py` | Dynamic tool generation + validation |
| `agent/sandbox/__init__.py` | Package init |
| `agent/sandbox/runner.py` | Sandboxed script execution |
| `agent/sandbox/static_analysis.py` | AST-based script validation |
| `agent/safety/__init__.py` | Package init |
| `agent/safety/scope_enforcer.py` | Enhanced scope enforcement (extracted) |
| `agent/safety/authorization.py` | Authorization levels from scope file |
| `agent/safety/audit.py` | Immutable audit trail |
| `prompts/system_prompt_v3.txt` | Slim system prompt for v3 engine |
| `prompts/planner_prompt.txt` | Prompt template for planning phase |
| `prompts/reflector_prompt.txt` | Prompt template for reflection phase |
| `prompts/strategist_prompt.txt` | Prompt template for strategy phase |
| `prompts/forge_prompt.txt` | Prompt template for script generation |
| `tests/test_mission_memory.py` | Unit tests for memory module |
| `tests/test_attack_graph.py` | Unit tests for graph module |
| `tests/test_forge.py` | Unit tests for dynamic tool forge |
| `tests/test_static_analysis.py` | Unit tests for script validation |
| `tests/test_orchestrator.py` | Integration tests for PAOR loop |
| `tests/test_context_manager.py` | Unit tests for context manager |

### Modified Files

| File | Changes |
|------|---------|
| `agent/main.py` | Add `--engine v2/v3` flag. When v3: instantiate `Orchestrator` instead of `AgentClient`. Remove hardcoded initial message -- orchestrator handles mission start. Keep session init, config loading, logging setup unchanged. |
| `agent/agent_client.py` | No changes during migration (kept as v2 engine). Removed in Phase 5. |
| `agent/providers/base.py` | Add `context_window`, `supports_structured_output`, `supports_tool_calling` properties. |
| `agent/providers/ollama_provider.py` | Add `context_window` property (query from `ollama show`). Add `supports_structured_output` (depends on model). |
| `agent/providers/anthropic_provider.py` | Add `context_window` property (200K). |
| `agent/providers/openai_provider.py` | Add `context_window` property. |
| `agent/providers/gemini_provider.py` | Add `context_window` property. |
| `agent/providers/mistral_provider.py` | Add `context_window` property. |
| `agent/providers/__init__.py` | No changes. |
| `agent/tools/__init__.py` | Register `forge_tool`. Add `get_result_parser(tool_name)` function that returns the parser for a given tool. |
| `agent/tools/nmap_scan.py` | Add `parse_result(raw: str) -> list[Finding]` function. |
| `agent/tools/nuclei.py` | Add `parse_result(raw: str) -> list[Finding]` function. |
| `agent/tools/ffuf.py` | Add `parse_result(raw: str) -> list[Finding]` function. |
| `agent/tools/recon.py` | Add `parse_result(raw: str) -> list[Finding]` function (extracts discovered subdomains as INFO findings). |
| `agent/tools/whatweb_tool.py` | Add `parse_result(raw: str) -> list[Finding]` function. |
| `agent/tools/wpscan.py` | Add `parse_result(raw: str) -> list[Finding]` function. |
| `agent/tools/sqlmap.py` | Add `parse_result(raw: str) -> list[Finding]` function. |
| `agent/tools/hydra_tool.py` | Add `parse_result(raw: str) -> list[Finding]` function. |
| `agent/tools/jwt_tool.py` | Add `parse_result(raw: str) -> list[Finding]` function. |
| `agent/tools/graphql_enum.py` | Add `parse_result(raw: str) -> list[Finding]` function. |
| `agent/tools/metasploit.py` | Add `parse_result(raw: str) -> list[Finding]` function. Replace `BLOCKED_MODULE_PATTERNS` with authorization-level check from `safety/authorization.py`. |
| `agent/tools/privesc.py` | Add `parse_result(raw: str) -> list[Finding]` function. |
| `agent/tools/scope_checker.py` | Keep as-is for v2 compatibility. v3 uses `safety/scope_enforcer.py` which imports the core logic. |
| `agent/tools/report.py` | Add graph-aware reporting: accept `AttackGraph` and `MissionTimeline` data. Generate Mermaid diagrams in report. Keep backward compatibility (if called without graph data, generate report from raw findings as today). |
| `agent/tools/stealth.py` | No changes. |
| `agent/tools/rate_limiter.py` | No changes. |
| `agent/tools/http_utils.py` | No changes. |
| `agent/tools/logs_helper.py` | No changes. |
| `agent/tools/read_log.py` | No changes. |
| `agent/tools/screenshot.py` | No changes. |
| `agent/tools/auth_manager.py` | No changes. |
| `agent/tools/mission_diff.py` | No changes. |
| `agent/tools/cvss_scorer.py` | No changes. |
| `agent/tools/cleanup.py` | No changes. |
| `agent/tools/payloads.py` | No changes. |
| `agent/tools/human_input.py` | No changes. |
| `agent/tools/set_phish.py` | No changes. |
| `agent/tools/bettercap.py` | No changes. |
| `agent/tools/zphisher.py` | No changes. |
| `agent/utils/validation.py` | No changes. |
| `config.yaml.example` | Add: `engine: "v3"`, `authorization_level: 2`, `strategist_interval: 5`, `forge_timeout: 60`, `forge_max_lines: 200`. |
| `requirements.txt` | No new dependencies for Phase 1-2. Phase 3 may add `restrictedpython` (optional, for enhanced static analysis). |
| `pyproject.toml` | Version bump to 3.0.0 at Phase 5. |

### Deleted Files (Phase 5 only)

| File | Reason |
|------|--------|
| `agent/agent_client.py` | Replaced by `agent/orchestrator.py` |
| `prompts/system_prompt.txt` | Replaced by `prompts/system_prompt_v3.txt` + role-specific prompts |

---

## 13. Architectural Decision Records

### ADR-001: PAOR Loop Over Simple Tool Loop

**Status:** Proposed

**Context:** The current architecture sends the full conversation + system prompt to the LLM each turn and executes whatever tools it requests. The LLM's behavior is entirely controlled by the 318-line system prompt, which encodes a fixed kill chain. This works for scripted assessments but prevents genuine autonomous reasoning.

**Decision:** Replace the simple "call LLM -> execute tools -> append results" loop with a Plan-Act-Observe-Reflect (PAOR) loop. Each phase has a distinct purpose and prompt. Planning and reflection are separate LLM calls with focused prompts.

**Consequences:**
- More LLM calls per logical turn (2-3 instead of 1). This costs more API credits and is slower. For Ollama, this is significant -- each call may take 30-60s with a large model.
- Plans are explicit and logged, making the agent's reasoning auditable.
- Reflection enables genuine adaptation without hardcoded branching rules.
- The system prompt shrinks dramatically (role + rules only), which benefits local LLMs with small context windows.
- Trade-off: plan quality depends entirely on LLM capability. A weak local model may produce poor plans. Mitigation: the planner prompt includes concrete examples and a constrained output schema.

### ADR-002: Structured Memory Over Conversation History

**Status:** Proposed

**Context:** The current architecture's only state is the conversation history. Context compaction truncates old tool results after N turns, causing the agent to forget discoveries. There is no semantic understanding of what has been found -- the stall detector counts regex matches for severity tags.

**Decision:** Introduce `MissionMemory` as an explicit, structured knowledge base that exists outside the conversation. Tool results are parsed into structured `Finding` objects. The conversation can be pruned aggressively because knowledge is preserved in memory.

**Consequences:**
- Each tool needs a result parser. This is ~15 parsers to write, each relatively simple (regex extraction from known output formats).
- The context manager must decide what subset of memory to inject into each LLM prompt. This is a new source of complexity.
- Resume capability improves dramatically -- restoring `memory.json` is more reliable than replaying a truncated conversation.
- Trade-off: parsers can miss findings if tool output format changes. Mitigation: parsers are fail-soft (raw output is still available via `read_log`).

### ADR-003: Dynamic Tool Forge with Sandbox

**Status:** Proposed

**Context:** The project vision calls for "dynamic tool generation -- when Phantom encounters something its built-in tools can't handle, it writes and executes custom scripts on the fly." The current architecture has no mechanism for this.

**Decision:** Implement a `DynamicToolForge` that generates Python scripts via the LLM, validates them via AST-based static analysis, and executes them in a sandboxed subprocess. The forge is itself a tool in the registry.

**Consequences:**
- The agent can handle novel situations (custom APIs, unusual protocols, non-standard auth flows) without new built-in tools.
- Sandbox implementation varies by platform. Linux has strong primitives (namespaces, seccomp). Windows has weaker isolation. The sandbox is best-effort, not guaranteed.
- Static analysis can be bypassed by sufficiently creative code. The allowlist approach (deny by default, allow specific imports) reduces this risk but limits what scripts can do.
- Generated scripts may be buggy. The forge should retry once with error feedback if a script fails.
- Trade-off: this is the highest-risk component. A sandbox escape + scope bypass would allow arbitrary code execution against arbitrary targets. Defense-in-depth (static analysis + scope validation + runtime network filtering + audit trail) mitigates but does not eliminate this risk.

### ADR-004: Authorization Levels Over Module Blocklists

**Status:** Proposed

**Context:** The metasploit tool blocks entire module categories (`post/`, `persistence`, `backdoor`, etc.) regardless of context. The vision calls for "full exploitation -- persistence, lateral movement, exfiltration, all autonomous." A blanket blocklist prevents this.

**Decision:** Replace category-based blocklists with scope-file-defined authorization levels (0-3). Higher levels unlock more dangerous capabilities. Level is set by the human operator before mission start.

**Consequences:**
- The operator must explicitly opt in to dangerous capabilities. This is a conscious decision, not a default.
- At Level 3, the agent can perform persistence and lateral movement. This is powerful and dangerous. The scope file serves as the authorization contract.
- The authorization level is checked in code, not in the system prompt. The LLM cannot escalate its own authorization.
- Trade-off: more configuration burden on the operator. Mitigation: default to Level 1 (scan only). The agent can request elevation via `request_human_input` if it believes higher access would be valuable.

### ADR-005: Attack Graph as First-Class Data Structure

**Status:** Proposed

**Context:** The system prompt asks the LLM to "correlate findings into attack chains" in prose. This is unreliable, especially with smaller models. There is no structured representation of the attack surface or exploitation paths.

**Decision:** Introduce an explicit `AttackGraph` (directed graph with typed nodes and edges) that is built incrementally during the mission. Tool result parsers create nodes and edges. The strategist reviews the graph to identify attack chains.

**Consequences:**
- Attack chains are computed algorithmically (graph traversal), not generated by the LLM. This is deterministic and reliable.
- The graph provides structured input for the debrief report, replacing prose-based chain descriptions.
- Graph construction requires understanding tool output formats to create correct edges. Some relationships (e.g., "this credential works on that service") can only be established by the reflector/LLM, not by parsers alone.
- Trade-off: graph maintenance adds complexity to every tool execution. Mitigation: graph updates are best-effort -- if a parser fails to create edges, the reflector can add them later.

---

## Appendix: Slim System Prompt for v3 (Draft)

```
You are Phantom, an autonomous penetration testing agent. You think freely,
adapt your strategy based on findings, and chain exploits into real attack paths.

RULES (absolute, never broken):
1. Act ONLY within the authorized scope. The scope_enforcer blocks out-of-scope actions.
2. Log everything. Every action is recorded to the audit trail.
3. When built-in tools cannot solve a problem, use forge_tool to create a custom script.
4. After every action, analyze what you learned and how it changes your strategy.
5. Build attack chains, not isolated findings. Think: entry point -> exploitation -> impact.

AVAILABLE TOOLS:
{tool_list}

CURRENT STATE:
{state_summary}

ATTACK GRAPH:
{graph_summary}

PENDING HYPOTHESES:
{hypotheses}

YOUR LAST PLAN:
{last_plan}

Decide what to do next. Output a JSON plan:
[
  {"tool": "tool_name", "parameters": {...}, "rationale": "why this action now"}
]
```

This is approximately 40 lines instead of 318. The state summary, graph summary, and hypotheses are injected by the context manager from structured memory. The LLM reasons about what to do; it does not follow a script.

For Ollama/local models, the prompt is even shorter, with a concrete example plan included to guide output format.
