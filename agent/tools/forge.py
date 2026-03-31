"""Dynamic Tool Forge -- generate, validate, and execute custom tools at runtime.

This is the core differentiating feature of Phantom.  When the agent encounters
a situation that no built-in tool can handle, it calls ``forge_tool`` to have
the LLM write a bespoke Python script, which is then statically analysed,
scope-checked, and executed in a sandboxed subprocess.

Security posture:  **every byte of LLM-generated code is untrusted input.**
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from agent.models.events import Event, EventType
from agent.tools.sandbox import (
    MAX_SCRIPT_LINES,
    MAX_SCRIPT_SIZE,
    SandboxConfig,
    execute_in_sandbox,
    validate_network_targets,
)
from agent.tools.scope_checker import scope_guard
from agent.tools.script_templates import (
    ALLOWED_IMPORTS,
    build_generation_prompt,
    wrap_script,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Output format preamble -- injected into every generation prompt so that the
# orchestrator's finding extractor can parse results without heuristics.
# ---------------------------------------------------------------------------

_OUTPUT_FORMAT_PREAMBLE: str = """\
=== REQUIRED OUTPUT FORMAT ===
Every interesting finding MUST be printed using one of these severity prefixes:

[CRITICAL] <title>: <detail>
[HIGH]     <title>: <detail>
[MEDIUM]   <title>: <detail>
[LOW]      <title>: <detail>
[INFO]     <title>: <detail>

Examples:
[CRITICAL] SQL Injection: Parameter 'id' reflects unsanitized in error output
[HIGH] Directory Traversal: /api/files?path=../../../../etc/passwd returns 200
[INFO] Technology: Apache/2.4.29 detected via Server header

Non-finding status lines (e.g. "Testing parameter x...") may use plain print.
Only findings that confirm a vulnerability or reveal actionable intelligence
need a severity prefix.
"""

# ---------------------------------------------------------------------------
# Attack category hints -- injected so the LLM knows what techniques to try
# per parameter type, rather than only doing what the description says.
# ---------------------------------------------------------------------------

_ATTACK_CATEGORY_HINTS: str = """\
=== ATTACK CATEGORIES TO TEST (where applicable) ===
Apply these checks against every relevant parameter or endpoint you find:

SSTI (Server-Side Template Injection):
  Payloads: {{7*7}}, ${{7*7}}, <%= 7*7 %>, #{{7*7}}, {{config}}
  Confirmation: if response contains "49" the expression was evaluated.

SQLi (SQL Injection):
  Payloads: ', ", 1' OR '1'='1, 1; DROP TABLE--, 1 AND SLEEP(5)--
  Confirmation: SQL error strings, boolean response differences, or time delays.

SSRF (Server-Side Request Forgery):
  Payloads in URL/file/src params: http://169.254.169.254/latest/meta-data/,
  http://localhost/, http://0.0.0.0/, http://[::1]/
  Confirmation: cloud metadata content, internal service banners, or status 200.

Path Traversal:
  Payloads: ../../../etc/passwd, ....//....//etc/passwd, %2e%2e%2f%2e%2e%2f
  Confirmation: /etc/passwd content (root: or daemon: lines) in response body.

XXE (XML External Entity):
  Apply when Content-Type is application/xml or text/xml.
  Payload: <!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  Confirmation: file contents appear in response.

Open Redirect:
  Payloads in redirect/next/url/return params: //evil.com, https://evil.com,
  /\\evil.com
  Confirmation: Location header points to injected host, or response body
  contains the injected URL.
"""

# ---------------------------------------------------------------------------
# Tool spec -- registered alongside all other Phantom tools
# ---------------------------------------------------------------------------

TOOL_SPEC: dict[str, Any] = {
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
                "description": "Primary target (must be in scope).",
            },
            "context": {
                "type": "string",
                "description": (
                    "Optional additional context -- previous findings, "
                    "discovered services, credentials, etc."
                ),
                "default": "",
            },
            "timeout": {
                "type": "integer",
                "description": "Execution timeout in seconds (default 60, max 300).",
                "default": 60,
            },
        },
        "required": ["description", "target"],
    },
}


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------


@dataclass
class ValidationResult:
    """Outcome of static analysis on LLM-generated code."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Blocked constructs
# ---------------------------------------------------------------------------

# Top-level modules that are NEVER allowed
_BLOCKED_MODULES: frozenset[str] = frozenset(
    {
        "os",
        "subprocess",
        "shutil",
        "pathlib",
        "ctypes",
        "importlib",
        "pickle",
        "shelve",
        "multiprocessing",
        "threading",
        "signal",
        "pty",
        "resource",
        "posix",
        "nt",
        "winreg",
        "mmap",
        "code",
        "codeop",
        "compileall",
    }
)

# Specific attribute accesses that are blocked even if the module is allowed
_BLOCKED_ATTR_CALLS: frozenset[str] = frozenset(
    {
        "os.system",
        "os.popen",
        "os.exec",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.spawn",
        "os.spawnl",
        "os.spawnle",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.run",
        "subprocess.check_output",
        "shutil.rmtree",
    }
)

# Built-in names that must never appear as function calls
_BLOCKED_BUILTINS: frozenset[str] = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "breakpoint",
    }
)

# Top-level allowed module roots (derived from ALLOWED_IMPORTS)
_ALLOWED_ROOTS: frozenset[str] = frozenset(m.split(".")[0] for m in ALLOWED_IMPORTS)


# ---------------------------------------------------------------------------
# AST-based static analysis
# ---------------------------------------------------------------------------


def _validate_script(code: str, scope_targets: list[str]) -> ValidationResult:
    """Parse the AST and walk all nodes looking for violations.

    This function treats the code as **completely untrusted**.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # --- Size checks ---
    if len(code) > MAX_SCRIPT_SIZE:
        errors.append(
            f"Script exceeds maximum size ({len(code)} > {MAX_SCRIPT_SIZE} bytes)"
        )
        return ValidationResult(valid=False, errors=errors)

    line_count = code.count("\n") + 1
    if line_count > MAX_SCRIPT_LINES:
        errors.append(
            f"Script exceeds maximum lines ({line_count} > {MAX_SCRIPT_LINES})"
        )
        return ValidationResult(valid=False, errors=errors)

    # --- Parse AST ---
    try:
        tree = ast.parse(code, filename="<forged_script>", mode="exec")
    except SyntaxError as exc:
        errors.append(f"Syntax error: {exc}")
        return ValidationResult(valid=False, errors=errors)

    # --- Walk all nodes ---
    for node in ast.walk(tree):
        # -- Import / ImportFrom --
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _BLOCKED_MODULES:
                    errors.append(f"Blocked import: {alias.name}")
                elif root not in _ALLOWED_ROOTS:
                    errors.append(f"Import not in allowlist: {alias.name}")

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root = node.module.split(".")[0]
                if root in _BLOCKED_MODULES:
                    errors.append(f"Blocked import: {node.module}")
                elif root not in _ALLOWED_ROOTS:
                    errors.append(f"Import not in allowlist: {node.module}")
            else:
                # `from . import X` -- relative imports are blocked
                errors.append("Relative imports are not allowed")

        # -- Dangerous built-in calls --
        elif isinstance(node, ast.Call):
            func = node.func
            # Direct call: eval(...), exec(...), compile(...)
            if isinstance(func, ast.Name) and func.id in _BLOCKED_BUILTINS:
                errors.append(f"Blocked built-in call: {func.id}()")

            # Attribute call: os.system(...), subprocess.Popen(...)
            if isinstance(func, ast.Attribute):
                full_name = _resolve_attr_name(func)
                if full_name:
                    for blocked in _BLOCKED_ATTR_CALLS:
                        if full_name == blocked or full_name.startswith(blocked + "."):
                            errors.append(f"Blocked call: {full_name}()")
                            break

        # -- Dunder attribute access (getattr(obj, '__class__'), etc.) --
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("__") and node.attr.endswith("__"):
                # Allow __init__ and __str__ which are common
                if node.attr not in {"__init__", "__str__", "__repr__", "__len__"}:
                    warnings.append(f"Suspicious dunder access: .{node.attr}")

        # -- String literals: check for IPs / domains --
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            # Delegate to network target validation -- collected below
            pass

    # --- Network target validation on string literals ---
    is_valid, violations = validate_network_targets(code, scope_targets)
    if not is_valid:
        for v in violations:
            errors.append(v)

    # --- Regex-based fallback for obfuscation attempts ---
    # Catches string concatenation tricks the AST walk might miss
    _fallback_patterns = [
        (r"\b__import__\b", "Hidden __import__ call"),
        (r"\beval\s*\(", "Hidden eval() call"),
        (r"\bexec\s*\(", "Hidden exec() call"),
        (r"\bcompile\s*\(", "Hidden compile() call"),
        (r"\bos\.system\b", "Hidden os.system call"),
        (r"\bsubprocess\b", "Hidden subprocess usage"),
        (r"\bimportlib\b", "Hidden importlib usage"),
        (r"\bctypes\b", "Hidden ctypes usage"),
        (r"\bpickle\b", "Hidden pickle usage"),
        (r"\bshelve\b", "Hidden shelve usage"),
        (r"ANTHROPIC_API_KEY|OPENAI_API_KEY|XAI_API_KEY", "API key reference"),
        (r"\bglobals\s*\(\s*\)", "globals() call"),
        (r"\blocals\s*\(\s*\)", "locals() call"),
    ]
    for pattern, description in _fallback_patterns:
        if re.search(pattern, code):
            # Only add if not already caught by AST
            msg = f"Regex fallback: {description}"
            if msg not in errors:
                errors.append(msg)

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )


def _resolve_attr_name(node: ast.Attribute, depth: int = 0) -> Optional[str]:
    """Resolve a dotted attribute chain (e.g. os.path.join) to a string.

    Returns None if the chain cannot be resolved (e.g., method on a
    computed expression).  Limits depth to prevent stack overflow on
    adversarial ASTs.
    """
    if depth > 10:
        return None
    if isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    if isinstance(node.value, ast.Attribute):
        parent = _resolve_attr_name(node.value, depth + 1)
        if parent:
            return f"{parent}.{node.attr}"
    return None


# ---------------------------------------------------------------------------
# DynamicToolForge
# ---------------------------------------------------------------------------


class DynamicToolForge:
    """Generate, validate, and execute custom tools at runtime.

    Parameters
    ----------
    llm_call : callable
        ``async def llm_call(prompt: str) -> str`` -- sends a prompt to the
        LLM and returns the raw text response.  The forge uses this to ask
        the LLM to write scripts.
    scope_checker : callable
        ``def scope_checker(target: str) -> bool`` -- returns True if the
        target is within the authorized mission scope.
    event_bus : optional
        If provided, the forge emits ``DYNAMIC_TOOL_CREATED`` events.
    mission_id : str
        Current mission ID (for event emission).
    session_dir : str
        Directory for storing generated scripts and output.
    scope_targets : list[str]
        List of authorized scope targets (IPs, domains, CIDRs).
    sandbox_config : SandboxConfig, optional
        Override default sandbox configuration.
    """

    MAX_RETRIES: int = 1

    def __init__(
        self,
        llm_call: Callable,
        scope_checker: Callable[[str], bool],
        event_bus: Optional[Any] = None,
        mission_id: str = "",
        session_dir: str = "",
        scope_targets: Optional[list[str]] = None,
        sandbox_config: Optional[SandboxConfig] = None,
    ) -> None:
        self.llm_call = llm_call
        self.scope_checker = scope_checker
        self.event_bus = event_bus
        self.mission_id = mission_id
        self.scope_targets: list[str] = list(scope_targets or [])
        self.executed_scripts: list[dict] = []

        # Session directory for scripts
        if session_dir:
            self._session_dir = session_dir
        else:
            self._session_dir = tempfile.mkdtemp(prefix="phantom-forge-")
        self._scripts_dir = os.path.join(self._session_dir, "forged_scripts")
        os.makedirs(self._scripts_dir, exist_ok=True)

        # Sandbox config
        self.sandbox_config = sandbox_config or SandboxConfig(
            allowed_network_targets=tuple(self.scope_targets),
            workspace_dir=os.path.join(self._session_dir, "sandbox_workspace"),
        )

    # ------------------------------------------------------------------
    # Public API -- the tool function
    # ------------------------------------------------------------------

    def forge_tool(
        self,
        description: str,
        target: str,
        context: str = "",
        timeout: int = 60,
    ) -> str:
        """The tool function registered in the tool registry.

        The LLM calls this like any other tool.  Returns the script
        output as a string (success or failure).
        """
        # --- Input validation ---
        if not description or not description.strip():
            return "ERROR: description is required and cannot be empty."

        if not target or not target.strip():
            return "ERROR: target is required and cannot be empty."

        target = target.strip()
        description = description.strip()
        context = (context or "").strip()

        # Clamp timeout
        timeout = max(10, min(timeout, 300))

        # --- Scope check on the declared target ---
        if not self.scope_checker(target):
            return f"BLOCKED: Target '{target}' is not in authorized scope."

        # --- Generate script ---
        code = self._generate_script(description, target, context)
        if code is None:
            return "ERROR: LLM failed to generate a script."

        # --- Validate ---
        validation = _validate_script(code, self.scope_targets)
        if not validation.valid:
            # Retry once with error feedback
            retry_code = self._retry_on_failure(
                description,
                error="; ".join(validation.errors),
                original_code=code,
            )
            if retry_code is not None:
                validation = _validate_script(retry_code, self.scope_targets)
                if validation.valid:
                    code = retry_code

            if not validation.valid:
                error_detail = "\n".join(f"  - {e}" for e in validation.errors)
                return f"BLOCKED: Generated script failed validation:\n{error_detail}"

        if validation.warnings:
            for w in validation.warnings:
                logger.warning("Forge validation warning: %s", w)

        # --- Wrap and write to disk ---
        wrapped = wrap_script(code, self.scope_targets)
        script_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()[:16]
        script_name = f"forge_{script_hash}.py"
        script_path = os.path.join(self._scripts_dir, script_name)

        try:
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(f"# Forged script: {description[:80]}\n")
                f.write(f"# Target: {target}\n")
                f.write(f"# Hash: {script_hash}\n\n")
                f.write(wrapped)
        except OSError as exc:
            return f"ERROR: Could not write script to disk: {exc}"

        # --- Execute in sandbox ---
        config = SandboxConfig(
            timeout=timeout,
            max_memory_mb=self.sandbox_config.max_memory_mb,
            max_output_bytes=self.sandbox_config.max_output_bytes,
            allowed_network_targets=tuple(self.scope_targets),
            workspace_dir=self.sandbox_config.effective_workspace(),
        )

        result = execute_in_sandbox(script_path, config)

        # --- Record for audit ---
        audit_record = {
            "timestamp": time.time(),
            "description": description,
            "target": target,
            "script_hash": script_hash,
            "script_path": script_path,
            "exit_code": result["exit_code"],
            "duration_seconds": result["duration_seconds"],
            "stdout_size": len(result["stdout"]),
            "stderr_size": len(result["stderr"]),
            "validation_warnings": validation.warnings,
        }
        self.executed_scripts.append(audit_record)
        self._write_audit(audit_record)

        # --- Emit event ---
        self._emit_created_event(description, target, script_hash, result)

        # --- If script failed, try once more ---
        if result["exit_code"] != 0:
            retry_code = self._retry_on_failure(
                description,
                error=result["stderr"][:2000],
                original_code=code,
            )
            if retry_code is not None:
                retry_validation = _validate_script(retry_code, self.scope_targets)
                if retry_validation.valid:
                    retry_wrapped = wrap_script(retry_code, self.scope_targets)
                    retry_hash = hashlib.sha256(retry_code.encode("utf-8")).hexdigest()[
                        :16
                    ]
                    retry_name = f"forge_{retry_hash}_retry.py"
                    retry_path = os.path.join(self._scripts_dir, retry_name)
                    try:
                        with open(retry_path, "w", encoding="utf-8") as f:
                            f.write(f"# Retry of: {description[:80]}\n")
                            f.write(f"# Original hash: {script_hash}\n\n")
                            f.write(retry_wrapped)
                    except OSError:
                        pass
                    else:
                        result = execute_in_sandbox(retry_path, config)
                        audit_record_retry = {
                            "timestamp": time.time(),
                            "description": f"[RETRY] {description}",
                            "target": target,
                            "script_hash": retry_hash,
                            "script_path": retry_path,
                            "exit_code": result["exit_code"],
                            "duration_seconds": result["duration_seconds"],
                            "stdout_size": len(result["stdout"]),
                            "stderr_size": len(result["stderr"]),
                        }
                        self.executed_scripts.append(audit_record_retry)
                        self._write_audit(audit_record_retry)

        # --- Format output ---
        return self._format_result(description, target, script_hash, result)

    # ------------------------------------------------------------------
    # Script generation
    # ------------------------------------------------------------------

    def _generate_script(
        self,
        description: str,
        target: str,
        context: str,
    ) -> Optional[str]:
        """Ask the LLM to write a Python script.

        Returns the raw code string or None on failure.
        """
        # Prepend the standardised output-format contract and attack-category
        # hints so every generated script produces finding lines that the
        # orchestrator's extractor can parse without guessing at the format.
        augmented_description = (
            _OUTPUT_FORMAT_PREAMBLE
            + "\n"
            + _ATTACK_CATEGORY_HINTS
            + "\n=== YOUR TASK ===\n"
            + description
        )

        prompt = build_generation_prompt(augmented_description, target, context)

        try:
            raw_response = self.llm_call(prompt)
        except Exception as exc:
            logger.error("LLM call failed during script generation: %s", exc)
            return None

        if not raw_response or not isinstance(raw_response, str):
            return None

        # Strip markdown fences if the LLM wraps the code
        code = self._extract_code(raw_response)
        if not code or not code.strip():
            return None

        return code.strip()

    # ------------------------------------------------------------------
    # Retry logic
    # ------------------------------------------------------------------

    def _retry_on_failure(
        self,
        description: str,
        error: str,
        original_code: str,
    ) -> Optional[str]:
        """Send the error back to the LLM for a corrected script.

        Returns corrected code or None.  Max 1 retry.
        """
        retry_prompt = (
            "Your previous script failed.  Fix the issues and return ONLY "
            "the corrected Python code (no markdown, no explanation).\n\n"
            f"=== ORIGINAL TASK ===\n{description}\n\n"
            f"=== ERROR ===\n{error}\n\n"
            f"=== ORIGINAL CODE ===\n{original_code}\n\n"
            "Remember: only use allowed imports, only contact in-scope targets, "
            "no os/subprocess/eval/exec/__import__."
        )

        try:
            raw = self.llm_call(retry_prompt)
        except Exception as exc:
            logger.warning("LLM retry call failed: %s", exc)
            return None

        if not raw or not isinstance(raw, str):
            return None

        code = self._extract_code(raw)
        return code.strip() if code and code.strip() else None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_code(text: str) -> str:
        """Extract Python code from an LLM response.

        Handles:
        - Raw code (no fences)
        - ```python ... ```
        - ``` ... ```
        """
        # Try to find fenced code blocks
        fenced = re.search(
            r"```(?:python)?\s*\n(.*?)```",
            text,
            re.DOTALL,
        )
        if fenced:
            return fenced.group(1)

        # If no fences, return the whole thing (strip leading/trailing whitespace)
        return text.strip()

    def _format_result(
        self,
        description: str,
        target: str,
        script_hash: str,
        result: dict,
    ) -> str:
        """Format sandbox execution result for return to the agent."""
        parts = [
            f"[Dynamic Tool] {description}",
            f"Target: {target}",
            f"Script: {script_hash}",
            f"Duration: {result['duration_seconds']}s",
            f"Exit code: {result['exit_code']}",
            "",
        ]

        if result["exit_code"] == 0:
            parts.append("=== OUTPUT ===")
            # Limit output size returned to the LLM context
            stdout = result["stdout"]
            if len(stdout) > 10_000:
                stdout = stdout[:10_000] + "\n[OUTPUT TRUNCATED]"
            parts.append(stdout)
        else:
            parts.append("=== FAILED ===")
            parts.append(result["stderr"][:5000])
            if result["stdout"]:
                parts.append("\n=== PARTIAL OUTPUT ===")
                parts.append(result["stdout"][:5000])

        return "\n".join(parts)

    def _emit_created_event(
        self,
        description: str,
        target: str,
        script_hash: str,
        result: dict,
    ) -> None:
        """Emit a DYNAMIC_TOOL_CREATED event if an event bus is available."""
        if self.event_bus is None:
            return

        try:
            event = Event(
                mission_id=self.mission_id,
                turn=0,
                event_type=EventType.DYNAMIC_TOOL_CREATED,
                phase="execution",
                tool_name="forge_tool",
                tool_input={
                    "description": description[:500],
                    "target": target,
                },
                tool_output=result.get("stdout", "")[:2000],
                tool_duration_ms=int(result.get("duration_seconds", 0) * 1000),
                target=target,
                title=f"Dynamic tool: {description[:100]}",
                description=description[:500],
                metadata={
                    "script_hash": script_hash,
                    "exit_code": result.get("exit_code", -1),
                },
            )
            self.event_bus.emit(event)
        except Exception as exc:
            logger.warning("Failed to emit DYNAMIC_TOOL_CREATED event: %s", exc)

    def _write_audit(self, record: dict) -> None:
        """Append an audit record to the session audit log."""
        audit_path = os.path.join(self._session_dir, "forge_audit.jsonl")
        try:
            with open(audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except OSError as exc:
            logger.warning("Could not write forge audit log: %s", exc)


# ---------------------------------------------------------------------------
# Module-level run() for tool registry compatibility
# ---------------------------------------------------------------------------

# Singleton forge instance -- initialized lazily by the orchestrator.
# The run() function below is a shim that defers to the singleton.
_forge_instance: Optional[DynamicToolForge] = None

# ---------------------------------------------------------------------------
# auto_exploit -- targeted confirmation script for a single finding
# ---------------------------------------------------------------------------

AUTO_EXPLOIT_TOOL_SPEC: dict[str, Any] = {
    "name": "auto_exploit",
    "description": (
        "Given a specific finding title and detail, automatically generates and executes "
        "a targeted Python script to confirm exploitability and measure impact. "
        "Use this immediately after a [HIGH] or [CRITICAL] finding to escalate the attack "
        "with a focused proof-of-concept. Returns structured output with a severity assessment."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "finding_title": {
                "type": "string",
                "description": "The finding title exactly as reported (e.g. 'SQL Injection').",
            },
            "finding_detail": {
                "type": "string",
                "description": (
                    "The finding detail line — endpoint, parameter, payload, and observed "
                    "evidence that triggered the finding."
                ),
            },
            "target": {
                "type": "string",
                "description": "Primary target (must be in scope).",
            },
            "timeout": {
                "type": "integer",
                "description": "Execution timeout in seconds (default 90, max 300).",
                "default": 90,
            },
        },
        "required": ["finding_title", "finding_detail", "target"],
    },
}


def init_forge(
    llm_call: Callable,
    scope_checker: Callable[[str], bool],
    event_bus: Optional[Any] = None,
    mission_id: str = "",
    session_dir: str = "",
    scope_targets: Optional[list[str]] = None,
    sandbox_config: Optional[SandboxConfig] = None,
) -> DynamicToolForge:
    """Initialize the global forge instance.  Called by the orchestrator."""
    global _forge_instance  # noqa: PLW0603
    _forge_instance = DynamicToolForge(
        llm_call=llm_call,
        scope_checker=scope_checker,
        event_bus=event_bus,
        mission_id=mission_id,
        session_dir=session_dir,
        scope_targets=scope_targets,
        sandbox_config=sandbox_config,
    )
    return _forge_instance


def run(
    description: str = "",
    target: str = "",
    context: str = "",
    timeout: int = 60,
    **kwargs: Any,
) -> str:
    """Tool registry entry point -- matches the pattern of all other tools.

    The forge must be initialized via ``init_forge()`` before this is called.
    """
    if _forge_instance is None:
        return (
            "ERROR: Dynamic Tool Forge is not initialized. "
            "The orchestrator must call init_forge() before forge_tool can be used."
        )

    return _forge_instance.forge_tool(
        description=description,
        target=target,
        context=context,
        timeout=timeout,
    )


def auto_exploit(
    finding_title: str = "",
    finding_detail: str = "",
    target: str = "",
    timeout: int = 90,
    **kwargs: Any,
) -> str:
    """Auto-exploit tool registry entry point.

    Takes a specific finding and generates + executes a targeted exploit script
    via the forge to confirm exploitability and measure impact.

    The forge must be initialized via ``init_forge()`` before this is called.
    """
    if _forge_instance is None:
        return (
            "ERROR: Dynamic Tool Forge is not initialized. "
            "The orchestrator must call init_forge() before auto_exploit can be used."
        )

    if not finding_title or not finding_title.strip():
        return "ERROR: finding_title is required."
    if not finding_detail or not finding_detail.strip():
        return "ERROR: finding_detail is required."
    if not target or not target.strip():
        return "ERROR: target is required."

    target = target.strip()

    # Scope check before any forge call.
    guard = scope_guard(target)
    if guard:
        return guard

    timeout = max(10, min(timeout, 300))

    # Build a focused exploit-confirmation description.
    exploit_description = (
        f"EXPLOIT CONFIRMATION TASK\n\n"
        f"Finding: {finding_title.strip()}\n"
        f"Detail: {finding_detail.strip()}\n\n"
        "Write a Python script that:\n"
        "1. Reproduces the exact condition described in the finding detail above.\n"
        "2. Attempts to escalate impact — e.g. extract data, bypass authentication,\n"
        "   read sensitive files, or trigger the full exploit chain.\n"
        "3. Measures and reports the blast radius (how many records/endpoints are affected).\n"
        "4. Prints each result with the correct severity prefix:\n"
        "   [CRITICAL] / [HIGH] / [MEDIUM] / [LOW] / [INFO]\n"
        "5. Prints a final [SEVERITY ASSESSMENT] line summarizing confirmed impact.\n\n"
        "Be precise: target the specific parameter/endpoint from the finding detail."
    )

    context = (
        f"This is an escalation script. The initial finding was:\n"
        f"  Title: {finding_title.strip()}\n"
        f"  Detail: {finding_detail.strip()}\n"
        "Focus exclusively on confirming and deepening exploitation of this specific issue."
    )

    raw_result = _forge_instance.forge_tool(
        description=exploit_description,
        target=target,
        context=context,
        timeout=timeout,
    )

    # Prepend a header that makes it easy for the orchestrator to correlate.
    header = (
        f"[auto_exploit] Escalation attempt for: {finding_title.strip()}\n"
        f"Target: {target}\n"
        f"{'-' * 60}\n"
    )
    return header + raw_result
