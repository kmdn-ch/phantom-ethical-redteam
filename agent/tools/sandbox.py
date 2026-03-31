"""Sandbox runtime for dynamically generated scripts.

Provides process isolation, resource limiting, environment scrubbing, and
network target validation for scripts produced by the Dynamic Tool Forge.
Cross-platform: Linux (better isolation) and Windows (best-effort).
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Env vars that MUST be stripped -- they may contain secrets
_SENSITIVE_ENV_PREFIXES: tuple[str, ...] = (
    "ANTHROPIC_",
    "OPENAI_",
    "XAI_",
    "PHANTOM_API",
    "AWS_",
    "AZURE_",
    "GCP_",
    "GOOGLE_",
    "DOCKER_",
    "NPM_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITLAB_",
    "SLACK_",
    "DISCORD_",
    "TELEGRAM_",
    "DATABASE_URL",
    "DB_",
    "REDIS_",
    "MONGO",
    "SECRET",
    "PASSWORD",
    "PRIVATE_KEY",
    "API_KEY",
    "ACCESS_KEY",
    "TOKEN",
)

# Patterns for extracting IPs and domains from source code
_IP_PATTERN = re.compile(
    r"""(?<![.\w])"""  # not preceded by word/dot
    r"""(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    r"""(?![.\w])""",  # not followed by word/dot
)

_DOMAIN_PATTERN = re.compile(
    r"""(?:https?://|wss?://|ftp://)?"""  # optional scheme
    r"""([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"""
    r"""(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)""",
)

# Well-known domains that should never appear in generated scripts
_EXFILTRATION_DOMAINS: frozenset[str] = frozenset(
    {
        "pastebin.com",
        "transfer.sh",
        "ngrok.io",
        "ngrok.app",
        "webhook.site",
        "requestbin.com",
        "pipedream.net",
        "burpcollaborator.net",
        "interactsh.com",
        "oastify.com",
        "dnslog.cn",
    }
)

MAX_SCRIPT_SIZE: int = 50_000  # 50 KB
MAX_SCRIPT_LINES: int = 500


# ---------------------------------------------------------------------------
# SandboxConfig
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxConfig:
    """Configuration for a sandbox execution environment."""

    timeout: int = 60  # seconds
    max_memory_mb: int = 512
    max_output_bytes: int = 10_000_000  # 10 MB
    allowed_network_targets: tuple[str, ...] = ()
    workspace_dir: Optional[str] = None

    def effective_workspace(self) -> str:
        """Return workspace_dir or create a temp directory."""
        if self.workspace_dir:
            os.makedirs(self.workspace_dir, exist_ok=True)
            return self.workspace_dir
        return tempfile.mkdtemp(prefix="phantom-sandbox-")


# ---------------------------------------------------------------------------
# Environment construction
# ---------------------------------------------------------------------------


def create_sandbox_env() -> dict[str, str]:
    """Return a clean environment dict -- PATH only, no secrets.

    This is deliberately restrictive.  The subprocess inherits only what
    is explicitly passed, preventing API key / credential leakage.
    """
    env: dict[str, str] = {}

    # Minimal set of variables required for Python to function
    safe_keys = {"PATH", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP", "HOME", "LANG"}

    for key in safe_keys:
        val = os.environ.get(key)
        if val is not None:
            env[key] = val

    # Ensure Python doesn't create .pyc files in unexpected places
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Ensure deterministic hash seeding (reproducibility)
    env["PYTHONHASHSEED"] = "0"

    # Final paranoia pass: reject anything that slipped through
    for key in list(env.keys()):
        key_upper = key.upper()
        if any(
            key_upper.startswith(p) or key_upper == p for p in _SENSITIVE_ENV_PREFIXES
        ):
            del env[key]

    return env


# ---------------------------------------------------------------------------
# Resource limits (platform-specific)
# ---------------------------------------------------------------------------


def enforce_resource_limits(max_memory_mb: int = 512) -> None:
    """Set resource limits for the CURRENT process.

    Intended to be called via ``preexec_fn`` on Linux.  On Windows this is
    a no-op -- resource limits are enforced via Job Objects externally.
    """
    if platform.system() != "Linux":
        return

    try:
        import resource

        # Max virtual memory
        mem_bytes = max_memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))

        # CPU time limit (seconds) -- generous fallback; wall-time is the
        # primary timeout enforced by the parent process.
        resource.setrlimit(resource.RLIMIT_CPU, (300, 300))

        # No core dumps
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        # Limit number of open files
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 512))

        # Limit number of child processes
        resource.setrlimit(resource.RLIMIT_NPROC, (32, 64))

    except (ImportError, ValueError, OSError) as exc:
        logger.warning("Could not set resource limits: %s", exc)


# ---------------------------------------------------------------------------
# Network target validation
# ---------------------------------------------------------------------------


def validate_network_targets(
    code: str,
    scope_targets: list[str],
) -> tuple[bool, list[str]]:
    """Extract all IPs/domains from code and check against scope.

    Returns:
        (is_valid, list_of_violations)

    A violation is any IP or domain found in the code that does not match
    any entry in ``scope_targets``.  Localhost / loopback addresses are
    always allowed (the script may need to bind locally).
    """
    violations: list[str] = []
    found_targets: set[str] = set()

    # --- Extract IPs ---
    for match in _IP_PATTERN.finditer(code):
        ip = match.group(1)
        # Allow loopback
        if ip.startswith("127.") or ip == "0.0.0.0":
            continue
        found_targets.add(ip)

    # --- Extract domains ---
    for match in _DOMAIN_PATTERN.finditer(code):
        domain = match.group(1).lower()
        # Skip things that look like version strings (e.g. "2.7.18")
        if all(c.isdigit() or c == "." for c in domain):
            continue
        # Skip common non-target domains and Python dotted names
        if domain in {"example.com", "example.org", "localhost"}:
            continue
        # Skip Python module/attribute patterns (e.g., requests.get, json.dumps)
        _PYTHON_ROOTS = {
            "requests",
            "json",
            "urllib",
            "base64",
            "hashlib",
            "html",
            "xml",
            "struct",
            "binascii",
            "http",
            "ssl",
            "ipaddress",
            "time",
            "datetime",
            "collections",
            "itertools",
            "string",
            "textwrap",
            "io",
            "csv",
            "math",
            "re",
            "socket",
            "os",
            "sys",
            "self",
            "print",
            "result",
            "response",
            "data",
            "config",
            "status",
        }
        first_part = domain.split(".")[0]
        if first_part in _PYTHON_ROOTS:
            continue
        found_targets.add(domain)

    # --- Check exfiltration domains ---
    for target in found_targets:
        target_lower = target.lower()
        for exfil in _EXFILTRATION_DOMAINS:
            if target_lower == exfil or target_lower.endswith("." + exfil):
                violations.append(f"Exfiltration domain blocked: {target}")

    # --- Check against scope ---
    for target in found_targets:
        target_lower = target.lower()
        in_scope = False
        for allowed in scope_targets:
            allowed_lower = allowed.lower().strip()
            if not allowed_lower:
                continue
            # Exact match
            if target_lower == allowed_lower:
                in_scope = True
                break
            # Subdomain match (target is *.allowed)
            if target_lower.endswith("." + allowed_lower):
                in_scope = True
                break
            # CIDR / IP-in-range matching is left to the runtime scope
            # checker.  Here we do string comparison only.
            if target_lower == allowed_lower:
                in_scope = True
                break
        if not in_scope:
            violations.append(f"Target '{target}' is not in authorized scope")

    return (len(violations) == 0, violations)


# ---------------------------------------------------------------------------
# Sandbox execution
# ---------------------------------------------------------------------------


def execute_in_sandbox(
    script_path: str,
    config: SandboxConfig,
) -> dict:
    """Run a script in an isolated subprocess.

    Returns a dict with:
        exit_code, stdout, stderr, duration_seconds
    """
    if not os.path.isfile(script_path):
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Script file not found: {script_path}",
            "duration_seconds": 0.0,
        }

    env = create_sandbox_env()
    workspace = config.effective_workspace()

    # Platform-specific subprocess kwargs
    popen_kwargs: dict = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": env,
        "cwd": workspace,
    }

    is_linux = platform.system() == "Linux"
    is_windows = platform.system() == "Windows"

    if is_linux:
        # Use preexec_fn for resource limits on Linux
        def _preexec() -> None:
            enforce_resource_limits(config.max_memory_mb)

        popen_kwargs["preexec_fn"] = _preexec

    if is_windows:
        # CREATE_NEW_PROCESS_GROUP so we can kill the tree on timeout
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        popen_kwargs["creationflags"] = CREATE_NEW_PROCESS_GROUP

    start = time.monotonic()
    process: Optional[subprocess.Popen] = None

    try:
        process = subprocess.Popen(
            [sys.executable, script_path],
            **popen_kwargs,
        )

        stdout_bytes, stderr_bytes = process.communicate(timeout=config.timeout)
        duration = time.monotonic() - start

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

    except subprocess.TimeoutExpired:
        duration = time.monotonic() - start
        logger.warning(
            "Sandbox script timed out after %.1fs: %s", duration, script_path
        )
        # Kill the process tree
        if process is not None:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.communicate(timeout=5)
            except Exception:
                pass
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Script timed out after {config.timeout}s",
            "duration_seconds": round(duration, 2),
        }
    except Exception as exc:
        duration = time.monotonic() - start
        logger.error("Sandbox execution error: %s", exc)
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Sandbox execution error: {exc}",
            "duration_seconds": round(duration, 2),
        }

    # Truncate output to prevent memory exhaustion
    max_out = config.max_output_bytes
    if len(stdout) > max_out:
        stdout = stdout[:max_out] + "\n[TRUNCATED]"
    if len(stderr) > max_out:
        stderr = stderr[:max_out] + "\n[TRUNCATED]"

    return {
        "exit_code": process.returncode if process else -1,
        "stdout": stdout,
        "stderr": stderr,
        "duration_seconds": round(duration, 2),
    }
