"""Templates for LLM-generated scripts in the Dynamic Tool Forge.

This module defines:
- The allowed imports whitelist (formatted for prompt injection)
- The prompt template that instructs the LLM how to write safe scripts
- The wrapper that captures output in a standard JSON format
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Allowed imports whitelist
# ---------------------------------------------------------------------------

ALLOWED_IMPORTS: frozenset[str] = frozenset(
    {
        # Network
        "requests",
        "socket",
        "ssl",
        "urllib",
        "urllib.parse",
        "urllib.request",
        "http",
        "http.client",
        # Data
        "json",
        "csv",
        "xml",
        "xml.etree.ElementTree",
        "html",
        "html.parser",
        "base64",
        "hashlib",
        "hmac",
        "re",
        "struct",
        "binascii",
        # Utils
        "time",
        "datetime",
        "collections",
        "itertools",
        "string",
        "textwrap",
        "io",
        "math",
        "ipaddress",
    }
)

# Formatted for injection into prompts
ALLOWED_IMPORTS_LIST: str = "\n".join(f"  - {m}" for m in sorted(ALLOWED_IMPORTS))


# ---------------------------------------------------------------------------
# Script generation prompt
# ---------------------------------------------------------------------------

SCRIPT_GENERATION_PROMPT: str = """\
You are a code generator for an ethical red-team agent.  Write a single,
self-contained Python script that accomplishes the task described below.

=== TASK ===
{description}

=== TARGET ===
{target}

=== CONTEXT ===
{context}

=== RULES (MANDATORY -- violation causes rejection) ===
1. ONLY use these imports:
{allowed_imports}

2. NEVER use any of the following -- they will be blocked:
   os.system, subprocess, shutil.rmtree, eval, exec, compile,
   __import__, importlib, ctypes, pickle, shelve, multiprocessing,
   threading.Thread, globals(), locals(), getattr with dunder names

3. All network requests MUST target ONLY: {target}
   Do NOT contact any other host, IP, or domain.

4. Print your results to stdout as structured text.
   Use print() -- do NOT write files.

5. Handle exceptions gracefully. Never let the script crash silently.

6. Keep the script under 200 lines.

7. Do NOT include shebangs, if __name__ blocks, or argparse.
   The script runs directly top-to-bottom.

8. Set timeouts on all network operations (max 15 seconds per request).

=== OUTPUT FORMAT ===
Write ONLY the Python code. No markdown fences, no explanations.
Start with imports, then logic, then print results.
"""


# ---------------------------------------------------------------------------
# Script wrapper -- injected around generated code before execution
# ---------------------------------------------------------------------------

SCRIPT_WRAPPER: str = """\
import sys
import json as _json
import traceback as _traceback

# --- Scope enforcement (injected by forge) ---
_SCOPE_TARGETS = {scope_targets_json}

def _check_scope(url):
    \"\"\"Verify a URL target is in scope before making requests.\"\"\"
    from urllib.parse import urlparse
    host = urlparse(url).hostname or url.split("/")[0].split(":")[0]
    host = host.lower()
    for t in _SCOPE_TARGETS:
        if host == t or host.endswith("." + t):
            return True
    raise RuntimeError(
        f"SCOPE VIOLATION: {{host}} is not in scope. "
        f"Authorized targets: {{_SCOPE_TARGETS}}"
    )

# Patch requests to enforce scope at runtime
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

# --- Capture output ---
_output_lines = []
_original_print = print

def print(*args, **kwargs):  # noqa: A001 -- intentional override
    import io as _io
    buf = _io.StringIO()
    kwargs["file"] = buf
    _original_print(*args, **kwargs)
    line = buf.getvalue()
    _output_lines.append(line)
    _original_print(line, end="", file=sys.stdout)

# --- Agent script begins ---
try:
{indented_code}
except Exception as _exc:
    _original_print(
        _json.dumps({{
            "status": "error",
            "output": "\\n".join(_output_lines),
            "errors": [f"{{type(_exc).__name__}}: {{_exc}}"],
            "traceback": _traceback.format_exc(),
        }}),
        file=sys.stderr,
    )
    sys.exit(1)
else:
    _original_print(
        _json.dumps({{
            "status": "success",
            "output": "\\n".join(_output_lines),
            "errors": [],
        }}),
        file=sys.stderr,
    )
"""


def build_generation_prompt(
    description: str,
    target: str,
    context: str,
) -> str:
    """Build the full prompt for the LLM to generate a script."""
    return SCRIPT_GENERATION_PROMPT.format(
        description=description,
        target=target,
        context=context or "No additional context.",
        allowed_imports=ALLOWED_IMPORTS_LIST,
    )


def wrap_script(code: str, scope_targets: list[str]) -> str:
    """Wrap generated code with scope enforcement and output capture."""
    import json

    indented = "\n".join("    " + line for line in code.splitlines())
    return SCRIPT_WRAPPER.format(
        scope_targets_json=json.dumps(scope_targets),
        indented_code=indented,
    )
