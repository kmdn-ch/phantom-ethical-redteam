"""Tests for agent.tools.forge — DynamicToolForge validation and sandbox env.

These tests load forge/sandbox/script_templates by file path to avoid
triggering agent.tools.__init__ (which auto-imports all v2 tools and
depends on sys.path hacks that don't work in pytest).
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_ROOT = Path(__file__).resolve().parent.parent / "agent" / "tools"
_AGENT = Path(__file__).resolve().parent.parent / "agent"

# Ensure agent/ root is on sys.path for absolute imports within modules
if str(_AGENT.parent) not in sys.path:
    sys.path.insert(0, str(_AGENT.parent))


def _load_file(name: str, filepath: Path):
    """Load a single .py file as a module without triggering package __init__."""
    spec = importlib.util.spec_from_file_location(
        name, filepath, submodule_search_locations=[]
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# Load sandbox and templates first (no problematic deps)
_sandbox_mod = _load_file("agent.tools.sandbox", _ROOT / "sandbox.py")
_templates_mod = _load_file(
    "agent.tools.script_templates", _ROOT / "script_templates.py"
)

# Now load forge — it imports sandbox + templates which are already in sys.modules
_forge_mod = _load_file("agent.tools.forge", _ROOT / "forge.py")

DynamicToolForge = _forge_mod.DynamicToolForge
ValidationResult = _forge_mod.ValidationResult
_validate_script = _forge_mod._validate_script
_resolve_attr_name = _forge_mod._resolve_attr_name

create_sandbox_env = _sandbox_mod.create_sandbox_env
validate_network_targets = _sandbox_mod.validate_network_targets

ALLOWED_IMPORTS = _templates_mod.ALLOWED_IMPORTS
build_generation_prompt = _templates_mod.build_generation_prompt
wrap_script = _templates_mod.wrap_script


# ===========================================================================
# _validate_script — allowed imports
# ===========================================================================


def test_validate_allowed_import_requests():
    code = 'import requests\nprint(requests.get("http://10.0.0.1").status_code)\n'
    result = _validate_script(code, ["10.0.0.1"])
    assert result.valid is True, f"Unexpected errors: {result.errors}"


def test_validate_allowed_import_json():
    code = "import json\nprint(json.dumps({'a': 1}))\n"
    result = _validate_script(code, [])
    assert result.valid is True


def test_validate_allowed_from_import():
    code = "from urllib.parse import urlparse\nprint(urlparse('http://10.0.0.1'))\n"
    result = _validate_script(code, ["10.0.0.1"])
    assert result.valid is True, f"Unexpected errors: {result.errors}"


# ===========================================================================
# _validate_script — blocked imports
# ===========================================================================


def test_validate_blocked_import_os():
    code = "import os\nos.listdir('/')\n"
    result = _validate_script(code, [])
    assert result.valid is False
    assert any("os" in e.lower() for e in result.errors)


def test_validate_blocked_import_subprocess():
    code = "import subprocess\nsubprocess.run(['ls'])\n"
    result = _validate_script(code, [])
    assert result.valid is False


def test_validate_blocked_import_pickle():
    code = "import pickle\n"
    result = _validate_script(code, [])
    assert result.valid is False


def test_validate_blocked_import_importlib():
    code = "import importlib\nimportlib.import_module('os')\n"
    result = _validate_script(code, [])
    assert result.valid is False


def test_validate_blocked_from_import():
    code = "from pathlib import Path\n"
    result = _validate_script(code, [])
    assert result.valid is False


def test_validate_blocked_relative_import():
    code = "from . import something\n"
    result = _validate_script(code, [])
    assert result.valid is False


# ===========================================================================
# _validate_script — blocked builtins
# ===========================================================================


def test_validate_blocked_eval():
    code = "result = eval('1+1')\n"
    result = _validate_script(code, [])
    assert result.valid is False
    assert any("eval" in e for e in result.errors)


def test_validate_blocked_exec():
    code = "exec('print(1)')\n"
    result = _validate_script(code, [])
    assert result.valid is False


def test_validate_blocked_compile():
    code = "compile('pass', '<string>', 'exec')\n"
    result = _validate_script(code, [])
    assert result.valid is False


def test_validate_blocked_dunder_import():
    code = "__import__('os')\n"
    result = _validate_script(code, [])
    assert result.valid is False


# ===========================================================================
# _validate_script — blocked attribute calls
# ===========================================================================


def test_validate_blocked_os_system():
    code = "import os\nos.system('whoami')\n"
    result = _validate_script(code, [])
    assert result.valid is False


# ===========================================================================
# _validate_script — scope checking
# ===========================================================================


def test_validate_in_scope_ip():
    code = 'import requests\nrequests.get("http://192.168.1.1/api")\n'
    result = _validate_script(code, ["192.168.1.1"])
    assert result.valid is True, f"Unexpected errors: {result.errors}"


def test_validate_out_of_scope_ip():
    code = 'import requests\nrequests.get("http://10.99.99.99/api")\n'
    result = _validate_script(code, ["192.168.1.1"])
    assert result.valid is False
    assert any("scope" in e.lower() for e in result.errors)


def test_validate_localhost_always_allowed():
    code = 'import requests\nrequests.get("http://127.0.0.1:8080/test")\n'
    result = _validate_script(code, ["10.0.0.1"])
    assert result.valid is True, f"Unexpected errors: {result.errors}"


def test_validate_exfiltration_domain_blocked():
    code = 'import requests\nrequests.get("https://webhook.site/test")\n'
    result = _validate_script(code, ["webhook.site"])
    assert result.valid is False
    assert any("exfiltration" in e.lower() for e in result.errors)


# ===========================================================================
# _validate_script — size limits
# ===========================================================================


def test_validate_too_large():
    code = "x = 1\n" * 60_000  # well over 50KB
    result = _validate_script(code, [])
    assert result.valid is False
    assert any("size" in e.lower() for e in result.errors)


def test_validate_too_many_lines():
    code = "\n".join(f"x{i} = {i}" for i in range(600))
    result = _validate_script(code, [])
    assert result.valid is False
    assert any("lines" in e.lower() for e in result.errors)


# ===========================================================================
# _validate_script — syntax error
# ===========================================================================


def test_validate_syntax_error():
    code = "def foo(\n"  # invalid syntax
    result = _validate_script(code, [])
    assert result.valid is False
    assert any("syntax" in e.lower() for e in result.errors)


# ===========================================================================
# _validate_script — regex fallback
# ===========================================================================


def test_validate_api_key_reference():
    code = 'key = "ANTHROPIC_API_KEY"\n'
    result = _validate_script(code, [])
    assert result.valid is False
    assert any("API key" in e for e in result.errors)


def test_validate_globals_call():
    code = "g = globals()\n"
    result = _validate_script(code, [])
    assert result.valid is False


# ===========================================================================
# _validate_script — dunder warnings
# ===========================================================================


def test_validate_dunder_warning():
    code = "class Foo:\n    def __init__(self): pass\n"
    result = _validate_script(code, [])
    # __init__ is in the allowed list, so no warning
    assert all("__init__" not in w for w in result.warnings)


def test_validate_suspicious_dunder():
    code = "x.__class__.__bases__\n"
    result = _validate_script(code, [])
    # Should produce a warning (not error) for __class__ and __bases__
    assert len(result.warnings) > 0


# ===========================================================================
# create_sandbox_env
# ===========================================================================


def test_sandbox_env_has_path():
    env = create_sandbox_env()
    assert "PATH" in env


def test_sandbox_env_strips_secrets():
    import os

    old = os.environ.get("ANTHROPIC_API_KEY")
    os.environ["ANTHROPIC_API_KEY"] = "sk-test-secret"
    try:
        env = create_sandbox_env()
        assert "ANTHROPIC_API_KEY" not in env
    finally:
        if old is None:
            os.environ.pop("ANTHROPIC_API_KEY", None)
        else:
            os.environ["ANTHROPIC_API_KEY"] = old


def test_sandbox_env_has_python_flags():
    env = create_sandbox_env()
    assert env.get("PYTHONDONTWRITEBYTECODE") == "1"
    assert env.get("PYTHONHASHSEED") == "0"


# ===========================================================================
# validate_network_targets
# ===========================================================================


def test_network_validation_in_scope():
    is_valid, violations = validate_network_targets(
        'url = "http://10.0.0.1/api"', ["10.0.0.1"]
    )
    assert is_valid is True
    assert violations == []


def test_network_validation_out_of_scope():
    is_valid, violations = validate_network_targets(
        'url = "http://evil.com/exfil"', ["10.0.0.1"]
    )
    assert is_valid is False
    assert len(violations) > 0


def test_network_validation_loopback_allowed():
    is_valid, violations = validate_network_targets(
        'url = "http://127.0.0.1:5000"', ["10.0.0.1"]
    )
    assert is_valid is True


# ===========================================================================
# build_generation_prompt / wrap_script
# ===========================================================================


def test_build_generation_prompt():
    prompt = build_generation_prompt(
        description="Test SQL injection",
        target="http://10.0.0.1",
        context="Found login form",
    )
    assert "Test SQL injection" in prompt
    assert "10.0.0.1" in prompt
    assert "RULES" in prompt


def test_wrap_script_contains_scope():
    wrapped = wrap_script("print('hello')", ["10.0.0.1"])
    assert "10.0.0.1" in wrapped
    assert "_check_scope" in wrapped
    assert "    print('hello')" in wrapped


def test_wrap_script_empty_scope():
    wrapped = wrap_script("x = 1", [])
    assert "_SCOPE_TARGETS" in wrapped


# ===========================================================================
# DynamicToolForge._extract_code
# ===========================================================================


def test_extract_code_raw():
    code = DynamicToolForge._extract_code("import json\nprint(1)")
    assert code == "import json\nprint(1)"


def test_extract_code_fenced():
    text = "Here is the code:\n```python\nimport json\nprint(1)\n```\nDone."
    code = DynamicToolForge._extract_code(text)
    assert code.strip() == "import json\nprint(1)"


def test_extract_code_fenced_no_lang():
    text = "```\nimport json\n```"
    code = DynamicToolForge._extract_code(text)
    assert "import json" in code
