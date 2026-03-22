# agent/main.py
import os
import sys
import yaml
import json
import time
import logging
import argparse
import subprocess
import webbrowser
import socket
from pathlib import Path

# Ensure agent/ is on sys.path
sys.path.insert(0, str(Path(__file__).parent))

# Force UTF-8 output on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8")

from tools.logs_helper import init_session, get_session_dir
from agent_client import AgentClient
from providers import PROVIDERS

ROOT = Path(__file__).parent.parent

# --- Argument parsing ---
parser = argparse.ArgumentParser(description="Phantom Ethical Red Team Agent")
parser.add_argument("--resume", type=str, default="",
                    help="Resume a previous session (session directory name, e.g. 20260318_120000)")
parser.add_argument("--no-dashboard", action="store_true",
                    help="Do not launch the web dashboard automatically")
args = parser.parse_args()

# --- Change to project root ---
os.chdir(ROOT)


# --- Web dashboard auto-launch ---
def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


_dashboard_proc = None

if not args.no_dashboard:
    DASHBOARD_PORT = 5000
    if _port_in_use(DASHBOARD_PORT):
        print(f"  Dashboard already running on http://localhost:{DASHBOARD_PORT}")
    else:
        try:
            web_app = ROOT / "web" / "app.py"
            _dashboard_proc = subprocess.Popen(
                [sys.executable, str(web_app)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=str(ROOT),
            )
            # Give Flask a moment to start
            time.sleep(1.5)
            print(f"  Dashboard started on http://localhost:{DASHBOARD_PORT}")
        except Exception as e:
            print(f"  Dashboard launch failed: {e}")

    # Open browser
    try:
        webbrowser.open(f"http://localhost:{DASHBOARD_PORT}")
    except Exception:
        pass


# --- Session setup ---
if args.resume:
    session_dir = os.path.join("logs", args.resume)
    if not os.path.isdir(session_dir):
        print(f"Session not found: {session_dir}")
        sys.exit(1)
    os.environ["PHANTOM_SESSION_DIR"] = session_dir
else:
    session_dir = init_session()

# --- Secret redaction filter ---
import re as _re

class _SecretRedactFilter(logging.Filter):
    """Redact API keys, passwords, and tokens from log output."""
    _PATTERNS = [
        _re.compile(r'(sk-[a-zA-Z0-9]{20,})'),                    # Anthropic/OpenAI keys
        _re.compile(r'(xai-[a-zA-Z0-9]{20,})'),                   # xAI keys
        _re.compile(r'(Bearer\s+[A-Za-z0-9\-._~+/]+=*)'),         # Bearer tokens
        _re.compile(r'(Basic\s+[A-Za-z0-9+/]+=*)'),               # Basic auth
        _re.compile(r'(?i)(api[_-]?key\s*[=:]\s*)\S+'),           # Generic api_key=...
        _re.compile(r'(?i)(password\s*[=:]\s*)\S+'),               # password=...
    ]

    def filter(self, record):
        msg = str(record.msg)
        for pattern in self._PATTERNS:
            msg = pattern.sub(r'[REDACTED]', msg)
        record.msg = msg
        return True

# --- Structured logging: console (INFO) + file (DEBUG) ---
log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

file_handler = logging.FileHandler(
    os.path.join(session_dir, "agent.log"), encoding="utf-8"
)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(log_formatter)
file_handler.addFilter(_SecretRedactFilter())

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
console_handler.addFilter(_SecretRedactFilter())

root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)
root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)

logger = logging.getLogger(__name__)

# --- Config ---
config_path = ROOT / "config.yaml"
if not config_path.exists():
    template = ROOT / "config.yaml.example"
    if template.exists():
        import shutil
        shutil.copy(template, config_path)
        print("  config.yaml created from template. Run install.ps1 to configure.")
    else:
        print("config.yaml not found. Run install.ps1 or install.sh first.")
        sys.exit(1)

with open(config_path, encoding="utf-8") as f:
    config = yaml.safe_load(f)

with open(ROOT / "prompts" / "system_prompt.txt", encoding="utf-8") as f:
    SYSTEM_PROMPT = f.read()

scope_path = ROOT / config.get("scope_file", "scopes/current_scope.md")
SCOPE = scope_path.read_text(encoding="utf-8") if scope_path.exists() else ""

if not SCOPE.strip() or "https://xxx" in SCOPE:
    print("Invalid scope or placeholder detected. Fill in scopes/current_scope.md with an authorized target.")
    sys.exit(1)

# Load API key from .env if present
env_file = ROOT / ".env"
if env_file.exists():
    for line in env_file.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

provider = config.get("provider", "anthropic").lower()
interactive = config.get("interactive", True)
mode_label = "AUTONOMOUS" if config.get("autonomous", False) else "INTERACTIVE"

print("=" * 50)
print("  Phantom -- Ethical RedTeam")
print(f"  Provider  : {provider.upper()}")
print(f"  Model     : {config.get('model') or 'default'}")
print(f"  Mode      : {mode_label}")
print(f"  Session   : {session_dir}")
print(f"  Scope     : {SCOPE.splitlines()[0]}")
if args.resume:
    print(f"  RESUMING  : {args.resume}")
print("=" * 50 + "\n")

client = AgentClient(config=config)

# --- Resume or fresh start ---
turn = 0
if args.resume:
    state = AgentClient.load_state(session_dir)
    if state:
        messages = state["messages"]
        turn = state["turn"]
        logger.info("Resumed session %s at turn %d", args.resume, turn)
        print(f"Resumed from turn {turn} with {len(messages)} messages.\n")
    else:
        print("No state.json found in session. Starting fresh.\n")
        messages = []
else:
    messages = []

if not messages:
    # Extract target info from scope for a focused initial message
    scope_lines = [l.strip() for l in SCOPE.splitlines() if l.strip() and not l.strip().startswith("#")]
    target_summary = ", ".join(scope_lines[:5])

    messages = [
        {
            "role": "user",
            "content": (
                f"AUTHORIZED SCOPE:\n{SCOPE}\n\n"
                f"PRIMARY TARGETS: {target_summary}\n\n"
                "MISSION OBJECTIVES:\n"
                "1. Map the full attack surface (subdomains, ports, technologies)\n"
                "2. Identify all vulnerabilities (CVEs, misconfigs, injections)\n"
                "3. Adapt strategy based on detected technologies (see ADAPTIVE INTELLIGENCE rules)\n"
                "4. Correlate findings into attack chains — not just isolated vulns\n"
                "5. Capture evidence (screenshots) for every CRITICAL/HIGH finding\n"
                "6. Attempt exploitation where safe to confirm impact\n"
                "7. Compute aggregate risk score and produce a professional report\n\n"
                "CONSTRAINTS:\n"
                "- Stay strictly within authorized scope — use check_scope before new targets\n"
                "- Follow phase order: Recon -> Fingerprint -> Scan -> Enumerate -> Exploit -> Report\n"
                "- After fingerprinting: apply ADAPTIVE INTELLIGENCE rules based on detected stack\n"
                "- Use read_log after every tool to analyze results before proceeding\n"
                "- Correlate findings across tools to identify attack chains\n"
                "- Handle edge cases: WAF, rate limiting, auth required, target down\n"
                "- Take screenshots as evidence for critical/high findings\n\n"
                "BEGIN AUTONOMOUS MISSION. End with === MISSION COMPLETE === when done."
            ),
        }
    ]

max_turns = config.get("max_autonomous_turns", 50)

while turn < max_turns:
    try:
        messages = client.think(messages=messages, system_prompt=SYSTEM_PROMPT)

        # Save state after each turn
        client.save_state(messages, turn, session_dir)

        # Extract text from last assistant message
        last_assistant = next(
            (m for m in reversed(messages) if m.get("role") == "assistant"), None
        )
        assistant_text = ""
        if last_assistant:
            content = last_assistant["content"]
            if isinstance(content, list):
                assistant_text = " ".join(
                    b.get("text", "") for b in content if b.get("type") == "text"
                )
            else:
                assistant_text = str(content)

        if "=== MISSION COMPLETE ===" in assistant_text:
            print("\nMISSION COMPLETE!")
            print(assistant_text.split("=== MISSION COMPLETE ===")[-1])
            break

        turn += 1

        if turn % config.get("pause_every_n_turns", 10) == 0:
            print(f"\nPause after {turn} steps.")
            if interactive and sys.stdin.isatty():
                cmd = input("Enter = continue | 'stop' = stop | 'report' = force report: ").strip().lower()
                if cmd == "stop":
                    break
                if cmd == "report":
                    messages.append({"role": "user", "content": "Generate final report now using generate_report tool."})
            else:
                print("  (non-interactive mode -- continuing automatically)")

    except KeyboardInterrupt:
        print("\nMission aborted by user.")
        client.save_state(messages, turn, session_dir)
        break
    except Exception as e:
        logger.error("Error: %s", e, exc_info=True)
        print(f"Error: {e}")
        client.save_state(messages, turn, session_dir)
        break

print(f"\nPhantom stopped. Session logs: {session_dir}")

# Cleanup dashboard subprocess
if _dashboard_proc and _dashboard_proc.poll() is None:
    print("  Dashboard still running at http://localhost:5000 (close manually or Ctrl+C)")
