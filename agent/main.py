# agent/main.py
import os
import sys
import yaml
import logging
from pathlib import Path

# Ensure agent/ is on sys.path so claude_client is importable
sys.path.insert(0, str(Path(__file__).parent))

from claude_client import ClaudeClient

ROOT = Path(__file__).parent.parent

logging.basicConfig(
    filename=ROOT / "logs" / "agent.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# CONFIG
with open(ROOT / "config.yaml") as f:
    config = yaml.safe_load(f)

with open(ROOT / "prompts" / "system_prompt.txt") as f:
    SYSTEM_PROMPT = f.read()

scope_path = ROOT / config.get("scope_file", "scopes/current_scope.md")
SCOPE = scope_path.read_text() if scope_path.exists() else ""

# Reject placeholder scope — agent must not run without a real target
if not SCOPE.strip() or "https://xxx" in SCOPE:
    print("❌ Scope invalide ou placeholder détecté. Renseigne scopes/current_scope.md avec une cible autorisée.")
    sys.exit(1)

# API key from environment variable (never from config file)
api_key = os.environ.get("ANTHROPIC_API_KEY") or config.get("anthropic_api_key", "")
if not api_key or api_key.startswith("sk-ant-key-claude-here"):
    print("❌ ANTHROPIC_API_KEY non définie. Exporte la variable d'environnement.")
    sys.exit(1)

print("🚀 Phantom - Claude Ethical RedTeam v1.0")
print(f"Mode : {'AUTONOME TOTAL' if config.get('autonomous', False) else 'Interactif'}")
print(f"Scope : {SCOPE[:300]}...\n")

client = ClaudeClient(api_key=api_key, model=config["model"])

messages = [
    {
        "role": "user",
        "content": (
            f"Authorized scope :\n{SCOPE}\n\n"
            "START THE MISSION IN AUTONOMOUS MODE. Think step by step, "
            "correct yourself, use the tools in sequence. "
            "Finish only with === MISSION COMPLETE === when it's done."
        ),
    }
]

turn = 0
max_turns = config.get("max_autonomous_turns", 50)

while turn < max_turns:
    try:
        messages = client.think(messages=messages, system_prompt=SYSTEM_PROMPT)

        # Extract text from assistant content blocks (content is now a list)
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
            print("\n🎯 MISSION COMPLETE BY PHANTOM !")
            print(assistant_text.split("=== MISSION COMPLETE ===")[-1])
            break

        turn += 1

        # Pause every N turns
        if turn % config.get("pause_every_n_turns", 10) == 0:
            print(f"\n⏸️  Pause after {turn} steps (mode autonome).")
            cmd = input("Entrée = continue | 'stop' = stop | 'report' = force report : ").strip().lower()
            if cmd == "stop":
                break
            if cmd == "report":
                messages.append({"role": "user", "content": "Generate final report now."})

    except KeyboardInterrupt:
        print("\n👋 Mission aborted by user.")
        break
    except Exception as e:
        logging.error(f"Error : {e}")
        print(f"Erreur : {e}")
        break

print("Phantom stopped successfully.")
