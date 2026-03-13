# agent/main.py
import os
import yaml
import logging
from claude_client import ClaudeClient

logging.basicConfig(filename='logs/agent.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# CONFIG
with open('config.yaml') as f:
    config = yaml.safe_load(f)

with open('prompts/system_prompt.txt') as f:
    SYSTEM_PROMPT = f.read()

scope_path = config.get('scope_file', 'scopes/current_scope.md')
SCOPE = open(scope_path).read() if os.path.exists(scope_path) else "⚠️ No scope !"

print("🚀 Phantom - Claude Ethical RedTeam v1.0")
print(f"Mode : {'AUTONOME TOTAL' if config.get('autonomous', False) else 'Interactif'}")
print(f"Scope : {SCOPE[:300]}...\n")

client = ClaudeClient(api_key=config['anthropic_api_key'], model=config['model'])

messages = [
    {"role": "user", "content": f"Athorized scope :\n{SCOPE}\n\nSTART THE MISSION IN AUTONOMOUS MODE. Think step by step, correct yourself, scorrige-toi, use the tools in sequence. Finish only with === MISSION COMPLETE === when it's done."}
]

turn = 0
max_turns = config.get('max_autonomous_turns', 50)

while turn < max_turns:
    try:
        messages = client.think(messages=messages, system_prompt=SYSTEM_PROMPT)

        # Verification terminaison autonome
        assistant_content = next((m['content'] for m in reversed(messages) if m.get('role') == 'assistant'), "")
        if "=== MISSION COMPLETE ===" in assistant_content:
            print("\n🎯 MISSION COMPLETE BY PHANTOM !")
            print(assistant_content.split("=== MISSION COMPLETE ===")[-1])
            break

        turn += 1

        # Intelligent pause each N turns
        if turn % config.get('pause_every_n_turns', 10) == 0:
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

print("Phantom stopped successfuly.")
