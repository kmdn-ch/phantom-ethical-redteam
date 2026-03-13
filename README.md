# Phantom – Claude Ethical Red Team (DEF CON)

**Autonomous Red Team agent powered by Claude AI**  
Uses Nuclei, sqlmap, ffuf, advanced reconnaissance, ethical social engineering templates, etc. 

**Only on authorized scopes.**

## Features

- Autonomous agent with step-by-step reasoning + auto-correction
- Native Claude tool-calling (Nuclei, sqlmap, ffuf, recon, cleanup, ethical phishing templates)
- Full logging + automatic cleanup of temporary files
- “Ethical ghost” mode (erases only its own traces)
- Social engineering limited to educational templates (no actual messages sent without double confirmation)

## Built-in Tools

- Nuclei + sqlmap + ffuf (base)
- Bettercap (MITM réseau)
- Zphisher (templates phishing 30+)
- CyberStrikeAI (orchestrator AI 100+ tools – DEF CON level)

Execute `./install.sh` once.

## Final launch

```bash
./install.sh
python agent/main.py
