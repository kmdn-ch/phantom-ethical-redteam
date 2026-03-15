# Phantom – Ethical RedTeam

**Autonomous Red Team agent — works with any LLM**
Uses Nuclei, sqlmap, ffuf, advanced reconnaissance, and social engineering templates — on authorized scopes only.

> **Legal notice:** This project is intended solely for lawful security research and authorized testing in controlled environments. Use only on assets you own or are expressly authorized in writing to assess. Nothing in this repository grants authorization to target third-party systems.

![Phantom in action](images/phantom-banner.png)

---

## Features

- Autonomous agent with step-by-step reasoning + auto-correction
- Native tool-calling on any supported LLM (Nuclei, sqlmap, ffuf, recon, bettercap, cleanup, phishing templates)
- Full logging + automatic cleanup of temporary files
- Pause every N turns — human can stop, continue, or force a report
- Social engineering limited to educational templates (no actual send without human confirmation)

## Supported LLM Providers

| Provider | Default model (2026-03-15) | API key env var |
|---|---|---|
| Anthropic (Claude) | `claude-sonnet-4-6` | `ANTHROPIC_API_KEY` |
| OpenAI (ChatGPT) | `gpt-5.4` | `OPENAI_API_KEY` |
| xAI (Grok) | `grok-4-20-beta` | `XAI_API_KEY` |
| Google (Gemini) | `gemini-3.0-pro` | `GEMINI_API_KEY` |
| Mistral | `mistral-large-latest` | `MISTRAL_API_KEY` |
| DeepSeek | `deepseek-chat-v3.2` | `DEEPSEEK_API_KEY` |
| Ollama (local) | `deepseek-r1:3.2` | *(none)* |

## Built-in Tools

| Tool | Role |
|---|---|
| Nuclei | CVE / misconfiguration scanning |
| sqlmap | SQL injection detection & exploitation |
| ffuf | Directory & endpoint fuzzing |
| recon | Passive reconnaissance (DNS, WHOIS, headers) |
| bettercap | Network MITM, ARP probe (Linux only) |
| Zphisher | Phishing page templates (educational, Linux only) |
| CyberStrikeAI | AI-native orchestrator — 100+ tools |

---

## Installation

### Linux

```bash
chmod +x install.sh
./install.sh
```

```
[ STEP 0 / 3 ] LLM Provider
  1) Anthropic (Claude sonnet-4-6)   2) OpenAI (ChatGPT 5.4)    3) xAI (Grok 4.20 Beta)
  4) Google (Gemini 3)               5) Mistral                  6) DeepSeek 3.2
  7) Ollama (local — deepseek-r1:3.2)
Choose provider [1-7] : 1
✅ Provider selected : ANTHROPIC

[ STEP 1 / 3 ] API Key
Enter your ANTHROPIC_API_KEY : sk-ant-...
✅ API key saved to .env

[ STEP 2 / 3 ] Authorized Scope
Target URL : https://someth1ng.com
Authorization note : Pentest contract signed 2026-03-15
Engagement date : 2026-03-15
✅ Scope saved to scopes/current_scope.md

[ STEP 3 / 3 ] Installing dependencies...
→ nuclei and ffuf installed from GitHub Releases
→ Python virtualenv created in .venv/
✅ Installation complete !

  source .venv/bin/activate
  export $(cat .env)
  export PATH=$PATH:$(pwd)/bin:/usr/local/bin
  python3 agent/main.py
```

> **Note :** `chmod +x install.sh` is required once after cloning — the installer uses LF line endings and is safe to run on any Debian/Ubuntu system.

### Windows (PowerShell)

```powershell
.\install.ps1
```

Same interactive flow (provider → API key → scope → dependencies).
Windows limitations: `bettercap` and `zphisher` require WSL2.

The installer handles everything: provider selection, API key validation, scope enforcement, Python virtualenv, and external tools (nuclei/ffuf binaries downloaded automatically).

---

## Real-world example — Web application pentest

### Context

You are a red teamer hired to test the security of `https://someth1ng.com`.
The client has signed a Rules of Engagement document. The scope is limited to this domain and its subdomains.

### Step 1 — Install & configure

Run `./install.sh` and follow the prompts (API key + target URL). Done — no manual file editing needed.

### Step 2 — Launch Phantom

```bash
source .venv/bin/activate
export $(cat .env)
python3 agent/main.py
```

```
🚀 Phantom - Ethical RedTeam v1.5.0
Mode : AUTONOME TOTAL
Scope : https://someth1ng.com — Pentest contract signed 2026-03-15...
```

### Step 3 — Phantom reasons and acts autonomously

Phantom works through the standard kill chain, narrating every decision:

```
🤖 Phantom : Starting mission on https://someth1ng.com.
  Result obtained: scope confirmed.
  Analysis: I will begin with passive recon before any active scan.
  Next optimal action: run_recon on the target.
  Reason: passive data collection has zero impact on availability.

🔧 Execution : run_recon
→ DNS records, WHOIS, HTTP headers, tech stack fingerprinting...

🤖 Phantom : Result obtained: Apache 2.4.51, PHP 8.0, WordPress 6.1.
  Analysis: WordPress 6.1 is EOL — multiple known CVEs. Apache version exposed.
  Next optimal action: run_nuclei with wordpress templates.
  Reason: high probability of CVE hits before any brute-force or injection.

🔧 Execution : run_nuclei
→ Target: https://someth1ng.com, templates: http/cves, severity: critical

🤖 Phantom : Result obtained: 3 findings — CVE-2023-2745 (path traversal),
  CVE-2022-3590 (SSRF via pingback), misconfigured xmlrpc.php.
  Analysis: CVE-2023-2745 exploitable without auth — direct path to /etc/passwd.
  Next optimal action: run_sqlmap on login endpoint discovered by ffuf.
  Reason: parallel track — test both path traversal and SQL injection.

🔧 Execution : run_ffuf
→ Discovered: /admin, /wp-login.php, /api/v1/users, /backup.zip

🔧 Execution : run_sqlmap
→ Target: https://someth1ng.com/api/v1/users?id=1
→ Injection found: UNION-based, 4 columns — database: someth1ng_prod

🤖 Phantom : Result obtained: SQLi confirmed, partial dump acquired.
  Analysis: standard tools exhausted on web layer. Internal network segment
  (192.168.1.0/24) is in scope — MITM probe warranted.
  Next optimal action: run_bettercap on eth0.
  Reason: ARP probe will map live hosts and expose unencrypted traffic.

🔧 Execution : run_bettercap
→ Interface: eth0, module: net.probe, duration: 30s
→ 14 live hosts discovered — 3 running HTTP on port 80 (no TLS)

🤖 Phantom : Result obtained: 3 unencrypted internal services exposed.
  Analysis: web fingerprinting of internal hosts shows legacy Apache 2.2
  with no patch history. Standard CVE templates yielded 0 hits.
  Escalating to full tool suite.
  Next optimal action: run_cyberstrike on 192.168.1.42.
  Reason: legacy target requires deeper enumeration beyond nuclei/ffuf scope.

🔧 Execution : run_cyberstrike
→ Target: 192.168.1.42, role: redteam, skill: full-scan
→ 7 critical findings — LFI, exposed .git repo, default credentials on /manager
→ Achieved RCE via Tomcat manager upload (CVE-2019-0232)
```

After 10 turns, Phantom pauses:

```
⏸️  Pause after 10 steps (mode autonome).
Entrée = continue | 'stop' = stop | 'report' = force report :
```

You review the logs in `logs/agent.log`, then press Enter to continue — or type `report` to get an immediate executive summary.

### Step 4 — Mission complete

```
🤖 Phantom : Objectives achieved. Generating final report.

=== MISSION COMPLETE ===

**Executive Summary**
app.someth1ng.com presents 3 critical vulnerabilities exploitable without authentication.

**Critical findings**
1. CVE-2023-2745 — WordPress path traversal → arbitrary file read (PoC: /wp-admin/?action=..&page=../../../etc/passwd)
2. SQL injection on /api/v1/users?id= → full database dump (someth1ng_prod, 12 tables, 4 200 users)
3. /backup.zip publicly accessible → contains database credentials in plaintext
4. Internal host 192.168.1.42 — RCE via Tomcat manager (CVE-2019-0232), default credentials
5. 3 internal services transmitting data over unencrypted HTTP (bettercap ARP probe)

**Recommendations**
- Patch WordPress to 6.5+ immediately
- Parameterize all SQL queries — use prepared statements
- Remove /backup.zip and audit all publicly accessible backup files
- Disable xmlrpc.php if not required
- Enforce TLS on all internal services
- Rotate Tomcat manager credentials and restrict access to localhost
```

All findings are in `logs/` — ready to import into your report.

---

## Configuration

`config.yaml`:

```yaml
provider: "anthropic"   # anthropic | openai | grok | gemini | ollama | mistral | deepseek
model: ""               # leave empty for provider default
autonomous: true
max_autonomous_turns: 50
pause_every_n_turns: 10
```

The installer writes the API key to `.env` and sets the provider in `config.yaml` automatically. To launch manually:

```bash
# Linux
source .venv/bin/activate
export $(cat .env)
export PATH=$PATH:$(pwd)/bin:/usr/local/bin
python3 agent/main.py

# Windows (PowerShell)
foreach ($line in Get-Content .env) { [System.Environment]::SetEnvironmentVariable($line.Split("=")[0], $line.Split("=",2)[1]) }
$env:PATH += ";$PWD\bin"
python agent\main.py
```

To switch provider or change the target between engagements, re-run the installer or edit `config.yaml` and `scopes/current_scope.md` directly.

---

## Legal

This tool is for authorized penetration testing only. Running it against systems you do not have written permission to test is illegal. The authors are not responsible for misuse.
