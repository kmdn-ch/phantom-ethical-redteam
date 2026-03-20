#!/bin/bash
set -e

echo "========================================"
echo "  Phantom – Ethical RedTeam"
echo "  Installer v2.2.1"
echo "========================================"
echo ""

# ─────────────────────────────────────────
# Helper — test LLM connection via curl
# Uses the fastest/cheapest model per provider (not the mission model)
# ─────────────────────────────────────────
test_llm_connection() {
    local provider="$1"
    local api_key="$2"
    local http_status

    echo -n "  → Testing connection to $provider API... "

    case "$provider" in
        anthropic)
            http_status=$(curl -s -o /tmp/phantom_test.json -w "%{http_code}" \
                -X POST https://api.anthropic.com/v1/messages \
                -H "x-api-key: $api_key" \
                -H "anthropic-version: 2023-06-01" \
                -H "content-type: application/json" \
                -d '{"model":"claude-haiku-4-5-20251001","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')
            ;;
        openai)
            http_status=$(curl -s -o /tmp/phantom_test.json -w "%{http_code}" \
                -X POST https://api.openai.com/v1/chat/completions \
                -H "Authorization: Bearer $api_key" \
                -H "Content-Type: application/json" \
                -d '{"model":"gpt-4o-mini","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')
            ;;
        grok)
            http_status=$(curl -s -o /tmp/phantom_test.json -w "%{http_code}" \
                -X POST https://api.x.ai/v1/chat/completions \
                -H "Authorization: Bearer $api_key" \
                -H "Content-Type: application/json" \
                -d '{"model":"grok-2-latest","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')
            ;;
        gemini)
            http_status=$(curl -s -o /tmp/phantom_test.json -w "%{http_code}" \
                -X POST "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=$api_key" \
                -H "Content-Type: application/json" \
                -d '{"contents":[{"parts":[{"text":"hi"}]}]}')
            ;;
        mistral)
            http_status=$(curl -s -o /tmp/phantom_test.json -w "%{http_code}" \
                -X POST https://api.mistral.ai/v1/chat/completions \
                -H "Authorization: Bearer $api_key" \
                -H "Content-Type: application/json" \
                -d '{"model":"mistral-small-latest","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')
            ;;
        deepseek)
            http_status=$(curl -s -o /tmp/phantom_test.json -w "%{http_code}" \
                -X POST https://api.deepseek.com/v1/chat/completions \
                -H "Authorization: Bearer $api_key" \
                -H "Content-Type: application/json" \
                -d '{"model":"deepseek-chat","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')
            ;;
        ollama)
            http_status=$(curl -s -o /tmp/phantom_test.json -w "%{http_code}" \
                "$OLLAMA_HOST/api/tags")
            ;;
    esac

    rm -f /tmp/phantom_test.json

    if [ "$http_status" = "200" ]; then
        echo "✅ OK (HTTP 200)"
        return 0
    else
        echo "❌ Failed (HTTP $http_status)"
        return 1
    fi
}

# ─────────────────────────────────────────
# STEP 0 — LLM Provider selection (with Ollama auto-detection)
# ─────────────────────────────────────────
echo "[ STEP 0 / 3 ] LLM Provider"
echo "-----------------------------------------"

OLLAMA_DETECTED=false
OLLAMA_AUTO_MODEL=""
OLLAMA_HOST="http://localhost:11434"

# --- Auto-detect Ollama ---
if command -v ollama &>/dev/null; then
    echo "  [i] Ollama detected on this system."
    # Check if Ollama is running and has models
    if curl -s "$OLLAMA_HOST/api/tags" >/dev/null 2>&1; then
        model_list=$(curl -s "$OLLAMA_HOST/api/tags" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    models = data.get('models', [])
    for m in models:
        size_gb = round(m.get('size', 0) / 1e9, 1)
        print(f\"{m['name']}|{size_gb}\")
except: pass
" 2>/dev/null)

        if [ -n "$model_list" ]; then
            model_count=$(echo "$model_list" | wc -l)
            OLLAMA_AUTO_MODEL=$(echo "$model_list" | head -1 | cut -d'|' -f1)

            echo "  [i] Ollama is running with $model_count model(s):"
            while IFS='|' read -r mname msize; do
                echo "       - $mname ($msize GB)"
            done <<< "$model_list"
            echo ""
            echo "  --> Ollama auto-detected with model: $OLLAMA_AUTO_MODEL"
            read -rp "  Use Ollama with '$OLLAMA_AUTO_MODEL'? [Y/n] : " use_ollama
            if [ -z "$use_ollama" ] || [[ "$use_ollama" =~ ^[Yy]$ ]]; then
                OLLAMA_DETECTED=true
                if [ "$model_count" -gt 1 ]; then
                    read -rp "  Use '$OLLAMA_AUTO_MODEL' or type another model name [Enter = keep] : " pick_model
                    if [ -n "$pick_model" ]; then OLLAMA_AUTO_MODEL="$pick_model"; fi
                fi
            fi
        else
            echo "  [!] Ollama is running but no models installed."
            echo "      Install a model first: ollama pull deepseek-v3.2:cloud"
            echo ""
        fi
    else
        echo "  [!] Ollama installed but not running. Start it with: ollama serve"
        echo ""
    fi
fi

if [ "$OLLAMA_DETECTED" = true ]; then
    PROVIDER="ollama"
    ENV_VAR=""
    KEY_PREFIX=""
    OLLAMA_MODEL="$OLLAMA_AUTO_MODEL"
    echo ""
    echo "✅ Provider: OLLAMA (auto-detected)"
    echo "   Model: $OLLAMA_MODEL"
    echo "   Host: $OLLAMA_HOST"
    echo ""
else
    echo "  1) Anthropic  (Claude sonnet-4-6)   — https://console.anthropic.com"
    echo "  2) OpenAI     (ChatGPT 5.4)         — https://platform.openai.com"
    echo "  3) xAI        (Grok 4.20 Beta)      — https://console.x.ai"
    echo "  4) Google     (Gemini 3)             — https://aistudio.google.com/apikey"
    echo "  5) Mistral    (mistral-large)        — https://console.mistral.ai"
    echo "  6) DeepSeek   (DeepSeek 3.2)         — https://platform.deepseek.com"
    echo "  7) Ollama     (local)"
    echo ""

    while true; do
        read -rp "Choose provider [1-7] : " provider_choice
        case "$provider_choice" in
            1) PROVIDER="anthropic"; ENV_VAR="ANTHROPIC_API_KEY"; KEY_PREFIX="sk-ant-" ;;
            2) PROVIDER="openai";    ENV_VAR="OPENAI_API_KEY";    KEY_PREFIX="sk-" ;;
            3) PROVIDER="grok";      ENV_VAR="XAI_API_KEY";       KEY_PREFIX="xai-" ;;
            4) PROVIDER="gemini";    ENV_VAR="GEMINI_API_KEY";    KEY_PREFIX="" ;;
            5) PROVIDER="mistral";   ENV_VAR="MISTRAL_API_KEY";   KEY_PREFIX="" ;;
            6) PROVIDER="deepseek";  ENV_VAR="DEEPSEEK_API_KEY";  KEY_PREFIX="" ;;
            7) PROVIDER="ollama";    ENV_VAR="";                  KEY_PREFIX="" ;;
            *) echo "⚠️  Invalid choice. Enter a number between 1 and 7." ; continue ;;
        esac
        break
    done

    echo "✅ Provider selected : $PROVIDER"
    echo ""
fi

# ─────────────────────────────────────────
# STEP 1 — API Key + connection test
# ─────────────────────────────────────────
echo "[ STEP 1 / 3 ] API Key"
echo "-----------------------------------------"

# Create config.yaml from template if missing
if [ ! -f "config.yaml" ]; then
    if [ -f "config.yaml.example" ]; then
        cp config.yaml.example config.yaml
    else
        echo "❌ config.yaml.example not found"; exit 1
    fi
fi

OLLAMA_HOST="http://localhost:11434"

if [ "$PROVIDER" = "ollama" ] && [ "$OLLAMA_DETECTED" = true ]; then
    # Already configured by auto-detection -- just confirm and write config
    echo "  Ollama already configured by auto-detection."
    test_llm_connection "ollama" "" && echo "  ✅ Connection confirmed."
    sed -i "s|^provider:.*|provider: \"$PROVIDER\"|" config.yaml
    sed -i "s|^ollama_host:.*|ollama_host: \"$OLLAMA_HOST\"|" config.yaml
    sed -i "s|^model:.*|model: \"$OLLAMA_MODEL\"|" config.yaml
    > .env

elif [ "$PROVIDER" = "ollama" ]; then
    # Manual Ollama setup
    read -rp "Ollama host [http://localhost:11434] : " input_host
    OLLAMA_HOST=${input_host:-http://localhost:11434}

    if ! test_llm_connection "ollama" ""; then
        echo "⚠️  Cannot reach Ollama at $OLLAMA_HOST"
        echo "   Make sure Ollama is running : ollama serve"
        read -rp "   Continue anyway? [y/N] : " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }
    fi

    OLLAMA_MODEL="deepseek-v3.2:cloud"
    echo ""
    echo "  Default Ollama model: $OLLAMA_MODEL"
    if command -v ollama &>/dev/null; then
        echo "  Local models:"
        ollama list 2>/dev/null | tail -n +2 | awk '{print "    - "$1}'
    fi
    read -rp "Model name [$OLLAMA_MODEL] : " input_model
    OLLAMA_MODEL=${input_model:-$OLLAMA_MODEL}

    echo "  Checking if '$OLLAMA_MODEL' is available locally..."
    if command -v ollama &>/dev/null; then
        if ! ollama list 2>/dev/null | grep -q "$OLLAMA_MODEL"; then
            echo "  Pulling '$OLLAMA_MODEL' (this may take a while)..."
            ollama pull "$OLLAMA_MODEL" || echo "  ⚠️  Pull failed. Run manually: ollama pull $OLLAMA_MODEL"
        else
            echo "  ✅ Model '$OLLAMA_MODEL' already available"
        fi
    else
        echo "  ⚠️  ollama CLI not found. Run manually: ollama pull $OLLAMA_MODEL"
    fi

    sed -i "s|^provider:.*|provider: \"$PROVIDER\"|" config.yaml
    sed -i "s|^ollama_host:.*|ollama_host: \"$OLLAMA_HOST\"|" config.yaml
    sed -i "s|^model:.*|model: \"$OLLAMA_MODEL\"|" config.yaml
    > .env
else
    while true; do
        read -rsp "Enter your $ENV_VAR : " api_key
        echo ""

        # Format check
        if [ -n "$KEY_PREFIX" ] && [[ "$api_key" != ${KEY_PREFIX}* ]]; then
            echo "⚠️  Invalid key format (expected prefix: $KEY_PREFIX). Try again."
            continue
        fi
        if [ ${#api_key} -le 10 ]; then
            echo "⚠️  Key too short. Try again."
            continue
        fi

        # Connection test
        if test_llm_connection "$PROVIDER" "$api_key"; then
            break
        else
            echo "⚠️  Connection failed. Check your key and network, then try again."
            echo "     (or press Ctrl+C to abort)"
        fi
    done

    echo "${ENV_VAR}=${api_key}" > .env
    sed -i "s|^provider:.*|provider: \"$PROVIDER\"|" config.yaml
    echo "✅ API key saved to .env"
fi
echo ""

# ─────────────────────────────────────────
# STEP 2 — Authorized scope
# ─────────────────────────────────────────
echo "[ STEP 2 / 3 ] Authorized Scope"
echo "-----------------------------------------"

while true; do
    read -rp "Target URL (e.g. https://target.example.com) : " scope_url
    if [[ "$scope_url" == http* && "$scope_url" != "https://xxx" ]]; then
        break
    fi
    echo "⚠️  Invalid URL or placeholder. Enter a real authorized target."
done

read -rp "Authorization note (e.g. 'Pentest contract signed 2026-03-15') : " scope_note
read -rp "Engagement date (e.g. 2026-03-15) : " scope_date

mkdir -p scopes logs
cat > scopes/current_scope.md <<SCOPE
**Scope autorisé :** $scope_url

**Autorisation :** $scope_note

**Date :** $scope_date
SCOPE

echo "✅ Scope saved to scopes/current_scope.md"
echo ""

# ─────────────────────────────────────────
# STEP 3 — Dependencies
# ─────────────────────────────────────────
echo "[ STEP 3 / 3 ] Installing dependencies"
echo "-----------------------------------------"

sudo apt update -q
sudo apt install -y curl wget unzip git nmap sqlmap bettercap golang-go python3 python3-pip python3-venv

# Default wordlist for ffuf (SecLists — directory-list-2.3-medium)
mkdir -p wordlists
if [ ! -f "wordlists/directory-list-2.3-medium.txt" ]; then
    echo "→ Downloading default wordlist (SecLists)..."
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt" \
        -O "wordlists/directory-list-2.3-medium.txt" \
        && echo "✅ wordlist downloaded ($(wc -l < wordlists/directory-list-2.3-medium.txt) entries)" \
        || echo "⚠️  wordlist download failed — use run_payloads to generate PATT wordlists"
fi

# nuclei — not in apt, install from GitHub Releases
if ! command -v nuclei &>/dev/null; then
    echo "→ Installing nuclei..."
    curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep "browser_download_url.*linux_amd64.zip" \
        | cut -d '"' -f 4 \
        | wget -qi - -O /tmp/nuclei.zip
    unzip -q /tmp/nuclei.zip -d /tmp/nuclei_bin
    sudo mv /tmp/nuclei_bin/nuclei /usr/local/bin/nuclei
    rm -rf /tmp/nuclei.zip /tmp/nuclei_bin
    echo "✅ nuclei installed"
fi

# ffuf — not in apt, install from GitHub Releases
if ! command -v ffuf &>/dev/null; then
    echo "→ Installing ffuf..."
    curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest \
        | grep "browser_download_url.*linux_amd64.tar.gz" \
        | cut -d '"' -f 4 \
        | wget -qi - -O /tmp/ffuf.tar.gz
    tar -xzf /tmp/ffuf.tar.gz -C /tmp/
    sudo mv /tmp/ffuf /usr/local/bin/ffuf
    rm -f /tmp/ffuf.tar.gz
    echo "✅ ffuf installed"
fi

# Zphisher
if [ ! -d "tools/zphisher_repo" ]; then
    git clone https://github.com/htr-tech/zphisher.git tools/zphisher_repo 2>/dev/null
    chmod +x tools/zphisher_repo/zphisher.sh
fi

# CyberStrikeAI
mkdir -p bin
if [ ! -d "tools/cyberstrike_repo" ]; then
    git clone https://github.com/Ed1s0nZ/CyberStrikeAI.git tools/cyberstrike_repo 2>/dev/null || true
fi
if [ -d "tools/cyberstrike_repo" ]; then
    (cd tools/cyberstrike_repo && go build -o ../../bin/cyberstrike ./cmd/cyberstrike 2>/dev/null) \
        && echo "✅ CyberStrikeAI built" \
        || echo "⚠️  CyberStrikeAI build failed — verify Go installation"
fi

# Python venv + dependencies
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt
echo "✅ Python dependencies installed in .venv"

echo ""
echo "========================================"
echo "  ✅ Installation complete !"
echo "  Provider : $PROVIDER"
echo "  Scope    : $scope_url"
echo "========================================"
echo ""
echo "  Launching Phantom now..."
echo ""

# Activate venv and load env
source .venv/bin/activate
if [ "$PROVIDER" != "ollama" ]; then
    export $(cat .env)
fi
export PATH="$PATH:$(pwd)/bin:/usr/local/bin"

exec python3 agent/main.py
