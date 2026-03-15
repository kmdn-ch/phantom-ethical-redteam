#!/bin/bash
set -e

echo "========================================"
echo "  Phantom – Claude Ethical RedTeam"
echo "  Installer v1.3.0"
echo "========================================"
echo ""

# ─────────────────────────────────────────
# STEP 0 — LLM Provider selection
# ─────────────────────────────────────────
echo "[ STEP 0 / 3 ] LLM Provider"
echo "-----------------------------------------"
echo "  1) Anthropic  (Claude sonnet-4-6)   — https://console.anthropic.com"
echo "  2) OpenAI     (ChatGPT 5.4)        — https://platform.openai.com"
echo "  3) xAI        (Grok 4.20 Beta)     — https://console.x.ai"
echo "  4) Google     (Gemini 3)           — https://aistudio.google.com/apikey"
echo "  5) Mistral    (mistral-large)      — https://console.mistral.ai"
echo "  6) DeepSeek   (DeepSeek 3.2)       — https://platform.deepseek.com"
echo "  7) Ollama     (local — deepseek-r1:3.2 default)"
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

# ─────────────────────────────────────────
# STEP 1 — API Key
# ─────────────────────────────────────────
echo "[ STEP 1 / 3 ] API Key"
echo "-----------------------------------------"

if [ "$PROVIDER" = "ollama" ]; then
    read -rp "Ollama host [http://localhost:11434] : " OLLAMA_HOST
    OLLAMA_HOST=${OLLAMA_HOST:-http://localhost:11434}
    # Write config — no API key needed
    sed -i "s|^provider:.*|provider: \"$PROVIDER\"|" config.yaml
    sed -i "s|^ollama_host:.*|ollama_host: \"$OLLAMA_HOST\"|" config.yaml
    > .env
    echo "✅ Ollama configured (host: $OLLAMA_HOST)"
else
    while true; do
        read -rsp "Enter your $ENV_VAR : " api_key
        echo ""
        if [ -z "$KEY_PREFIX" ] || [[ "$api_key" == ${KEY_PREFIX}* ]]; then
            if [ ${#api_key} -gt 10 ]; then
                break
            fi
        fi
        echo "⚠️  Invalid key. Try again."
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
cat > scopes/current_scope.md <<EOF
**Scope autorisé :** $scope_url

**Autorisation :** $scope_note

**Date :** $scope_date
EOF

echo "✅ Scope saved to scopes/current_scope.md"
echo ""

# ─────────────────────────────────────────
# STEP 3 — Dependencies
# ─────────────────────────────────────────
echo "[ STEP 3 / 3 ] Installing dependencies"
echo "-----------------------------------------"

sudo apt update -q && sudo apt install -y \
    golang-go python3-pip curl git nmap \
    nuclei sqlmap ffuf bettercap

# Zphisher (educational phishing templates)
git clone https://github.com/htr-tech/zphisher.git tools/zphisher_repo 2>/dev/null || true
chmod +x tools/zphisher_repo/zphisher.sh

# CyberStrikeAI
git clone https://github.com/Ed1s0nZ/CyberStrikeAI.git tools/cyberstrike_repo 2>/dev/null || true
mkdir -p bin
cd tools/cyberstrike_repo && go build -o ../../bin/cyberstrike ./cmd/cyberstrike 2>/dev/null || \
    echo "⚠️  CyberStrikeAI build failed — verify Go installation"
cd ../..

# Python dependencies
pip install -r requirements.txt -q

echo ""
echo "========================================"
echo "  ✅ Installation complete !"
echo "========================================"
echo ""
echo "  Provider : $PROVIDER"
echo "  Scope    : $scope_url"
echo ""
echo "  To start Phantom :"
echo ""
if [ "$PROVIDER" != "ollama" ]; then
    echo "    export \$(cat .env)"
fi
echo "    export PATH=\$PATH:\$(pwd)/bin"
echo "    python agent/main.py"
echo ""
echo "========================================"
