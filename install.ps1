#Requires -Version 5.1
<#
.SYNOPSIS
    Phantom – Ethical RedTeam — Windows Installer v1.6.0
.DESCRIPTION
    Interactive setup: LLM provider, API key, authorized scope, dependencies.
    Run from the repo root: .\install.ps1
#>

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Phantom - Ethical RedTeam"              -ForegroundColor Cyan
Write-Host "  Installer v1.6.0 (Windows)"            -ForegroundColor Cyan
Write-Host "========================================"  -ForegroundColor Cyan
Write-Host ""

# ─────────────────────────────────────────
# STEP 0 — LLM Provider selection
# ─────────────────────────────────────────
Write-Host "[ STEP 0 / 3 ] LLM Provider" -ForegroundColor Yellow
Write-Host "-----------------------------------------"
Write-Host "  1) Anthropic  (Claude sonnet-4-6)   — https://console.anthropic.com"
Write-Host "  2) OpenAI     (ChatGPT 5.4)        — https://platform.openai.com"
Write-Host "  3) xAI        (Grok 4.20 Beta)     — https://console.x.ai"
Write-Host "  4) Google     (Gemini 3)           — https://aistudio.google.com/apikey"
Write-Host "  5) Mistral    (mistral-large)      — https://console.mistral.ai"
Write-Host "  6) DeepSeek   (DeepSeek 3.2)       — https://platform.deepseek.com"
Write-Host "  7) Ollama     (local — deepseek-r1:3.2 default)"
Write-Host ""

$providerMap = @{
    "1" = @{ Name = "anthropic"; EnvVar = "ANTHROPIC_API_KEY"; Prefix = "sk-ant-" }
    "2" = @{ Name = "openai";    EnvVar = "OPENAI_API_KEY";    Prefix = "sk-" }
    "3" = @{ Name = "grok";      EnvVar = "XAI_API_KEY";       Prefix = "xai-" }
    "4" = @{ Name = "gemini";    EnvVar = "GEMINI_API_KEY";    Prefix = "" }
    "5" = @{ Name = "mistral";   EnvVar = "MISTRAL_API_KEY";   Prefix = "" }
    "6" = @{ Name = "deepseek";  EnvVar = "DEEPSEEK_API_KEY";  Prefix = "" }
    "7" = @{ Name = "ollama";    EnvVar = "";                  Prefix = "" }
}

do {
    $choice = Read-Host "Choose provider [1-7]"
} while (-not $providerMap.ContainsKey($choice))

$provider   = $providerMap[$choice].Name
$envVar     = $providerMap[$choice].EnvVar
$keyPrefix  = $providerMap[$choice].Prefix

Write-Host "✅ Provider selected : $($provider.ToUpper())" -ForegroundColor Green
Write-Host ""

# ─────────────────────────────────────────
# Helper — test LLM connection
# ─────────────────────────────────────────
function Test-LLMConnection {
    param([string]$Provider, [string]$ApiKey, [string]$OllamaHost = "http://localhost:11434")

    Write-Host -NoNewline "  → Testing connection to $Provider API... "

    $headers = @{ "Content-Type" = "application/json" }
    $body    = '{"model":"","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'

    try {
        switch ($Provider) {
            "anthropic" {
                $headers["x-api-key"] = $ApiKey
                $headers["anthropic-version"] = "2023-06-01"
                $body = '{"model":"claude-haiku-4-5-20251001","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'
                $r = Invoke-WebRequest -Uri "https://api.anthropic.com/v1/messages" -Method POST -Headers $headers -Body $body -UseBasicParsing -ErrorAction Stop
            }
            "openai" {
                $headers["Authorization"] = "Bearer $ApiKey"
                $body = '{"model":"gpt-4o-mini","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'
                $r = Invoke-WebRequest -Uri "https://api.openai.com/v1/chat/completions" -Method POST -Headers $headers -Body $body -UseBasicParsing -ErrorAction Stop
            }
            "grok" {
                $headers["Authorization"] = "Bearer $ApiKey"
                $body = '{"model":"grok-2-latest","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'
                $r = Invoke-WebRequest -Uri "https://api.x.ai/v1/chat/completions" -Method POST -Headers $headers -Body $body -UseBasicParsing -ErrorAction Stop
            }
            "gemini" {
                $body = '{"contents":[{"parts":[{"text":"hi"}]}]}'
                $r = Invoke-WebRequest -Uri "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=$ApiKey" -Method POST -Headers $headers -Body $body -UseBasicParsing -ErrorAction Stop
            }
            "mistral" {
                $headers["Authorization"] = "Bearer $ApiKey"
                $body = '{"model":"mistral-small-latest","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'
                $r = Invoke-WebRequest -Uri "https://api.mistral.ai/v1/chat/completions" -Method POST -Headers $headers -Body $body -UseBasicParsing -ErrorAction Stop
            }
            "deepseek" {
                $headers["Authorization"] = "Bearer $ApiKey"
                $body = '{"model":"deepseek-chat","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'
                $r = Invoke-WebRequest -Uri "https://api.deepseek.com/v1/chat/completions" -Method POST -Headers $headers -Body $body -UseBasicParsing -ErrorAction Stop
            }
            "ollama" {
                $r = Invoke-WebRequest -Uri "$OllamaHost/api/tags" -Method GET -UseBasicParsing -ErrorAction Stop
            }
        }
        if ($r.StatusCode -eq 200) {
            Write-Host "✅ OK (HTTP 200)" -ForegroundColor Green
            return $true
        }
    } catch {
        $code = $_.Exception.Response.StatusCode.Value__
        Write-Host "❌ Failed (HTTP $code)" -ForegroundColor Red
    }
    return $false
}

# ─────────────────────────────────────────
# STEP 1 — API Key + connection test
# ─────────────────────────────────────────
Write-Host "[ STEP 1 / 3 ] API Key" -ForegroundColor Yellow
Write-Host "-----------------------------------------"

$apiKey = ""
$ollamaHost = "http://localhost:11434"

if ($provider -eq "ollama") {
    $inputHost = Read-Host "Ollama host [http://localhost:11434]"
    if ($inputHost) { $ollamaHost = $inputHost }

    if (-not (Test-LLMConnection -Provider "ollama" -OllamaHost $ollamaHost)) {
        Write-Host "⚠️  Cannot reach Ollama at $ollamaHost" -ForegroundColor Yellow
        Write-Host "   Make sure Ollama is running : ollama serve" -ForegroundColor Yellow
        $confirm = Read-Host "   Continue anyway? [y/N]"
        if ($confirm -notmatch "^[Yy]$") { Write-Host "Aborted."; exit 1 }
    }

    Set-Content -Path ".env" -Value "" -Encoding UTF8
    Write-Host "✅ Ollama configured (host: $ollamaHost)" -ForegroundColor Green
} else {
    $connected = $false
    while (-not $connected) {
        $secureKey = Read-Host "Enter your $envVar" -AsSecureString
        $apiKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
        )

        # Format check
        if ($apiKey.Length -le 10 -or ($keyPrefix -ne "" -and -not $apiKey.StartsWith($keyPrefix))) {
            Write-Host "⚠️  Invalid key format. Try again." -ForegroundColor Red
            continue
        }

        # Connection test
        $connected = Test-LLMConnection -Provider $provider -ApiKey $apiKey
        if (-not $connected) {
            Write-Host "⚠️  Connection failed. Check your key and network, then try again." -ForegroundColor Red
        }
    }

    Set-Content -Path ".env" -Value "$envVar=$apiKey" -Encoding UTF8
    Write-Host "✅ API key saved to .env" -ForegroundColor Green
}
Write-Host ""

# Update config.yaml provider field
$configContent = Get-Content "config.yaml" -Raw
$configContent = $configContent -replace '(?m)^provider:.*', "provider: `"$provider`""
if ($provider -eq "ollama") {
    $configContent = $configContent -replace '(?m)^ollama_host:.*', "ollama_host: `"$ollamaHost`""
}
Set-Content -Path "config.yaml" -Value $configContent -Encoding UTF8

# ─────────────────────────────────────────
# STEP 2 — Authorized scope
# ─────────────────────────────────────────
Write-Host "[ STEP 2 / 3 ] Authorized Scope" -ForegroundColor Yellow
Write-Host "-----------------------------------------"

do {
    $scopeUrl = Read-Host "Target URL (e.g. https://target.example.com)"
    $validUrl = $scopeUrl -match "^https?://" -and $scopeUrl -ne "https://xxx"
    if (-not $validUrl) { Write-Host "⚠️  Invalid URL or placeholder. Enter a real authorized target." -ForegroundColor Red }
} while (-not $validUrl)

$scopeNote = Read-Host "Authorization note (e.g. 'Pentest contract signed 2026-03-15')"
$scopeDate = Read-Host "Engagement date (e.g. 2026-03-15)"

New-Item -ItemType Directory -Force -Path "scopes" | Out-Null
New-Item -ItemType Directory -Force -Path "logs"   | Out-Null

$scopeContent = @"
**Scope autorisé :** $scopeUrl

**Autorisation :** $scopeNote

**Date :** $scopeDate
"@
Set-Content -Path "scopes\current_scope.md" -Value $scopeContent -Encoding UTF8

Write-Host "✅ Scope saved to scopes\current_scope.md" -ForegroundColor Green
Write-Host ""

# ─────────────────────────────────────────
# STEP 3 — Dependencies
# ─────────────────────────────────────────
Write-Host "[ STEP 3 / 3 ] Installing dependencies" -ForegroundColor Yellow
Write-Host "-----------------------------------------"

# Python check
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python not found — installing via winget..." -ForegroundColor Yellow
    winget install -e --id Python.Python.3.12 --silent
}

# pip packages
Write-Host "Installing Python packages..."
python -m pip install -r requirements.txt -q

# nuclei (Windows binary)
if (-not (Get-Command nuclei -ErrorAction SilentlyContinue)) {
    Write-Host "Downloading nuclei..."
    $nucleiUrl = "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_windows_amd64.zip"
    New-Item -ItemType Directory -Force -Path "bin" | Out-Null
    Invoke-WebRequest -Uri $nucleiUrl -OutFile "bin\nuclei.zip"
    Expand-Archive -Path "bin\nuclei.zip" -DestinationPath "bin" -Force
    Remove-Item "bin\nuclei.zip"
    Write-Host "✅ nuclei installed" -ForegroundColor Green
}

# ffuf (Windows binary)
if (-not (Get-Command ffuf -ErrorAction SilentlyContinue)) {
    Write-Host "Downloading ffuf..."
    $ffufUrl = "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_windows_amd64.zip"
    Invoke-WebRequest -Uri $ffufUrl -OutFile "bin\ffuf.zip"
    Expand-Archive -Path "bin\ffuf.zip" -DestinationPath "bin" -Force
    Remove-Item "bin\ffuf.zip"
    Write-Host "✅ ffuf installed" -ForegroundColor Green
}

# sqlmap (Python-based, works on Windows)
if (-not (Test-Path "tools\sqlmap_repo")) {
    Write-Host "Cloning sqlmap..."
    git clone https://github.com/sqlmapproject/sqlmap.git tools\sqlmap_repo 2>$null
    Write-Host "✅ sqlmap cloned" -ForegroundColor Green
}

# CyberStrikeAI
if (-not (Test-Path "tools\cyberstrike_repo")) {
    Write-Host "Cloning CyberStrikeAI..."
    git clone https://github.com/Ed1s0nZ/CyberStrikeAI.git tools\cyberstrike_repo 2>$null
    if (Get-Command go -ErrorAction SilentlyContinue) {
        Push-Location tools\cyberstrike_repo
        go build -o ..\..\bin\cyberstrike.exe .\cmd\cyberstrike 2>$null
        Pop-Location
        Write-Host "✅ CyberStrikeAI built" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Go not found — CyberStrikeAI skipped (install Go and re-run)" -ForegroundColor Yellow
    }
}

# Windows notes for Linux-only tools
Write-Host ""
Write-Host "ℹ️  Windows limitations:" -ForegroundColor Cyan
Write-Host "   • bettercap  : Linux/macOS only — use WSL2 for network MITM"
Write-Host "   • zphisher   : bash script — use WSL2 for phishing templates"

# ─────────────────────────────────────────
# Summary
# ─────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ✅ Installation complete !"            -ForegroundColor Green
Write-Host "  Provider : $($provider.ToUpper())"
Write-Host "  Scope    : $scopeUrl"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Launching Phantom now..." -ForegroundColor Cyan
Write-Host ""

# Load API key into current session
if ($provider -ne "ollama") {
    foreach ($line in Get-Content ".env") {
        if ($line -match "=") {
            $k, $v = $line -split "=", 2
            [System.Environment]::SetEnvironmentVariable($k.Trim(), $v.Trim(), "Process")
        }
    }
}
$env:PATH += ";$PWD\bin"

& python "agent\main.py"
