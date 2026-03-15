#Requires -Version 5.1
<#
.SYNOPSIS
    Phantom – Claude Ethical RedTeam — Windows Installer v1.3.0
.DESCRIPTION
    Interactive setup: LLM provider, API key, authorized scope, dependencies.
    Run from the repo root: .\install.ps1
#>

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Phantom - Claude Ethical RedTeam"      -ForegroundColor Cyan
Write-Host "  Installer v1.3.0 (Windows)"            -ForegroundColor Cyan
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
# STEP 1 — API Key
# ─────────────────────────────────────────
Write-Host "[ STEP 1 / 3 ] API Key" -ForegroundColor Yellow
Write-Host "-----------------------------------------"

$apiKey = ""
$ollamaHost = "http://localhost:11434"

if ($provider -eq "ollama") {
    $input = Read-Host "Ollama host [http://localhost:11434]"
    if ($input) { $ollamaHost = $input }
    Set-Content -Path ".env" -Value "" -Encoding UTF8
    Write-Host "✅ Ollama configured (host: $ollamaHost)" -ForegroundColor Green
} else {
    do {
        $secureKey = Read-Host "Enter your $envVar" -AsSecureString
        $apiKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
        )
        $valid = ($apiKey.Length -gt 10) -and ($keyPrefix -eq "" -or $apiKey.StartsWith($keyPrefix))
        if (-not $valid) { Write-Host "⚠️  Invalid key. Try again." -ForegroundColor Red }
    } while (-not $valid)

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
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Provider : $($provider.ToUpper())"
Write-Host "  Scope    : $scopeUrl"
Write-Host ""
Write-Host "  To start Phantom :"
Write-Host ""
if ($provider -ne "ollama") {
    Write-Host '  # Load API key'
    Write-Host '  foreach ($line in Get-Content .env) { [System.Environment]::SetEnvironmentVariable($line.Split("=")[0], $line.Split("=",2)[1]) }'
}
Write-Host '  $env:PATH += ";$PWD\bin"'
Write-Host "  python agent\main.py"
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
