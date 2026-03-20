#Requires -Version 5.1
<#
.SYNOPSIS
    Phantom - Ethical RedTeam -- Windows Installer v2.2.1
.DESCRIPTION
    Interactive setup: LLM provider, API key, authorized scope, dependencies.
    Run from the repo root: .\install.ps1
#>

$ErrorActionPreference = "Stop"


Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Phantom - Ethical RedTeam"              -ForegroundColor Cyan
Write-Host "  Installer v2.2.1 (Windows)"            -ForegroundColor Cyan
Write-Host "========================================"  -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------
# STEP 0 -- LLM Provider selection (with Ollama auto-detection)
# -----------------------------------------
Write-Host "[ STEP 0 / 3 ] LLM Provider" -ForegroundColor Yellow
Write-Host "-----------------------------------------"

$providerMap = @{
    "1" = @{ Name = "anthropic"; EnvVar = "ANTHROPIC_API_KEY"; Prefix = "sk-ant-" }
    "2" = @{ Name = "openai";    EnvVar = "OPENAI_API_KEY";    Prefix = "sk-" }
    "3" = @{ Name = "grok";      EnvVar = "XAI_API_KEY";       Prefix = "xai-" }
    "4" = @{ Name = "gemini";    EnvVar = "GEMINI_API_KEY";    Prefix = "" }
    "5" = @{ Name = "mistral";   EnvVar = "MISTRAL_API_KEY";   Prefix = "" }
    "6" = @{ Name = "deepseek";  EnvVar = "DEEPSEEK_API_KEY";  Prefix = "" }
    "7" = @{ Name = "ollama";    EnvVar = "";                  Prefix = "" }
}

# --- Auto-detect Ollama ---
$ollamaDetected = $false
$ollamaAutoModel = ""
$ollamaAutoHost = "http://localhost:11434"

if (Get-Command ollama -ErrorAction SilentlyContinue) {
    Write-Host "  [i] Ollama detected on this system." -ForegroundColor Cyan
    try {
        $tags = Invoke-RestMethod -Uri "$ollamaAutoHost/api/tags" -UseBasicParsing -ErrorAction Stop
        if ($tags.models.Count -gt 0) {
            $ollamaDetected = $true
            # Pick the first available model
            $ollamaAutoModel = $tags.models[0].name
            Write-Host "  [i] Ollama is running with $($tags.models.Count) model(s):" -ForegroundColor Cyan
            foreach ($m in $tags.models) {
                $size = ""
                if ($m.size) { $size = " ($([math]::Round($m.size / 1GB, 1)) GB)" }
                Write-Host "       - $($m.name)$size" -ForegroundColor White
            }
            Write-Host ""
            Write-Host "  --> Ollama auto-detected with model: $ollamaAutoModel" -ForegroundColor Green
            $useOllama = Read-Host "  Use Ollama with '$ollamaAutoModel'? [Y/n]"
            if ($useOllama -eq "" -or $useOllama -match "^[Yy]$") {
                # Let user pick a different model if multiple are available
                if ($tags.models.Count -gt 1) {
                    $pickModel = Read-Host "  Use '$ollamaAutoModel' or type another model name [Enter = keep]"
                    if ($pickModel) { $ollamaAutoModel = $pickModel }
                }
                Write-Host ""
            } else {
                $ollamaDetected = $false
            }
        } else {
            Write-Host "  [!] Ollama is running but no models installed." -ForegroundColor Yellow
            Write-Host "      Install a model first: ollama pull deepseek-v3.2:cloud" -ForegroundColor Yellow
            Write-Host ""
        }
    } catch {
        Write-Host "  [!] Ollama installed but not running. Start it with: ollama serve" -ForegroundColor Yellow
        Write-Host ""
    }
}

if ($ollamaDetected) {
    # Skip provider selection -- use Ollama
    $provider = "ollama"
    $envVar = ""
    $keyPrefix = ""
    $ollamaModel = $ollamaAutoModel
    $ollamaHost = $ollamaAutoHost
    Write-Host "[OK] Provider: OLLAMA (auto-detected)" -ForegroundColor Green
    Write-Host "     Model: $ollamaModel" -ForegroundColor Green
    Write-Host "     Host: $ollamaHost" -ForegroundColor Green
    Write-Host ""
} else {
    # Manual provider selection
    Write-Host "  1) Anthropic  (Claude sonnet-4-6)   - https://console.anthropic.com"
    Write-Host "  2) OpenAI     (ChatGPT 5.4)         - https://platform.openai.com"
    Write-Host "  3) xAI        (Grok 4.20 Beta)      - https://console.x.ai"
    Write-Host "  4) Google     (Gemini 3)             - https://aistudio.google.com/apikey"
    Write-Host "  5) Mistral    (mistral-large)        - https://console.mistral.ai"
    Write-Host "  6) DeepSeek   (DeepSeek 3.2)         - https://platform.deepseek.com"
    Write-Host "  7) Ollama     (local)"
    Write-Host ""

    do {
        $choice = Read-Host "Choose provider [1-7]"
    } while (-not $providerMap.ContainsKey($choice))

    $provider   = $providerMap[$choice].Name
    $envVar     = $providerMap[$choice].EnvVar
    $keyPrefix  = $providerMap[$choice].Prefix

    Write-Host "[OK] Provider selected : $($provider.ToUpper())" -ForegroundColor Green
    Write-Host ""
}

# -----------------------------------------
# Helper -- test LLM connection
# -----------------------------------------
function Test-LLMConnection {
    param([string]$Provider, [string]$ApiKey, [string]$OllamaHost = "http://localhost:11434")

    Write-Host -NoNewline "  -> Testing connection to $Provider API... "

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
                $uri = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=$ApiKey"
                $r = Invoke-WebRequest -Uri $uri -Method POST -Headers $headers -Body $body -UseBasicParsing -ErrorAction Stop
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
            Write-Host "[OK] (HTTP 200)" -ForegroundColor Green
            return $true
        }
    } catch {
        $code = $_.Exception.Response.StatusCode.Value__
        Write-Host "[FAIL] (HTTP $code)" -ForegroundColor Red
    }
    return $false
}

# -----------------------------------------
# STEP 1 -- API Key + connection test
# -----------------------------------------
Write-Host "[ STEP 1 / 3 ] API Key" -ForegroundColor Yellow
Write-Host "-----------------------------------------"

$apiKey = ""
$ollamaHost = "http://localhost:11434"

if ($provider -eq "ollama" -and $ollamaDetected) {
    # Already configured by auto-detection -- just write .env and confirm connection
    Write-Host "  Ollama already configured by auto-detection." -ForegroundColor Green
    Write-Host "  -> Testing connection to $ollamaHost..."
    if (Test-LLMConnection -Provider "ollama" -OllamaHost $ollamaHost) {
        Write-Host "  [OK] Connection confirmed." -ForegroundColor Green
    }
    [System.IO.File]::WriteAllText("$PWD\.env", "", [System.Text.UTF8Encoding]::new($false))

} elseif ($provider -eq "ollama") {
    # Manual Ollama setup (user chose option 7 without auto-detect)
    $ollamaHost = "http://localhost:11434"
    $inputHost = Read-Host "Ollama host [http://localhost:11434]"
    if ($inputHost) { $ollamaHost = $inputHost }

    if (-not (Test-LLMConnection -Provider "ollama" -OllamaHost $ollamaHost)) {
        Write-Host "[!] Cannot reach Ollama at $ollamaHost" -ForegroundColor Yellow
        Write-Host "    Make sure Ollama is running : ollama serve" -ForegroundColor Yellow
        $confirm = Read-Host "    Continue anyway? [y/N]"
        if ($confirm -notmatch "^[Yy]$") { Write-Host "Aborted."; exit 1 }
    }

    # List local models and let user pick or pull one
    $ollamaModel = "deepseek-v3.2:cloud"
    Write-Host ""
    Write-Host "  Default Ollama model: $ollamaModel"
    try {
        $tags = Invoke-RestMethod -Uri "$ollamaHost/api/tags" -UseBasicParsing -ErrorAction Stop
        if ($tags.models.Count -gt 0) {
            Write-Host "  Local models found:" -ForegroundColor Cyan
            foreach ($m in $tags.models) { Write-Host "    - $($m.name)" }
        } else {
            Write-Host "  No local models found." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [!] Could not list models (Ollama unreachable)" -ForegroundColor Yellow
    }
    $inputModel = Read-Host "Model name [$ollamaModel]"
    if ($inputModel) { $ollamaModel = $inputModel }

    # Pull the model if not already present
    Write-Host "  Checking if '$ollamaModel' is available locally..."
    try {
        $tags = Invoke-RestMethod -Uri "$ollamaHost/api/tags" -UseBasicParsing -ErrorAction Stop
        $found = $tags.models | Where-Object { $_.name -eq $ollamaModel -or $_.name -eq "$ollamaModel`:latest" }
        if (-not $found) {
            Write-Host "  Pulling '$ollamaModel' (this may take a while)..." -ForegroundColor Yellow
            try {
                $env:GIT_REDIRECT_STDERR = "2>&1"
                ollama pull $ollamaModel
                Write-Host "  [OK] Model '$ollamaModel' pulled" -ForegroundColor Green
            } catch {
                Write-Host "  [!] Pull failed. Run manually: ollama pull $ollamaModel" -ForegroundColor Yellow
            } finally {
                Remove-Item Env:\GIT_REDIRECT_STDERR -ErrorAction SilentlyContinue
            }
        } else {
            Write-Host "  [OK] Model '$ollamaModel' already available" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] Could not check models. Run manually: ollama pull $ollamaModel" -ForegroundColor Yellow
    }

    [System.IO.File]::WriteAllText("$PWD\.env", "", [System.Text.UTF8Encoding]::new($false))
    Write-Host "[OK] Ollama configured (host: $ollamaHost, model: $ollamaModel)" -ForegroundColor Green
} else {
    $connected = $false
    while (-not $connected) {
        $secureKey = Read-Host "Enter your $envVar" -AsSecureString
        $apiKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
        )

        # Format check
        if ($apiKey.Length -le 10 -or ($keyPrefix -ne "" -and -not $apiKey.StartsWith($keyPrefix))) {
            Write-Host "[!] Invalid key format. Try again." -ForegroundColor Red
            continue
        }

        # Connection test
        $connected = Test-LLMConnection -Provider $provider -ApiKey $apiKey
        if (-not $connected) {
            Write-Host "[!] Connection failed. Check your key and network, then try again." -ForegroundColor Red
        }
    }

    [System.IO.File]::WriteAllText("$PWD\.env", "$envVar=$apiKey", [System.Text.UTF8Encoding]::new($false))
    Write-Host "[OK] API key saved to .env" -ForegroundColor Green
}
Write-Host ""

# Create config.yaml from template if missing
if (-not (Test-Path "config.yaml")) {
    if (Test-Path "config.yaml.example") {
        Copy-Item "config.yaml.example" "config.yaml"
    } else {
        Write-Host "[!] config.yaml.example not found" -ForegroundColor Red; exit 1
    }
}

# Update config.yaml provider field (UTF-8 without BOM -- BOM breaks YAML parser)
$configContent = Get-Content "config.yaml" -Raw
$configContent = $configContent -replace '(?m)^provider:.*', "provider: `"$provider`""
if ($provider -eq "ollama") {
    $configContent = $configContent -replace '(?m)^ollama_host:.*', "ollama_host: `"$ollamaHost`""
    $configContent = $configContent -replace '(?m)^model:.*', "model: `"$ollamaModel`""
}
$configContent = $configContent.TrimEnd()
[System.IO.File]::WriteAllText("$PWD\config.yaml", $configContent, [System.Text.UTF8Encoding]::new($false))

# -----------------------------------------
# STEP 2 -- Authorized scope
# -----------------------------------------
Write-Host "[ STEP 2 / 3 ] Authorized Scope" -ForegroundColor Yellow
Write-Host "-----------------------------------------"

do {
    $scopeUrl = Read-Host "Target URL (e.g. https://target.example.com)"
    $validUrl = $scopeUrl -match "^https?://" -and $scopeUrl -ne "https://xxx"
    if (-not $validUrl) { Write-Host "[!] Invalid URL or placeholder. Enter a real authorized target." -ForegroundColor Red }
} while (-not $validUrl)

$scopeNote = Read-Host "Authorization note (e.g. 'Pentest contract signed 2026-03-15')"
$scopeDate = Read-Host "Engagement date (e.g. 2026-03-15)"

New-Item -ItemType Directory -Force -Path "scopes" | Out-Null
New-Item -ItemType Directory -Force -Path "logs"   | Out-Null

$scopeContent = @"
**Scope autorise :** $scopeUrl

**Autorisation :** $scopeNote

**Date :** $scopeDate
"@
Set-Content -Path "scopes\current_scope.md" -Value $scopeContent -Encoding UTF8

Write-Host "[OK] Scope saved to scopes\current_scope.md" -ForegroundColor Green
Write-Host ""

# -----------------------------------------
# STEP 3 -- Dependencies
# -----------------------------------------
Write-Host "[ STEP 3 / 3 ] Installing dependencies" -ForegroundColor Yellow
Write-Host "-----------------------------------------"

# Python check
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python not found -- installing via winget..." -ForegroundColor Yellow
    winget install -e --id Python.Python.3.12 --silent
}

# pip packages
Write-Host "Installing Python packages..."
python -m pip install -r requirements.txt -q

# nuclei (Windows binary)
if (-not (Get-Command nuclei -ErrorAction SilentlyContinue)) {
    Write-Host "Downloading nuclei..."
    New-Item -ItemType Directory -Force -Path "bin" | Out-Null
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest" -UseBasicParsing
        $asset = $rel.assets | Where-Object { $_.name -match "windows.*amd64.*\.zip$" } | Select-Object -First 1
        if (-not $asset) { throw "No matching asset found" }
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile "bin\nuclei.zip" -UseBasicParsing
        Expand-Archive -Path "bin\nuclei.zip" -DestinationPath "bin" -Force
        Remove-Item "bin\nuclei.zip"
        Write-Host "[OK] nuclei installed ($($rel.tag_name))" -ForegroundColor Green
    } catch {
        Write-Host "[!] nuclei download failed: $_" -ForegroundColor Yellow
        Write-Host "    Install manually: https://github.com/projectdiscovery/nuclei/releases" -ForegroundColor Yellow
    }
}

# ffuf (Windows binary)
if (-not (Get-Command ffuf -ErrorAction SilentlyContinue)) {
    Write-Host "Downloading ffuf..."
    New-Item -ItemType Directory -Force -Path "bin" | Out-Null
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/ffuf/ffuf/releases/latest" -UseBasicParsing
        $asset = $rel.assets | Where-Object { $_.name -match "windows.*amd64.*\.zip$" } | Select-Object -First 1
        if (-not $asset) { throw "No matching asset found" }
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile "bin\ffuf.zip" -UseBasicParsing
        Expand-Archive -Path "bin\ffuf.zip" -DestinationPath "bin" -Force
        Remove-Item "bin\ffuf.zip"
        Write-Host "[OK] ffuf installed ($($rel.tag_name))" -ForegroundColor Green
    } catch {
        Write-Host "[!] ffuf download failed: $_" -ForegroundColor Yellow
        Write-Host "    Install manually: https://github.com/ffuf/ffuf/releases" -ForegroundColor Yellow
    }
}

# Default wordlist for ffuf (SecLists -- shared with run_payloads PATT wordlists)
New-Item -ItemType Directory -Force -Path "wordlists" | Out-Null
if (-not (Test-Path "wordlists\directory-list-2.3-medium.txt")) {
    Write-Host "Downloading default wordlist (SecLists)..."
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/danielmiessler/SecLists/main/Discovery/Web-Content/directory-list-2.3-medium.txt" `
            -OutFile "wordlists\directory-list-2.3-medium.txt" -UseBasicParsing
        $lines = (Get-Content "wordlists\directory-list-2.3-medium.txt").Count
        Write-Host "[OK] wordlist downloaded ($lines entries)" -ForegroundColor Green
    } catch {
        Write-Host "[!] wordlist download failed -- use run_payloads to generate PATT wordlists" -ForegroundColor Yellow
    }
}

# sqlmap (Python-based, works on Windows)
if (-not (Test-Path "tools\sqlmap_repo")) {
    Write-Host "Cloning sqlmap..."
    try {
        $env:GIT_REDIRECT_STDERR = "2>&1"
        git clone --quiet https://github.com/sqlmapproject/sqlmap.git tools\sqlmap_repo
        Write-Host "[OK] sqlmap cloned" -ForegroundColor Green
    } catch {
        Write-Host "[!] sqlmap clone failed: $_" -ForegroundColor Yellow
    } finally {
        Remove-Item Env:\GIT_REDIRECT_STDERR -ErrorAction SilentlyContinue
    }
}

# CyberStrikeAI
if (-not (Test-Path "tools\cyberstrike_repo")) {
    Write-Host "Cloning CyberStrikeAI..."
    try {
        $env:GIT_REDIRECT_STDERR = "2>&1"
        git clone --quiet https://github.com/Ed1s0nZ/CyberStrikeAI.git tools\cyberstrike_repo
        if (Get-Command go -ErrorAction SilentlyContinue) {
            Push-Location tools\cyberstrike_repo
            go build -o ..\..\bin\cyberstrike.exe .\cmd\cyberstrike 2>$null
            Pop-Location
            Write-Host "[OK] CyberStrikeAI built" -ForegroundColor Green
        } else {
            Write-Host "[!] Go not found -- CyberStrikeAI skipped (install Go and re-run)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] CyberStrikeAI clone failed: $_" -ForegroundColor Yellow
    } finally {
        Remove-Item Env:\GIT_REDIRECT_STDERR -ErrorAction SilentlyContinue
    }
}

# Windows notes for Linux-only tools
Write-Host ""
Write-Host "[i] Windows limitations:" -ForegroundColor Cyan
Write-Host "    - bettercap  : Linux/macOS only -- use WSL2 for network MITM"
Write-Host "    - zphisher   : bash script -- use WSL2 for phishing templates"

# -----------------------------------------
# Summary
# -----------------------------------------
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  [OK] Installation complete !"          -ForegroundColor Green
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
