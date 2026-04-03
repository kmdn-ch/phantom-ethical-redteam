#Requires -Version 5.1
<#
.SYNOPSIS
    Phantom - Ethical RedTeam -- One-line installer
.DESCRIPTION
    Bootstrap script. Clones the repo and launches the interactive installer.
    Usage: irm https://raw.githubusercontent.com/kmdn-ch/phantom-ethical-redteam/main/get.ps1 | iex
#>

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$REPO = "https://github.com/kmdn-ch/phantom-ethical-redteam.git"
$DEST = "$env:ProgramFiles\Phantom"

# --- Require administrator (Program Files needs elevation) ---
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Run this script as Administrator (right-click PowerShell -> Run as Administrator)." -ForegroundColor Red
    Write-Host "        Phantom installs to: $DEST" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Phantom - Ethical RedTeam" -ForegroundColor Cyan
Write-Host "  One-line installer" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# --- Check git ---
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] git is required. Install it from https://git-scm.com" -ForegroundColor Red
    exit 1
}

# --- Check Python ---
$python = $null
foreach ($cmd in @("python", "python3", "py")) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        try {
            $ver = & $cmd --version 2>&1
            if ($ver -match "Python 3\.(\d+)" -and [int]$Matches[1] -ge 11) {
                $python = $cmd
                break
            }
        } catch {
            # Windows Store stub or other error -- try next candidate
        }
    }
}
if (-not $python) {
    Write-Host "[ERROR] Python 3.11+ is required. Install it from https://python.org" -ForegroundColor Red
    exit 1
}

# --- Clone or update ---
if (Test-Path "$DEST\.git") {
    Write-Host "  [i] Existing installation found at $DEST" -ForegroundColor Cyan
    Write-Host "  --> Updating to latest version..." -ForegroundColor Yellow
    Push-Location $DEST
    git pull --quiet origin main
    Pop-Location
} else {
    if (Test-Path $DEST) {
        Write-Host "  [i] Directory $DEST exists but is not a git repo — removing it." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $DEST
    }
    Write-Host "  --> Cloning Phantom to $DEST ..." -ForegroundColor Yellow
    git clone --quiet $REPO $DEST
    Write-Host "  [OK] Cloned to $DEST" -ForegroundColor Green
}

# --- Launch installer ---
Write-Host ""
Write-Host "  --> Launching installer from $DEST ..." -ForegroundColor Yellow
Write-Host ""
Set-Location $DEST
& powershell.exe -ExecutionPolicy Bypass -File "$DEST\install.ps1"
