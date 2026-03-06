# scripts/run_demo.ps1
#
# Run the Mr Ninja demo simulation on Windows.
# Generates a synthetic 512-file MR and analyzes it end-to-end.
#
# Usage:
#   .\scripts\run_demo.ps1
#   .\scripts\run_demo.ps1 -Files 1000
#   .\scripts\run_demo.ps1 -Output report.md

param(
    [int]$Files = 512,
    [string]$Output = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir

Write-Host "=============================================="
Write-Host "  MR NINJA - Demo Runner"
Write-Host "  Large Context Orchestrator for GitLab Duo"
Write-Host "=============================================="
Write-Host ""

# Check Python
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Python: $pythonVersion"
} catch {
    Write-Host "ERROR: Python is not installed or not in PATH."
    exit 1
}

# Install dependencies if needed
try {
    python -c "import pydantic" 2>$null
} catch {
    Write-Host ""
    Write-Host "Installing dependencies..."
    pip install -r "$ProjectDir\requirements.txt" --quiet
}

Write-Host ""

# Run the demo
Set-Location $ProjectDir

if ($Output) {
    python -m demo.simulate_large_mr --files $Files --output $Output
} else {
    python -m demo.simulate_large_mr --files $Files
}

Write-Host ""
Write-Host "Demo complete."
