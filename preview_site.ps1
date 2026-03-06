# Preview the Mr Ninja website locally
# Usage: .\preview_site.ps1

Write-Host "🥷 Mr Ninja Website Preview" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is installed
$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pythonCmd = "python3"
} else {
    Write-Host "❌ Python is not installed. Please install Python 3 to run this script." -ForegroundColor Red
    Write-Host "   Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Navigate to public directory
$publicDir = Join-Path $PSScriptRoot "public"
if (-not (Test-Path $publicDir)) {
    Write-Host "❌ Error: public directory not found at $publicDir" -ForegroundColor Red
    exit 1
}

Set-Location $publicDir

# Configuration
$port = 8000
$url = "http://localhost:$port"

Write-Host "🚀 Starting local server on $url" -ForegroundColor Green
Write-Host "📂 Serving files from: $publicDir" -ForegroundColor Gray
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Open browser after a short delay
Start-Job -ScriptBlock {
    Start-Sleep -Seconds 2
    Start-Process $using:url
} | Out-Null

# Start HTTP server
try {
    & $pythonCmd -m http.server $port
} catch {
    Write-Host "❌ Error starting server: $_" -ForegroundColor Red
    exit 1
} finally {
    # Cleanup background job
    Get-Job | Where-Object { $_.State -eq "Completed" } | Remove-Job
}
