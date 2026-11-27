# One-time setup: Python environment, packages and the frontend build.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Assert-Success($step) { if ($LASTEXITCODE -ne 0) { throw "$step failed." } }

if (-not (Test-Path .venv)) { python -m venv .venv; Assert-Success 'Creating the virtual environment' }
.\.venv\Scripts\python.exe -m pip install -q -r backend\requirements-dev.txt
Assert-Success 'Installing Python packages'

Push-Location frontend
try {
    npm ci
    Assert-Success 'npm ci'
    npm run build
    Assert-Success 'Building the frontend'
} finally { Pop-Location }

Write-Host "`nSetup finished. Start the application with:  .\start.ps1"
