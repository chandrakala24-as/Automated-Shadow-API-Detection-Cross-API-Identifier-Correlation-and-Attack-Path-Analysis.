Set-Location $PSScriptRoot
if (-not (Test-Path .venv) -or -not (Test-Path frontend\dist\index.html)) {
    Write-Host 'Run .\setup.ps1 first.'
    exit 1
}
.\.venv\Scripts\python.exe run.py @args
