$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw 'Python is required.' }
python -c "import paramiko" 2>$null
if ($LASTEXITCODE -ne 0) { python -m pip install -r requirements.txt }
python app.py
