param(
  [switch]$AI,
  [switch]$Sym
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

# Verification .env
if (-not (Test-Path ".env")) {
  Write-Warning ".env introuvable - certains services risquent de ne pas demarrer."
}

if (-not $AI -and -not $Sym) {
  $AI = $true; $Sym = $true
}

$Python = "$Root\.venv\Scripts\python.exe"
$Uvicorn = "$Root\.venv\Scripts\uvicorn.exe"

if ($Sym) {
  Write-Host "Demarrage SymExec (port 8001)..."
  Start-Process powershell -NoNewWindow -PassThru -ArgumentList "-NoProfile","-Command","cd '$Root'; & '$Python' -m services.symexec_service.server" | Out-Null
}
if ($AI) {
  Write-Host "Demarrage AI Service (port 8002)..."
  Start-Process powershell -NoNewWindow -PassThru -ArgumentList "-NoProfile","-Command","cd '$Root'; & '$Python' -m services.ai_service.server" | Out-Null
}

# Ghidra MCP bridge
Write-Host "Demarrage Ghidra MCP bridge (port 8081)..."
Start-Process powershell -NoNewWindow -PassThru -ArgumentList "-NoProfile","-Command","cd '$Root'; & '$Python' -m aira.cli ghidra-mcp --transport sse --ghidra-server http://127.0.0.1:8080/ --mcp-host 127.0.0.1 --mcp-port 8081" | Out-Null

# FastAPI
Write-Host "Demarrage API AIRA (port 8000)..."
Start-Process powershell -NoNewWindow -PassThru -ArgumentList "-NoProfile","-Command","cd '$Root'; & '$Uvicorn' app.main:app --host 127.0.0.1 --port 8000" | Out-Null

Write-Host ""
Write-Host "Services demarres :"
Write-Host "  API AIRA   -> http://127.0.0.1:8000"
Write-Host "  SymExec    -> http://127.0.0.1:8001"
Write-Host "  AI Service -> http://127.0.0.1:8002"
Write-Host "  Ghidra MCP -> http://127.0.0.1:8081/sse"
Write-Host "  LangFlow   -> http://localhost:7860"
