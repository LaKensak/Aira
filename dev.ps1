$env:PYTHONUNBUFFERED="1"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

# Vérification .env
if (-not (Test-Path ".env")) {
  Write-Warning ".env introuvable. Copie .env.example vers .env et configure tes clés."
  exit 1
}

# Création du venv si absent (compatible Python 3.10+)
if (-Not (Test-Path ".venv")) {
  Write-Host "Création du venv..."
  $pyCmd = $null
  foreach ($candidate in @("python", "py -3.11", "py -3.10", "python3")) {
    try {
      $ver = & $candidate.Split()[0] ($candidate.Split()[1..99]) --version 2>&1
      if ($ver -match "Python 3\.(1[0-9]|[2-9][0-9])") {
        $pyCmd = $candidate; break
      }
    } catch {}
  }
  if (-not $pyCmd) { Write-Error "Python 3.10+ introuvable."; exit 1 }
  Invoke-Expression "$pyCmd -m venv .venv"
}

.\.venv\Scripts\Activate.ps1
python -m pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

Write-Host "Démarrage AIRA en mode dev -> http://localhost:8000"
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
