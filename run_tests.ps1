$ErrorActionPreference = 'Stop'
if (-not (Test-Path ".venv")) {
  py -3.11 -m venv .venv
}
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
# No external test deps needed; use stdlib unittest
python -m unittest discover -v
