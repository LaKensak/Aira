"""
Détection de spawning de processus cachés en arrière-plan.

Cas typique : binaire qui lance cmd.exe/powershell avec CREATE_NO_WINDOW
ou STARTF_USESHOWWINDOW + SW_HIDE pour cacher la fenêtre.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import List

# ── Constantes Windows ──────────────────────────────────────────────────────
CREATE_NO_WINDOW        = 0x08000000
STARTF_USESHOWWINDOW   = 0x00000001
SW_HIDE                = 0
DETACHED_PROCESS        = 0x00000008
CREATE_NEW_CONSOLE      = 0x00000010

# Shells et interpréteurs cibles
_SHELL_STRINGS = [
    "cmd.exe", "cmd ", "/c ", "/C ",
    "powershell", "pwsh",
    "wscript.exe", "cscript.exe",
    "mshta.exe", "msiexec.exe",
    "wmic.exe", "wmic ",
    "bash.exe", "sh.exe",
    "conhost.exe",
    "-enc ", "-EncodedCommand", "-nop ", "-noprofile",
    "-windowstyle hidden", "-w hidden",
    "hidden",
]

# APIs de capture de sortie (pipe redirection en mode silencieux)
_PIPE_APIS = {
    "CreatePipe", "SetHandleInformation",
    "GetStdHandle", "ReadFile", "PeekNamedPipe",
}

# APIs de création de processus
_CREATE_APIS = {
    "CreateProcessA", "CreateProcessW",
    "CreateProcessAsUserA", "CreateProcessAsUserW",
    "CreateProcessWithLogonW", "CreateProcessWithTokenW",
    "ShellExecuteExA", "ShellExecuteExW",
    "WinExec",
    "NtCreateProcess", "NtCreateProcessEx",
    "RtlCreateUserProcess",
}


def detect_hidden_process(binary_path: str) -> dict:
    """
    Analyse statique complète pour détecter les patterns de spawning caché.
    """
    indicators: List[str] = []
    risk_level = "none"
    confidence = 0

    try:
        data = Path(binary_path).read_bytes()
    except OSError as e:
        return {"error": str(e), "indicators": [], "risk_level": "unknown"}

    text = data.decode("latin-1", errors="ignore")

    # ── 1. Détection de la constante CREATE_NO_WINDOW ────────────────────────
    # 0x08000000 en little-endian = 00 00 80 08
    cnw_bytes = struct.pack("<I", CREATE_NO_WINDOW)
    if cnw_bytes in data:
        indicators.append(f"Constante CREATE_NO_WINDOW (0x08000000) trouvée dans le binaire")
        confidence = max(confidence, 70)

    # ── 2. Détection SW_HIDE / STARTF_USESHOWWINDOW ──────────────────────────
    # STARTUPINFO.dwFlags = 1 + wShowWindow = 0
    startf_bytes = struct.pack("<IH", STARTF_USESHOWWINDOW, SW_HIDE)
    if startf_bytes in data:
        indicators.append("STARTF_USESHOWWINDOW + SW_HIDE détectés (fenêtre cachée)")
        confidence = max(confidence, 75)

    # ── 3. Strings shell présentes ───────────────────────────────────────────
    found_shells: list[str] = []
    for shell in _SHELL_STRINGS:
        if shell.lower() in text.lower():
            found_shells.append(shell.strip())

    if found_shells:
        unique_shells = list(dict.fromkeys(found_shells))[:8]
        indicators.append(f"Strings shell/interpréteur : {unique_shells}")
        confidence = max(confidence, 50)

    # ── 4. Analyse LIEF des imports ──────────────────────────────────────────
    try:
        import lief
        b = lief.parse(binary_path)
        if b is not None:
            if isinstance(b, lief.PE.Binary):
                symbols = set()
                for lib in b.imports:
                    for entry in lib.entries:
                        if entry.name:
                            symbols.add(entry.name)
            else:
                symbols = {
                    (getattr(s, "name", "") or "").strip()
                    for s in getattr(b, "imported_symbols", [])
                }

            # APIs de création de processus
            create_found = _CREATE_APIS & symbols
            if create_found:
                # Combinaison suspecte : creation + shell + pipe
                pipe_found = _PIPE_APIS & symbols
                if found_shells and create_found:
                    indicators.append(
                        f"Combo suspect : {create_found} + strings shell"
                        + (f" + pipe I/O ({pipe_found})" if pipe_found else "")
                    )
                    confidence = max(confidence, 85)
                elif create_found:
                    indicators.append(f"APIs de création de processus : {create_found}")
                    confidence = max(confidence, 40)

                if pipe_found:
                    indicators.append(
                        f"APIs de redirection I/O (sortie capturée) : {pipe_found}"
                    )
                    confidence = max(confidence, 60)

    except Exception as e:
        indicators.append(f"[LIEF error] {e}")

    # ── 5. Patterns bytes spécifiques (DETACHED_PROCESS) ────────────────────
    detached_bytes = struct.pack("<I", DETACHED_PROCESS)
    if detached_bytes in data:
        indicators.append("Constante DETACHED_PROCESS (0x00000008) — processus sans console")
        confidence = max(confidence, 50)

    # ── 6. Encodage PowerShell Base64 ────────────────────────────────────────
    import re as _re
    ps_enc = _re.search(
        r'(?:-enc|-EncodedCommand|-e)\s+([A-Za-z0-9+/=]{20,})',
        text, _re.IGNORECASE
    )
    if ps_enc:
        import base64 as _b64
        try:
            decoded = _b64.b64decode(ps_enc.group(1)).decode("utf-16-le", errors="ignore")
            indicators.append(f"PowerShell encodé détecté : '{decoded[:120]}…'")
            confidence = max(confidence, 90)
        except Exception:
            indicators.append("Argument PowerShell -enc détecté (décodage échoué)")
            confidence = max(confidence, 70)

    # ── Verdict ──────────────────────────────────────────────────────────────
    if confidence >= 80:
        risk_level = "critical"
    elif confidence >= 60:
        risk_level = "high"
    elif confidence >= 40:
        risk_level = "medium"
    elif confidence > 0:
        risk_level = "low"
    else:
        risk_level = "none"

    return {
        "indicators":  indicators,
        "confidence":  confidence,
        "risk_level":  risk_level,
        "shells_found": list(dict.fromkeys(found_shells))[:10],
        "verdict": (
            "Spawning de processus caché probable"
            if confidence >= 60 else
            "Indicateurs de spawning caché faibles / absents"
        ),
    }
