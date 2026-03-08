"""
AIRA x64dbg Client — Level 5 du cascade d'analyse.

Trois modes (du plus au moins automatique) :
  1. winappdbg  : débogueur Python 3 natif Windows (pip install winappdbg3)
                  pose des BPs sur strcmp/strncmp, capture les args automatiquement
  2. HTTP API   : si le plugin x64dbg-rest-api est installé (port 2819)
  3. Script     : génère un script x64dbg .x64dbg à charger manuellement

Configuration dans .env :
  X64DBG_PATH=F:\\x64dbg\\release\\x64\\x64dbg.exe
  X64DBG_API_PORT=2819
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

import requests

# ── Config ───────────────────────────────────────────────────────────────────

_DEFAULT_PATHS = [
    r"C:\x64dbg\release\x64\x64dbg.exe",
    r"C:\tools\x64dbg\release\x64\x64dbg.exe",
    r"C:\Program Files\x64dbg\release\x64\x64dbg.exe",
    r"D:\x64dbg\release\x64\x64dbg.exe",
    r"D:\tools\x64dbg\release\x64\x64dbg.exe",
]

_API_PORT = int(os.getenv("X64DBG_API_PORT", "2819"))
_API_BASE = f"http://127.0.0.1:{_API_PORT}"


def _find_x64dbg() -> Optional[str]:
    """Find x64dbg.exe — checks env var first, then common locations."""
    from_env = os.getenv("X64DBG_PATH", "").strip()
    if from_env and Path(from_env).exists():
        return from_env
    for p in _DEFAULT_PATHS:
        if Path(p).exists():
            return p
    return None


# ── HTTP API mode (plugin requis) ────────────────────────────────────────────

class X64DbgApiClient:
    """
    Client pour le plugin x64dbg REST API.

    Endpoints utilisés :
      GET /bp/set?addr=<hex>       → poser un breakpoint
      GET /run                     → lancer/continuer l'exécution
      GET /pause                   → mettre en pause
      GET /reg?name=<r>            → lire un registre
      GET /mem?addr=<hex>&size=64  → lire la mémoire (string)
      GET /status                  → état du débogueur
    """

    def __init__(self, base: str = _API_BASE, timeout: int = 5):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self._s = requests.Session()

    def _get(self, path: str, params: dict | None = None) -> dict:
        try:
            r = self._s.get(f"{self.base}{path}", params=params, timeout=self.timeout)
            if r.ok:
                try:
                    return r.json()
                except Exception:
                    return {"text": r.text}
        except Exception:
            pass
        return {}

    def _post(self, path: str, data: dict) -> dict:
        try:
            r = self._s.post(f"{self.base}{path}", json=data, timeout=self.timeout)
            if r.ok:
                return r.json() if r.text else {}
        except Exception:
            pass
        return {}

    def is_available(self) -> bool:
        result = self._get("/status")
        return bool(result)

    def set_breakpoint(self, address: str) -> bool:
        """Poser un breakpoint à l'adresse hex donnée (ex: '0x140001234')."""
        result = self._get("/bp/set", {"addr": address})
        return bool(result)

    def set_breakpoint_on_symbol(self, symbol: str) -> bool:
        """Poser un BP sur un symbole comme 'msvcrt.strncmp'."""
        result = self._get("/bp/set", {"symbol": symbol})
        return bool(result)

    def run(self) -> bool:
        result = self._get("/run")
        return bool(result)

    def pause(self) -> bool:
        result = self._get("/pause")
        return bool(result)

    def read_register(self, name: str) -> str:
        """Lire un registre (ex: 'rcx', 'rdx', 'rip')."""
        result = self._get("/reg", {"name": name})
        return result.get("value", result.get("text", ""))

    def read_string_at(self, address: str, size: int = 64) -> str:
        """Lire une chaîne en mémoire à l'adresse donnée."""
        result = self._get("/mem", {"addr": address, "size": size})
        raw = result.get("bytes", result.get("text", ""))
        if isinstance(raw, list):
            try:
                b = bytes(raw)
                return b.split(b"\x00")[0].decode("utf-8", errors="replace")
            except Exception:
                return ""
        return str(raw)

    def get_strcmp_args(self) -> tuple[str, str]:
        """
        Lire les arguments d'un appel strncmp/strcmp depuis les registres.
        Convention d'appel Windows x64 : RCX=arg1, RDX=arg2
        """
        rcx = self.read_register("rcx")
        rdx = self.read_register("rdx")
        s1 = self.read_string_at(rcx) if rcx else ""
        s2 = self.read_string_at(rdx) if rdx else ""
        return s1, s2

    def intercept_comparisons(
        self,
        binary_path: str,
        probe_input: str = "AAAA1234",
        wait_seconds: int = 8,
    ) -> list[dict]:
        """
        Lance le binaire dans x64dbg, pose des BPs sur les fonctions de comparaison,
        collecte les paires (s1, s2) interceptées.
        """
        comparisons: list[dict] = []

        cmp_symbols = [
            "msvcrt.strncmp", "msvcrt.strcmp", "msvcrt._stricmp",
            "ucrtbase.strncmp", "ucrtbase.strcmp",
            "KERNEL32.lstrcmpA", "KERNEL32.lstrcmpiA",
        ]
        for sym in cmp_symbols:
            self.set_breakpoint_on_symbol(sym)

        self.run()

        deadline = time.time() + wait_seconds
        hits = 0
        while time.time() < deadline and hits < 20:
            status = self._get("/status").get("state", "")
            if status in ("paused", "broken", "bp"):
                s1, s2 = self.get_strcmp_args()
                if s1 or s2:
                    comparisons.append({"s1": s1, "s2": s2})
                hits += 1
                self.run()
            time.sleep(0.3)

        self.pause()
        return comparisons


# ── Script mode (sans plugin) ────────────────────────────────────────────────

_SCRIPT_TEMPLATE = """\
;; ============================================================
;; AIRA — Script x64dbg auto-généré
;; Binaire : {binary}
;; Objectif : intercepter les comparaisons de strings
;; ============================================================

;; Charger le binaire
init "{binary}"

;; Attendre que le chargement soit terminé
pause

;; --- Breakpoints sur les fonctions de comparaison ---
bpx strncmp
bpx strcmp
bpx _stricmp
bpx lstrcmpA
bpx lstrcmpiA
bpx wcsncmp
bpx wcscmp

;; Configurer les BPs pour logger les arguments et continuer
;; (RCX = arg1, RDX = arg2 sur Windows x64)
SetBreakpointCondition strncmp,  "1", "strncmp : '{{s rcx}}' vs '{{s rdx}}'", 1
SetBreakpointCondition strcmp,   "1", "strcmp  : '{{s rcx}}' vs '{{s rdx}}'", 1
SetBreakpointCondition _stricmp, "1", "_stricmp: '{{s rcx}}' vs '{{s rdx}}'", 1

;; Lancer l'exécution
run

;; Le résultat s'affiche dans le panneau "Log" de x64dbg
;; Cherche les lignes contenant "strncmp :" ou "strcmp :"
;; La chaîne qui N'est PAS ton input est probablement le mot de passe.
"""

_LOG_PARSE_RE = re.compile(
    r"(?:strncmp|strcmp|_stricmp|wcsncmp).*?'(.+?)'\s*vs\s*'(.+?)'",
    re.IGNORECASE,
)


def generate_script(binary_path: str, output_dir: Optional[str] = None) -> str:
    """
    Générer un script x64dbg (.x64dbg) pour poser des BPs sur les
    fonctions de comparaison et logger les arguments.

    Retourne le chemin du script généré.
    """
    out = Path(output_dir or tempfile.gettempdir())
    out.mkdir(parents=True, exist_ok=True)
    script_path = out / "aira_breakpoints.x64dbg"
    script_path.write_text(
        _SCRIPT_TEMPLATE.format(binary=str(binary_path).replace("\\", "\\\\")),
        encoding="utf-8",
    )
    return str(script_path)


def launch_with_script(binary_path: str, x64dbg_exe: Optional[str] = None) -> str:
    """
    Lancer x64dbg avec le binaire et le script AIRA.
    Retourne un message d'état.
    """
    exe = x64dbg_exe or _find_x64dbg()
    if not exe:
        return (
            "x64dbg introuvable. Configure X64DBG_PATH dans .env "
            "ou installe x64dbg dans C:\\x64dbg\\"
        )

    script = generate_script(binary_path)

    try:
        subprocess.Popen(
            [exe, binary_path, "-c", script],
            creationflags=subprocess.CREATE_NEW_CONSOLE,
        )
        return (
            f"x64dbg lancé avec {Path(binary_path).name}.\n"
            f"Script chargé : {script}\n"
            "Dans x64dbg, regarde l'onglet 'Log' pour voir les comparaisons.\n"
            "La chaîne qui n'est pas ton input est le mot de passe."
        )
    except Exception as exc:
        return f"Erreur lors du lancement de x64dbg : {exc}"


# ── Mode 1 : winappdbg (Python 3 natif) ──────────────────────────────────────

def _is_winappdbg_available() -> bool:
    try:
        import winappdbg  # noqa: F401
        return True
    except ImportError:
        return False


def _winappdbg_intercept(binary_path: str, probe_input: str = "AAAA1234\n") -> list[dict]:
    """
    Lance le binaire avec winappdbg, pose des BPs sur strcmp/strncmp,
    retourne la liste des paires (s1, s2) comparées.
    """
    import ctypes
    try:
        import winappdbg
        from winappdbg import Debug, Process, System, win32
    except ImportError:
        return []

    comparisons: list[dict] = []
    CMP_FUNCS = ["strncmp", "strcmp", "_stricmp", "wcsncmp", "wcscmp",
                 "lstrcmpA", "lstrcmpiA", "CompareStringA"]

    class CmpEventHandler(winappdbg.EventHandler):
        def load_dll(self, event):
            mod = event.get_module()
            pid = event.get_pid()
            proc = event.get_process()
            for fn in CMP_FUNCS:
                try:
                    addr = mod.resolve(fn)
                    if addr:
                        proc.break_at(addr, self._on_cmp)
                except Exception:
                    pass

        def _on_cmp(self, event):
            try:
                proc = event.get_process()
                thread = event.get_thread()
                ctx = thread.get_context()
                # Windows x64: RCX=arg1, RDX=arg2
                rcx = ctx.get("Rcx", 0)
                rdx = ctx.get("Rdx", 0)
                s1 = proc.peek_string(rcx, fUnicode=False)[:64] if rcx else ""
                s2 = proc.peek_string(rdx, fUnicode=False)[:64] if rdx else ""
                if s1 or s2:
                    comparisons.append({"s1": s1, "s2": s2})
                if len(comparisons) >= 30:
                    event.debug.stop()
            except Exception:
                pass

    try:
        handler = CmpEventHandler()
        debug = winappdbg.Debug(handler, bKillOnExit=True)
        proc = debug.execv([binary_path], bFollow=True)
        # Injecter l'input après 1 seconde
        import threading
        def send_input():
            time.sleep(1.5)
            try:
                import win32api, win32con
                hwnd = win32api.FindWindow(None, None)
            except Exception:
                pass
        threading.Thread(target=send_input, daemon=True).start()
        debug.loop()
    except Exception:
        pass

    return comparisons


# ── Interface principale ──────────────────────────────────────────────────────

def is_x64dbg_api_available() -> bool:
    try:
        return X64DbgApiClient().is_available()
    except Exception:
        return False


def x64dbg_find_password(binary_path: str) -> str:
    """
    Tente de trouver le mot de passe — 3 modes en cascade :
    1. winappdbg (Python 3 natif, automatique)
    2. x64dbg HTTP API (si plugin installé)
    3. Script x64dbg généré (semi-manuel)
    """
    # ── Mode 1 : winappdbg ───────────────────────────────────────────────
    if _is_winappdbg_available():
        comparisons = _winappdbg_intercept(binary_path)
        if comparisons:
            lines = ["[Level 5 — winappdbg] Comparaisons strcmp interceptées :"]
            found = []
            for c in comparisons[:20]:
                s1, s2 = c.get("s1", ""), c.get("s2", "")
                lines.append(f"  strcmp('{s1}', '{s2}')")
                if "AAAA" in s1 and s2 and len(s2) < 32:
                    found.append(s2)
                elif "AAAA" in s2 and s1 and len(s1) < 32:
                    found.append(s1)
            if found:
                lines.append(f"\n→ MOT DE PASSE TROUVÉ : '{found[0]}'")
            return "\n".join(lines)
        return "[Level 5 — winappdbg] Disponible mais aucune comparaison interceptée."

    # ── Mode 2 : x64dbg HTTP API ─────────────────────────────────────────
    client = X64DbgApiClient()
    if client.is_available():
        comparisons = client.intercept_comparisons(binary_path)
        if comparisons:
            lines = ["[Level 5 — x64dbg API] Comparaisons interceptées :"]
            for c in comparisons[:15]:
                s1, s2 = c.get("s1", ""), c.get("s2", "")
                lines.append(f"  strcmp('{s1}', '{s2}')")
                if "AAAA" in s1 and s2:
                    lines.append(f"  → Mot de passe probable : '{s2}'")
                elif "AAAA" in s2 and s1:
                    lines.append(f"  → Mot de passe probable : '{s1}'")
            return "\n".join(lines)

    # ── Mode 3 : Script x64dbg (semi-manuel) ────────────────────────────
    exe = _find_x64dbg()
    script = generate_script(binary_path)
    x64dbg_path = exe or "x64dbg.exe"

    if exe:
        try:
            subprocess.Popen(
                [exe, binary_path],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
            launched = f"x64dbg lancé avec {Path(binary_path).name}."
        except Exception as e:
            launched = f"Lance x64dbg manuellement ({e})."
    else:
        launched = "x64dbg non trouvé — lance-le manuellement."

    return (
        f"[Level 5 — x64dbg Script]\n"
        f"{launched}\n\n"
        f"Script généré : {script}\n\n"
        f"Dans x64dbg :\n"
        f"  1. Script → Run Script → {script}\n"
        f"  2. Lance le binaire (F9)\n"
        f"  3. Entre n'importe quel input (ex: test123)\n"
        f"  4. Onglet 'Log' → cherche les lignes strncmp\n"
        f"     La chaîne ≠ ton input = le mot de passe"
    )
