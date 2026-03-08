"""
Détection de shellcode générique dans un binaire.
Recherche : GetPC (CALL/POP, FPU), PEB walk, egg hunters,
API hashing (ROR13/DJB2), blobs haute-entropie exécutables.
"""
from __future__ import annotations

import math
from typing import List


# ── Patterns bytes ──────────────────────────────────────────────────────────

# GetPC CALL/POP : E8 00 00 00 00 suivi de POP reg (58-5F)
_GETPC_CALL_POP = [
    bytes([0xE8, 0x00, 0x00, 0x00, 0x00, reg])
    for reg in range(0x58, 0x60)   # POP EAX → POP EDI
]

# GetPC via FPU FNSTENV [ESP-12]
_GETPC_FPU = bytes([0xD9, 0x74, 0x24, 0xF4])   # FNSTENV [ESP-0Ch]

# PEB walk x86 : MOV EAX, FS:[30h]
_PEB_X86 = bytes([0x64, 0xA1, 0x30, 0x00, 0x00, 0x00])
# PEB walk x64 : MOV RAX, GS:[60h]
_PEB_X64 = bytes([0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00])

# API hashing ROR13 loop
_ROR13 = bytes([0xC1, 0xCF, 0x0D, 0x01, 0xC7])           # ROR edi, 13 ; ADD edi, ecx
_ROR13_ALT = bytes([0xD1, 0xCF, 0x01, 0xC7])              # ROR edi,1   ; ADD edi, ecx

# Egg hunter classique (NtAccessCheckAndAuditAlarm method)
_EGG_HUNTER = bytes([
    0x66, 0x81, 0xCA, 0xFF, 0x0F,   # OR DX, 0FFFh
    0x42,                             # INC EDX
    0x52,                             # PUSH EDX
    0x6A, 0x02,                       # PUSH 2
    0x58,                             # POP EAX
    0xCD, 0x2E,                       # INT 2Eh
    0x3C, 0x05,                       # CMP AL, 5
    0x5A,                             # POP EDX
    0x74,                             # JE (short)
])

# PUSH/RET shellcode dispatch (common trampoline)
_PUSH_RET = bytes([0xFF, 0xE4])   # JMP ESP
_CALL_ESP  = bytes([0xFF, 0xD4])   # CALL ESP

# NOP sled detector
_NOP = 0x90


def _count_nop_sled(data: bytes, min_len: int = 12) -> list[dict]:
    """Trouve les NOP sleds de longueur >= min_len."""
    sleds = []
    i = 0
    while i < len(data):
        if data[i] == _NOP:
            j = i
            while j < len(data) and data[j] == _NOP:
                j += 1
            length = j - i
            if length >= min_len:
                sleds.append({"offset": hex(i), "length": length})
            i = j
        else:
            i += 1
    return sleds[:10]


def _entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    freq = {}
    for b in chunk:
        freq[b] = freq.get(b, 0) + 1
    n = len(chunk)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _find_pattern(data: bytes, pattern: bytes, max_hits: int = 10) -> list[str]:
    hits = []
    start = 0
    while len(hits) < max_hits:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        hits.append(hex(idx))
        start = idx + 1
    return hits


def detect_shellcode(binary_path: str) -> dict:
    """
    Recherche des patterns de shellcode dans le binaire.
    Ne nécessite pas d'imports externes.
    """
    findings: List[dict] = []
    score = 0

    try:
        from pathlib import Path
        data = Path(binary_path).read_bytes()
    except OSError as e:
        return {"error": str(e), "findings": [], "score": 0}

    # ── 1. GetPC CALL/POP ────────────────────────────────────────────────────
    getpc_hits = []
    for pattern in _GETPC_CALL_POP:
        hits = _find_pattern(data, pattern, max_hits=5)
        getpc_hits.extend(hits)
    if getpc_hits:
        findings.append({
            "type":       "GetPC (CALL/POP)",
            "severity":   "high",
            "offsets":    getpc_hits[:5],
            "description": "Shellcode self-location technique — CALL $+5 / POP reg",
        })
        score += 30

    # ── 2. GetPC via FPU ─────────────────────────────────────────────────────
    fpu_hits = _find_pattern(data, _GETPC_FPU, max_hits=5)
    if fpu_hits:
        findings.append({
            "type":       "GetPC (FPU FNSTENV)",
            "severity":   "high",
            "offsets":    fpu_hits,
            "description": "FNSTENV trick pour obtenir l'EIP courant",
        })
        score += 25

    # ── 3. PEB Walk ──────────────────────────────────────────────────────────
    peb86 = _find_pattern(data, _PEB_X86, max_hits=5)
    peb64 = _find_pattern(data, _PEB_X64, max_hits=5)
    if peb86 or peb64:
        findings.append({
            "type":       "PEB Walk",
            "severity":   "critical",
            "offsets":    (peb86 + peb64)[:5],
            "description": "Accès direct au PEB (FS:[30h] / GS:[60h]) pour résoudre les APIs sans import table",
        })
        score += 40

    # ── 4. API Hashing (ROR13) ───────────────────────────────────────────────
    ror13_hits  = _find_pattern(data, _ROR13,     max_hits=5)
    ror13a_hits = _find_pattern(data, _ROR13_ALT, max_hits=5)
    if ror13_hits or ror13a_hits:
        findings.append({
            "type":       "API Hashing ROR13",
            "severity":   "critical",
            "offsets":    (ror13_hits + ror13a_hits)[:5],
            "description": "Algorithme de hashing ROR13 (Cobalt Strike, Metasploit, etc.)",
        })
        score += 45

    # ── 5. Egg Hunter ────────────────────────────────────────────────────────
    egg_hits = _find_pattern(data, _EGG_HUNTER, max_hits=3)
    if egg_hits:
        findings.append({
            "type":       "Egg Hunter",
            "severity":   "critical",
            "offsets":    egg_hits,
            "description": "Egg hunter (NtAccessCheckAndAuditAlarm method) — multi-stage shellcode",
        })
        score += 50

    # ── 6. NOP Sleds ─────────────────────────────────────────────────────────
    sleds = _count_nop_sled(data, min_len=16)
    if sleds:
        findings.append({
            "type":       "NOP Sled",
            "severity":   "medium",
            "offsets":    [s["offset"] for s in sleds[:5]],
            "description": f"{len(sleds)} NOP sled(s) détecté(s) — préparation pour shellcode/exploit",
        })
        score += 20

    # ── 7. JMP ESP / CALL ESP (trampolines) ──────────────────────────────────
    jmpesp  = _find_pattern(data, _PUSH_RET, max_hits=3)
    callesp = _find_pattern(data, _CALL_ESP, max_hits=3)
    if len(jmpesp) + len(callesp) > 3:
        findings.append({
            "type":       "Stack Pivot / Trampoline",
            "severity":   "medium",
            "offsets":    (jmpesp + callesp)[:5],
            "description": "JMP ESP / CALL ESP — gadgets typiques d'exploitation de stack overflow",
        })
        score += 15

    # ── 8. Blobs haute entropie dans sections exécutables ────────────────────
    try:
        import lief
        b = lief.parse(binary_path)
        if b is not None:
            for s in b.sections:
                try:
                    # Section exécutable et haute entropie
                    chars = int(getattr(s, "characteristics", 0) or 0)
                    is_exec = bool(chars & 0x20000000)
                    content = bytes(s.content)
                    if not content or len(content) < 64:
                        continue
                    ent = _entropy(content)
                    if is_exec and ent > 7.0:
                        findings.append({
                            "type":       "Blob exécutable haute entropie",
                            "severity":   "high",
                            "offsets":    [f"section:{s.name}"],
                            "description": f"Section '{s.name}' exécutable avec entropie {ent:.2f} — shellcode/payload probable",
                        })
                        score += 35
                except Exception:
                    pass
    except Exception:
        pass

    # Score plafonné
    score = min(score, 100)

    # Verdict
    if score >= 70:
        verdict = "Shellcode très probable"
    elif score >= 40:
        verdict = "Indicateurs de shellcode détectés"
    elif score >= 20:
        verdict = "Quelques patterns suspects"
    else:
        verdict = "Aucun shellcode détecté"

    return {
        "findings":      findings,
        "score":         score,
        "verdict":       verdict,
        "total_patterns": len(findings),
    }
