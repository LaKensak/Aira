"""
Détection d'obfuscation de chaînes :
- Boucles XOR (chiffrement simple)
- Stack strings (construction byte par byte en ASM)
- API hashing (résolution d'API sans import table)
- Strings encodées en Base64/Hex dans le binaire
"""
from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import List


# ── Patterns assembleur pour XOR loops ─────────────────────────────────────
# xor byte ptr [reg+off], key
_XOR_PATTERNS = [
    rb'\x30[\x44-\x47]\x24',          # xor [esp/ebp+disp8], reg8
    rb'\x30[\x84-\x87]\x24.{4}',      # xor [esp+disp32], reg8
    rb'\x34.',                          # xor al, imm8
    rb'\x80\x30.',                      # xor byte [eax], imm8
    rb'\x80\x31.',                      # xor byte [ecx], imm8
    rb'\x80\x33.',                      # xor byte [ebx], imm8
]

# Pattern stack string : MOV BYTE PTR [EBP-x], char
# \xC6 [\x45\x47] <disp8:any byte> <imm8:printable ASCII>
_STACK_STR_PATTERN = re.compile(
    rb'(?:\xC6[\x45\x47][\x00-\xFF][\x20-\x7E]){4,}'
)
# Alternative : PUSH imm8 de chars ASCII consécutifs
_PUSH_CHAR_PATTERN = re.compile(
    rb'(?:\x6A[\x20-\x7E]){5,}'
)

# Base64 strings (min 32 chars)
_B64_PATTERN = re.compile(
    rb'[A-Za-z0-9+/]{32,}={0,2}'
)

# Hex encoded strings
_HEX_PATTERN = re.compile(
    rb'(?:[0-9A-Fa-f]{2}){16,}'
)


def _count_pattern(data: bytes, pattern_bytes: bytes) -> int:
    count = 0
    start = 0
    while True:
        idx = data.find(pattern_bytes, start)
        if idx == -1:
            break
        count += 1
        start = idx + 1
    return count


def _try_decode_b64(raw: bytes) -> str | None:
    try:
        decoded = base64.b64decode(raw + b"==")
        text = decoded.decode("utf-8", errors="strict")
        if all(0x20 <= ord(c) <= 0x7E or c in "\n\r\t" for c in text):
            return text[:200]
    except Exception:
        pass
    return None


def _try_xor_keys(data: bytes, sample_size: int = 4096) -> list[dict]:
    """
    Tente de déchiffrer des zones de données avec des clés XOR 1-byte courantes.
    Cherche des strings lisibles après déchiffrement.
    """
    results = []
    sample = data[:sample_size]
    for key in range(1, 256):
        decrypted = bytes(b ^ key for b in sample)
        # Compter les bytes ASCII imprimables
        printable = sum(1 for b in decrypted if 0x20 <= b <= 0x7E)
        ratio = printable / len(sample) if sample else 0
        if ratio > 0.75:  # >75% printable = chiffrement XOR probable avec cette clé
            # Extraire les strings déchiffrées
            strings = re.findall(rb'[\x20-\x7E]{6,}', decrypted)
            if strings:
                results.append({
                    "key":     hex(key),
                    "ratio":   round(ratio, 2),
                    "strings": [s.decode("ascii", errors="replace")[:80] for s in strings[:5]],
                })
    return results[:8]


def detect_string_obfuscation(binary_path: str) -> dict:
    """
    Analyse l'obfuscation des chaînes dans un binaire.
    """
    try:
        data = Path(binary_path).read_bytes()
    except OSError as e:
        return {"error": str(e)}

    findings: List[dict] = []
    score = 0

    # ── 1. Comptage des instructions XOR ────────────────────────────────────
    total_xors = 0
    for pattern in _XOR_PATTERNS:
        total_xors += len(re.findall(pattern, data))

    if total_xors > 20:
        findings.append({
            "type":        "Boucle XOR",
            "severity":    "high",
            "count":       total_xors,
            "description": f"{total_xors} instructions XOR sur données — obfuscation XOR probable",
        })
        score += min(40, total_xors // 2)

    # ── 2. Stack Strings ─────────────────────────────────────────────────────
    ss_matches = _STACK_STR_PATTERN.findall(data)
    push_matches = _PUSH_CHAR_PATTERN.findall(data)
    total_ss = len(ss_matches) + len(push_matches)
    if total_ss > 3:
        findings.append({
            "type":        "Stack Strings",
            "severity":    "high",
            "count":       total_ss,
            "description": f"{total_ss} séquence(s) de construction de chaîne sur la pile — évite l'analyse statique",
        })
        score += min(35, total_ss * 5)

    # ── 3. Tentative de déchiffrement XOR ────────────────────────────────────
    # Chercher des blocs à haute densité de bytes non-ASCII (données chiffrées)
    block_size = 512
    encrypted_blocks = []
    for i in range(0, min(len(data), 50 * 1024), block_size):
        block = data[i:i + block_size]
        non_ascii = sum(1 for b in block if b > 0x7E or (b < 0x20 and b not in (0x09, 0x0A, 0x0D)))
        if len(block) > 0 and non_ascii / len(block) > 0.5:
            encrypted_blocks.append(i)

    if encrypted_blocks:
        # Essayer quelques clés XOR courantes sur le premier bloc chiffré
        xor_candidates = _try_xor_keys(data[encrypted_blocks[0]:encrypted_blocks[0] + 512])
        if xor_candidates:
            findings.append({
                "type":        "Données XOR chiffrées",
                "severity":    "medium",
                "count":       len(encrypted_blocks),
                "description": f"{len(encrypted_blocks)} bloc(s) de données potentiellement chiffrés en XOR",
                "xor_keys":   xor_candidates,
            })
            score += 25

    # ── 4. Strings Base64 dans le binaire ────────────────────────────────────
    b64_hits = _B64_PATTERN.findall(data)
    decoded_b64 = []
    for hit in b64_hits[:20]:
        dec = _try_decode_b64(hit)
        if dec and len(dec) > 10:
            decoded_b64.append({"raw": hit.decode("ascii")[:40], "decoded": dec})

    if decoded_b64:
        findings.append({
            "type":        "Chaînes Base64",
            "severity":    "medium",
            "count":       len(decoded_b64),
            "description": "Chaînes Base64 décodables trouvées",
            "samples":     decoded_b64[:5],
        })
        score += 20

    # ── 5. Présence de l'algorithme API hashing ──────────────────────────────
    # Patterns spécifiques à la résolution d'API par hash
    ror13_pattern = bytes([0xC1, 0xCF, 0x0D])        # ROR edi/ecx, 13
    djb2_mul_pattern = bytes([0x8D, 0x04, 0x40])     # LEA eax, [eax+eax*2]
    peb_pattern = bytes([0x64, 0xA1, 0x30, 0x00])    # MOV EAX, FS:[30h]
    peb64_pattern = bytes([0x65, 0x48, 0x8B, 0x04, 0x25, 0x60])

    hash_indicators = []
    if ror13_pattern in data:
        hash_indicators.append("ROR13 (Cobalt Strike, Metasploit)")
        score += 40
    if djb2_mul_pattern in data and peb_pattern in data:
        hash_indicators.append("DJB2 + PEB walk")
        score += 45
    if peb_pattern in data or peb64_pattern in data:
        hash_indicators.append("PEB walk direct (résolution API sans IAT)")
        score += 35

    if hash_indicators:
        findings.append({
            "type":        "API Hashing",
            "severity":    "critical",
            "count":       len(hash_indicators),
            "description": f"Résolution d'APIs par hashing détectée — le binaire trouve les fonctions sans import table",
            "algorithms":  hash_indicators,
        })

    score = min(score, 100)

    return {
        "findings":     findings,
        "score":        score,
        "total_xors":   total_xors,
        "stack_strings": total_ss,
        "verdict": (
            "Obfuscation sévère détectée"     if score >= 70 else
            "Obfuscation modérée détectée"    if score >= 40 else
            "Légère obfuscation possible"     if score >= 20 else
            "Aucune obfuscation détectée"
        ),
    }
