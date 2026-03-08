"""Classification des chaînes extraites par catégories (URLs, IPs, registre, base64…)."""
from __future__ import annotations

import re
from typing import Dict, List

# ── Patterns de détection ───────────────────────────────────────────────────
_PATTERNS: Dict[str, re.Pattern] = {
    "urls": re.compile(
        r'(?:https?|ftp|ftps)://[^\s"\'<>\x00-\x1f]{6,}'
    ),
    "ips": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d{1,5})?\b'
    ),
    "registry_keys": re.compile(
        r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU|HKU|HKCR)'
        r'[\\\w\s\.\-]{3,}',
        re.IGNORECASE
    ),
    "file_paths": re.compile(
        r'(?:[A-Za-z]:\\(?:[\w\s\.\-]+\\)*[\w\s\.\-]*|/(?:etc|tmp|var|usr|home|proc|dev)/[\w/\.\-]*)',
        re.IGNORECASE
    ),
    "unc_paths": re.compile(r'\\\\[\w\.\-]{2,}\\[\w\s\.\-\\]+'),
    "emails": re.compile(r'[a-zA-Z0-9_.+\-]{2,}@[a-zA-Z0-9\-]{2,}\.[a-zA-Z]{2,6}'),
    "base64": re.compile(
        r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'
    ),
    "hex_blobs": re.compile(r'\b(?:0x)?[0-9A-Fa-f]{16,}\b'),
    "flags_ctf": re.compile(
        r'(?:FLAG|CTF|AIRA|picoCTF|HTB|THM|flag|password|passwd|secret|token|key|p4ssw[o0]rd)'
        r'\{[^\}]+\}',
        re.IGNORECASE
    ),
    "commands": re.compile(
        r'(?:cmd(?:\.exe)?|powershell(?:\.exe)?|wscript|cscript|mshta|rundll32|regsvr32'
        r'|certutil|bitsadmin|wmic|sc\.exe|net\.exe)\b[^\n]{0,80}',
        re.IGNORECASE
    ),
    "domains": re.compile(
        r'(?:[a-zA-Z0-9\-]{2,}\.){2,}'
        r'(?:com|net|org|io|ru|cn|de|fr|uk|xyz|onion|cc|biz|gov|edu|co|me|info)\b'
    ),
    "guids": re.compile(
        r'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'
    ),
    "mutex_names": re.compile(
        r'(?:Global\\|Local\\)[\w\-\.]{4,}|'
        r'(?:Mutex|Event|Semaphore)[\w\-\.]{4,}',
        re.IGNORECASE
    ),
    "interesting_strings": re.compile(
        r'(?:password|passwd|secret|key|token|admin|root|user|login|auth|cred|flag|hash|salt|nonce'
        r'|inject|payload|shellcode|exploit|overflow|bypass|hook|debug|patch|crack|keygen)',
        re.IGNORECASE
    ),
}

# Seuil max par catégorie pour ne pas noyer le résultat
_MAX_PER_CAT = 40


def classify_strings(binary_path: str) -> Dict[str, List[str]]:
    """Extrait et classifie les chaînes d'un binaire."""
    from aira.static_analysis import extract_strings
    strings = extract_strings(binary_path, min_len=5)

    results: Dict[str, List[str]] = {k: [] for k in _PATTERNS}
    seen: Dict[str, set] = {k: set() for k in _PATTERNS}

    for s in strings:
        for cat, pattern in _PATTERNS.items():
            if len(results[cat]) >= _MAX_PER_CAT:
                continue
            for m in pattern.findall(s):
                m_clean = m.strip()
                if m_clean and m_clean not in seen[cat]:
                    seen[cat].add(m_clean)
                    results[cat].append(m_clean[:300])

    # Supprimer catégories vides
    return {k: v for k, v in results.items() if v}
