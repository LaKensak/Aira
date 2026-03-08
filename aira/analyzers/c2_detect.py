"""
Détection de Communication C2 (Command & Control).
Recherche : IPs hardcodées, User-Agents C2 connus, DNS tunneling,
beaconing (sleep + HTTP loop), signatures Cobalt Strike / Metasploit / Sliver.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

# ── User-Agents C2 connus ────────────────────────────────────────────────────
_KNOWN_C2_USERAGENTS = {
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;ENGB)":
        "Cobalt Strike (default UA)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)":
        "Cobalt Strike variante",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit":
        "Possible C2 UA (partiel)",
    "curl/7": "Possible C2 simple",
    "python-requests": "C2 Python probable",
    "Go-http-client":  "Sliver / Go C2",
    "Sliver": "Sliver C2 framework",
}

# ── Strings Cobalt Strike / Metasploit ──────────────────────────────────────
_CS_STRINGS = {
    "METSRV":         "Metasploit Meterpreter",
    "meterpreter":    "Metasploit Meterpreter",
    "beacon":         "Cobalt Strike Beacon (generic)",
    "pipe\\MSSE-":    "Cobalt Strike named pipe",
    "\\\\.\\ pipe":   "Named pipe C2",
    "badger":         "Brute Ratel C4",
    "BRC4":           "Brute Ratel C4",
    "havoc":          "Havoc C2 framework",
    "sliver":         "Sliver C2 framework",
    "BBHH":           "Cobalt Strike malleable C2 marker",
    "Palo Alto":      "PAN C2 spoof (possible)",
    "/updates":       "Cobalt Strike default endpoint",
    "/pixel.gif":     "Cobalt Strike default endpoint",
    "/jquery-3.":     "Cobalt Strike malleable C2",
    "/submit.php":    "Cobalt Strike default",
    "/s/ref=":        "Cobalt Strike Amazon profile",
}

# ── Patterns DNS tunneling ───────────────────────────────────────────────────
_DNS_TUNNEL_INDICATORS = [
    "DnsQueryA", "DnsQueryW", "DnsQuery_A", "DnsQuery_W",
    "dns_query", "getaddrinfo",
]

# ── IPs privées à exclure des résultats ──────────────────────────────────────
_PRIVATE_IP_RANGES = [
    re.compile(r'^10\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^127\.'),
    re.compile(r'^0\.0\.0\.0$'),
    re.compile(r'^255\.'),
]

# ── Pattern IP publique ───────────────────────────────────────────────────────
_IP_RE = re.compile(
    r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b'
)

# ── Patterns d'URLs ───────────────────────────────────────────────────────────
_URL_RE = re.compile(
    r'(?:https?|ftp)://([^\s"\'<>\x00-\x1f]{4,})'
)

# ── Beacon sleep patterns ─────────────────────────────────────────────────────
# Sleep + réseau HTTP dans le même binaire → beaconing probable
_SLEEP_APIS = {"Sleep", "SleepEx", "WaitForSingleObject", "NtDelayExecution"}
_HTTP_APIS  = {
    "InternetOpenA", "InternetOpenW", "WinHttpOpen",
    "HttpSendRequestA", "HttpSendRequestW", "WinHttpSendRequest",
    "URLDownloadToFileA", "URLDownloadToFileW",
}


def _is_public_ip(ip: str) -> bool:
    return not any(p.match(ip) for p in _PRIVATE_IP_RANGES)


def detect_c2(binary_path: str) -> dict:
    """
    Détecte les indicateurs de communication C2 dans un binaire.
    """
    try:
        data = Path(binary_path).read_bytes()
    except OSError as e:
        return {"error": str(e), "indicators": [], "score": 0}

    text = data.decode("latin-1", errors="ignore")
    indicators: List[dict] = []
    score = 0

    # ── 1. User-Agents C2 connus ─────────────────────────────────────────────
    for ua, framework in _KNOWN_C2_USERAGENTS.items():
        if ua.lower() in text.lower():
            indicators.append({
                "type":        "User-Agent C2 connu",
                "severity":    "critical",
                "value":       ua,
                "description": f"User-Agent identifié : {framework}",
            })
            score += 60

    # ── 2. Strings C2 framework ──────────────────────────────────────────────
    for string, framework in _CS_STRINGS.items():
        if string.lower() in text.lower():
            indicators.append({
                "type":        "Signature C2",
                "severity":    "critical",
                "value":       string,
                "description": framework,
            })
            score += 45

    # ── 3. IPs publiques hardcodées ──────────────────────────────────────────
    public_ips = []
    for m in _IP_RE.finditer(text):
        ip = m.group(1)
        if _is_public_ip(ip):
            public_ips.append(ip)

    seen_ips: set[str] = set()
    unique_ips = [ip for ip in public_ips if ip not in seen_ips and not seen_ips.add(ip)]
    if unique_ips:
        indicators.append({
            "type":        "IPs publiques hardcodées",
            "severity":    "high",
            "value":       unique_ips[:10],
            "description": f"{len(unique_ips)} adresse(s) IP publique(s) — serveur(s) C2 potentiel(s)",
        })
        score += min(40, len(unique_ips) * 15)

    # ── 4. URLs suspectes ────────────────────────────────────────────────────
    found_urls: list[str] = []
    for m in _URL_RE.finditer(text):
        url = m.group(0)
        if not any(safe in url for safe in ["microsoft.com", "windows.com", "example.com"]):
            found_urls.append(url[:120])

    seen_urls: set[str] = set()
    unique_urls = [u for u in found_urls if u not in seen_urls and not seen_urls.add(u)]
    if unique_urls:
        indicators.append({
            "type":        "URLs suspectes",
            "severity":    "high",
            "value":       unique_urls[:8],
            "description": f"{len(unique_urls)} URL(s) trouvée(s) dans le binaire",
        })
        score += min(30, len(unique_urls) * 8)

    # ── 5. Beacon pattern (Sleep + HTTP) ────────────────────────────────────
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

            sleep_found = _SLEEP_APIS & symbols
            http_found  = _HTTP_APIS  & symbols

            if sleep_found and http_found:
                indicators.append({
                    "type":        "Pattern Beaconing",
                    "severity":    "high",
                    "value":       {"sleep": list(sleep_found), "http": list(http_found)},
                    "description": "Combo Sleep + réseau HTTP — comportement de beaconing probable",
                })
                score += 35

    except Exception:
        pass

    # ── 6. DNS Tunneling ─────────────────────────────────────────────────────
    dns_found = [api for api in _DNS_TUNNEL_INDICATORS if api.lower() in text.lower()]
    # + encodage Base64 dans le même binaire
    b64_labels = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
    if dns_found and len(b64_labels) > 5:
        indicators.append({
            "type":        "DNS Tunneling possible",
            "severity":    "high",
            "value":       dns_found,
            "description": f"APIs DNS ({dns_found}) + {len(b64_labels)} blobs Base64 — exfiltration via DNS probable",
        })
        score += 40

    # ── 7. Patterns Cobalt Strike ROR13 ──────────────────────────────────────
    cs_ror13 = bytes([0xC1, 0xCF, 0x0D, 0x01, 0xC7])
    cs_hash_loadlib   = bytes([0xEC, 0x0E, 0x4E, 0x8E])  # LoadLibraryA hash
    cs_hash_virtualalloc = bytes([0x91, 0x7C, 0xA5, 0x17]) # VirtualAlloc hash

    if cs_ror13 in data:
        indicators.append({
            "type":        "Cobalt Strike ROR13",
            "severity":    "critical",
            "value":       hex(data.index(cs_ror13)),
            "description": "Boucle de hashing ROR13 (Cobalt Strike / Metasploit shellcode)",
        })
        score += 55

    if cs_hash_loadlib in data or cs_hash_virtualalloc in data:
        indicators.append({
            "type":        "Cobalt Strike API hash",
            "severity":    "critical",
            "value":       "LoadLibraryA/VirtualAlloc hashes",
            "description": "Hashes d'API Cobalt Strike détectés dans le binaire",
        })
        score += 50

    # ── 8. Onion / DGA patterns ───────────────────────────────────────────────
    onion_re = re.compile(r'[a-z2-7]{16,56}\.onion', re.IGNORECASE)
    onion_hits = onion_re.findall(text)
    if onion_hits:
        indicators.append({
            "type":        "Adresse .onion (Tor)",
            "severity":    "critical",
            "value":       onion_hits[:5],
            "description": "Communication C2 via réseau Tor probable",
        })
        score += 60

    score = min(score, 100)

    return {
        "indicators":  indicators,
        "score":       score,
        "public_ips":  unique_ips[:15],
        "urls_found":  unique_urls[:10],
        "verdict": (
            "C2 confirmé / très probable"    if score >= 70 else
            "Indicateurs C2 forts"           if score >= 45 else
            "Comportement réseau suspect"    if score >= 20 else
            "Aucun indicateur C2 détecté"
        ),
    }
