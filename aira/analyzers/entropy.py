"""Analyse entropie Shannon par section — détecte packing/chiffrement."""
from __future__ import annotations

import math
from typing import List


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _verdict(entropy: float) -> str:
    if entropy >= 7.2:
        return "packed/encrypted"
    elif entropy >= 6.5:
        return "suspicious"
    elif entropy >= 5.5:
        return "compressed"
    else:
        return "normal"


def analyze_entropy(binary_path: str) -> dict:
    """Retourne l'entropie par section + verdict global."""
    try:
        import lief
        b = lief.parse(binary_path)
    except Exception as e:
        return {"error": str(e), "sections": [], "overall_verdict": "unknown"}

    if b is None:
        return {"error": "cannot parse", "sections": [], "overall_verdict": "unknown"}

    sections: List[dict] = []
    for s in b.sections:
        try:
            content = bytes(s.content)
        except Exception:
            content = b""
        ent = _shannon_entropy(content)
        sections.append({
            "name":    s.name or "(unnamed)",
            "entropy": ent,
            "size":    len(content),
            "verdict": _verdict(ent),
        })

    # Overall verdict
    verdicts = [s["verdict"] for s in sections if s["size"] > 0]
    if "packed/encrypted" in verdicts:
        overall = "packed/encrypted"
    elif "suspicious" in verdicts:
        overall = "suspicious"
    elif "compressed" in verdicts:
        overall = "compressed"
    else:
        overall = "normal"

    # File-level entropy
    try:
        from pathlib import Path
        file_data = Path(binary_path).read_bytes()
        file_entropy = _shannon_entropy(file_data)
    except Exception:
        file_entropy = 0.0

    return {
        "sections":        sections,
        "overall_verdict": overall,
        "file_entropy":    file_entropy,
    }
