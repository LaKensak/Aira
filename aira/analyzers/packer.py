"""Détection de packers/protecteurs (UPX, MPRESS, Themida, etc.)."""
from __future__ import annotations

from typing import List

# Noms de sections connus par packer
_PACKER_SECTIONS: dict[str, set[str]] = {
    "UPX":         {"UPX0", "UPX1", "UPX2", "UPX3"},
    "ASPack":      {".aspack", ".adata"},
    "PECompact":   {".pec1", ".pec2", ".pec"},
    "MPRESS":      {".MPRESS1", ".MPRESS2"},
    "Themida":     {".winapi", ".winapi1", ".themida"},
    "NSPack":      {".nsp0", ".nsp1", ".nsp2"},
    "FSG":         {".FSG!"},
    "PESpin":      {".pespin"},
    "Petite":      {".petite"},
    "tElock":      {".tElock"},
    "RLPack":      {".rlpack"},
    "WinUpack":    {".unpack"},
    "Obsidium":    {".obsidium"},
    "ExeStealth":  {".exestealth"},
    "MEW":         {".MEW"},
}

# Caractéristiques spéciales de section
_SUSPICIOUS_SECTION_NAMES = {
    "CODE", "DATA", ".rsrc", ".reloc", ".ndata",
    ".itext", ".data1", ".text1", ".text0",
}


def detect_packer(binary_path: str) -> dict:
    """Détecte si le binaire est packé ou protégé."""
    try:
        import lief
        b = lief.parse(binary_path)
    except Exception as e:
        return {"error": str(e), "detected": None, "confidence": 0, "indicators": []}

    if b is None:
        return {"detected": None, "confidence": 0, "indicators": []}

    indicators: List[str] = []
    detected: str | None = None
    confidence = 0

    try:
        section_names = {s.name.strip('\x00').strip() for s in b.sections}
    except Exception:
        section_names = set()

    # 1. Noms de sections connus
    for packer, names in _PACKER_SECTIONS.items():
        hit = names & section_names
        if hit:
            detected = packer
            confidence = 95
            indicators.append(f"Section '{', '.join(hit)}' identifiée ({packer})")
            break

    # 2. Analyse PE spécifique
    try:
        import lief
        if isinstance(b, lief.PE.Binary):
            imports = list(b.imports)
            total_entries = sum(len(list(lib.entries)) for lib in imports)

            # Très peu d'imports = probablement packé
            if total_entries <= 3:
                indicators.append(
                    f"Seulement {total_entries} import(s) — typique d'un binaire packé"
                )
                if not detected:
                    detected = "Unknown packer"
                    confidence = max(confidence, 70)

            # EP dans dernière section
            try:
                ep_rva = b.optional_header.addressof_entrypoint
                sects = list(b.sections)
                if sects:
                    last = sects[-1]
                    last_va  = last.virtual_address
                    last_end = last_va + max(last.virtual_size, last.size)
                    if last_va <= ep_rva < last_end:
                        indicators.append("Entry point dans la dernière section (technique packer)")
                        confidence = max(confidence, 55)
            except Exception:
                pass

            # Overlay (données après la dernière section)
            try:
                overlay = bytes(b.overlay)
                if len(overlay) > 512:
                    indicators.append(
                        f"Overlay détecté : {len(overlay):,} octets après la dernière section"
                    )
                    confidence = max(confidence, 40)
            except Exception:
                pass

            # Ratio sections exécutables vs total
            try:
                exec_count = 0
                for s in b.sections:
                    chars = int(getattr(s, "characteristics", 0) or 0)
                    if chars & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                        exec_count += 1
                total_secs = len(list(b.sections))
                if total_secs > 0 and exec_count / total_secs > 0.6:
                    indicators.append(
                        f"{exec_count}/{total_secs} sections sont exécutables (anormal)"
                    )
                    confidence = max(confidence, 45)
            except Exception:
                pass

            # Noms de sections invalides / vides
            bad_names = [
                s.name.strip('\x00') for s in b.sections
                if not s.name.strip('\x00').startswith('.')
                and s.name.strip('\x00') not in _SUSPICIOUS_SECTION_NAMES
                and s.name.strip('\x00')
            ]
            if len(bad_names) > 2:
                indicators.append(
                    f"Noms de sections inhabituels : {bad_names[:5]}"
                )
                confidence = max(confidence, 35)

    except Exception:
        pass

    if not detected and confidence > 0:
        detected = "Unknown packer/protector"

    return {
        "detected":   detected,
        "confidence": confidence,
        "indicators": indicators,
        "verdict":    "packed" if confidence >= 60 else ("suspicious" if confidence > 0 else "clean"),
    }
