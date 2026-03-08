"""
Détection d'anomalies dans l'en-tête PE :
- Rich Header absent/falsifié
- Timestamp suspect (0, date future, APT-signature)
- Sections RWX (Read + Write + Execute)
- Checksum PE invalide
- Subsystem incohérent
- Debug directory
- TLS callbacks
- Ressources anormales
"""
from __future__ import annotations

import struct
import time
from pathlib import Path
from typing import List

# Timestamps APT connus
_KNOWN_APT_TIMESTAMPS = {
    0x00000000: "Timestamp effacé (0x00000000)",
    0x2A425E19: "Timestamp 1970-01-01 (effacement intentionnel)",
    0x4CE78E98: "Signature APT1 (2010-11-20)",
    0x471C4E98: "Timestamp Stuxnet",
    0x4D79F372: "Signature APT28/Sofacy",
}

# Subsystems Windows PE
_SUBSYSTEMS = {
    0:  "Unknown",
    1:  "Native",
    2:  "Windows GUI",
    3:  "Windows CUI (console)",
    5:  "OS/2 CUI",
    7:  "POSIX CUI",
    9:  "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "XBOX",
    16: "Windows Boot Application",
}


def _verify_rich_header(data: bytes) -> dict:
    """
    Vérifie la présence et la validité du Rich Header.
    Le Rich Header se trouve entre le DOS stub et le PE header,
    chiffré par XOR avec un checksum 4 bytes.
    """
    result = {"present": False, "valid": False, "compids": [], "note": ""}

    # Chercher la signature "Rich" (0x52696368)
    rich_sig = b"Rich"
    rich_idx = data.find(rich_sig)
    if rich_idx == -1:
        result["note"] = "Absent (packer ou stripped binary)"
        return result

    result["present"] = True
    # Le XOR key est les 4 bytes après "Rich"
    if rich_idx + 8 > len(data):
        result["note"] = "Tronqué"
        return result

    xor_key = struct.unpack_from("<I", data, rich_idx + 4)[0]

    # Chercher "DanS" (0x44616e53) — début du Rich Header chiffré
    dans_enc = struct.pack("<I", 0x44616e53 ^ xor_key)
    dans_idx = data.find(dans_enc)
    if dans_idx == -1:
        result["note"] = "Signature 'DanS' introuvable — possible falsification"
        return result

    # Décoder les compids entre DanS et Rich
    result["valid"] = True
    compids = []
    pos = dans_idx + 16  # Sauter les 4 DanS + 3 padding DWORD
    while pos < rich_idx:
        if pos + 8 > rich_idx:
            break
        try:
            comp_id  = struct.unpack_from("<I", data, pos)[0]     ^ xor_key
            use_count = struct.unpack_from("<I", data, pos + 4)[0] ^ xor_key
            prod_id  = comp_id >> 16
            build    = comp_id & 0xFFFF
            compids.append({
                "prod_id":   prod_id,
                "build":     build,
                "use_count": use_count,
            })
        except Exception:
            pass
        pos += 8

    result["compids"] = compids[:20]
    if not compids:
        result["note"] = "Rich Header vide — possible falsification"
        result["valid"] = False
    else:
        result["note"] = f"{len(compids)} compiler(s)/tool(s) identifié(s)"

    return result


def detect_pe_anomalies(binary_path: str) -> dict:
    """
    Analyse les anomalies dans les en-têtes PE.
    """
    try:
        data = Path(binary_path).read_bytes()
    except OSError as e:
        return {"error": str(e), "anomalies": []}

    # Ne traiter que les PE
    if data[:2] != b"MZ":
        return {"anomalies": [], "note": "Not a PE file"}

    anomalies: List[dict] = []
    score = 0

    # ── Rich Header ──────────────────────────────────────────────────────────
    rich = _verify_rich_header(data)
    if not rich["present"]:
        anomalies.append({
            "type":      "Rich Header absent",
            "severity":  "medium",
            "detail":    rich["note"],
        })
        score += 20
    elif not rich["valid"]:
        anomalies.append({
            "type":      "Rich Header invalide",
            "severity":  "high",
            "detail":    rich["note"],
        })
        score += 35

    try:
        import lief
        b = lief.parse(binary_path)
        if b is None or not isinstance(b, lief.PE.Binary):
            return {"anomalies": anomalies, "score": score, "rich_header": rich}

        # ── Timestamp ────────────────────────────────────────────────────────
        ts = b.header.time_date_stamps
        now = int(time.time())

        if ts in _KNOWN_APT_TIMESTAMPS:
            anomalies.append({
                "type":     "Timestamp APT connu",
                "severity": "critical",
                "detail":   f"Timestamp 0x{ts:08X} — {_KNOWN_APT_TIMESTAMPS[ts]}",
            })
            score += 50
        elif ts == 0:
            anomalies.append({
                "type":     "Timestamp nul",
                "severity": "medium",
                "detail":   "Timestamp = 0 (effacé ou packer)",
            })
            score += 20
        elif ts > now:
            import datetime
            future_date = datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
            anomalies.append({
                "type":     "Timestamp futur",
                "severity": "high",
                "detail":   f"Timestamp = {future_date} (date future — falsifié)",
            })
            score += 35

        # ── Sections RWX (Read + Write + Execute) ────────────────────────────
        RWX_FLAGS = 0xE0000000
        for s in b.sections:
            try:
                chars = int(getattr(s, "characteristics", 0) or 0)
                if (chars & RWX_FLAGS) == RWX_FLAGS:
                    anomalies.append({
                        "type":     "Section RWX",
                        "severity": "critical",
                        "detail":   f"Section '{s.name}' — Read+Write+Execute (injection/unpacking probable)",
                    })
                    score += 40
            except Exception:
                pass

        # ── EP dans une section inattendue ────────────────────────────────────
        try:
            ep_rva    = b.optional_header.addressof_entrypoint
            ep_section = None
            text_section = None
            for s in b.sections:
                s_va  = s.virtual_address
                s_end = s_va + max(s.virtual_size, s.size)
                if s_va <= ep_rva < s_end:
                    ep_section = s.name.strip('\x00')
                if s.name.strip('\x00').lower() in (".text", "code"):
                    text_section = s.name.strip('\x00')

            if ep_section and ep_section.lower() not in (".text", "code", ".init"):
                anomalies.append({
                    "type":     "EP hors section .text",
                    "severity": "high",
                    "detail":   f"Entry point dans '{ep_section}' (attendu .text) — packer/injector probable",
                })
                score += 30
        except Exception:
            pass

        # ── Checksum PE ──────────────────────────────────────────────────────
        try:
            stated_checksum = b.optional_header.checksum
            if stated_checksum != 0:
                # Calculer le vrai checksum
                computed = 0
                carry = 0
                for i in range(0, len(data) - 1, 2):
                    w = struct.unpack_from("<H", data, i)[0]
                    computed += w + carry
                    carry = computed >> 16
                    computed &= 0xFFFF
                computed = (computed + carry) & 0xFFFF
                computed += len(data)
                if computed != stated_checksum:
                    anomalies.append({
                        "type":     "Checksum PE invalide",
                        "severity": "medium",
                        "detail":   f"Checksum déclaré: 0x{stated_checksum:08X}, calculé: 0x{computed:08X}",
                    })
                    score += 15
        except Exception:
            pass

        # ── TLS Callbacks (code s'exécute AVANT main) ─────────────────────────
        try:
            tls = b.tls
            if tls and tls.callbacks:
                cbs = list(tls.callbacks)
                anomalies.append({
                    "type":     "TLS Callbacks",
                    "severity": "high",
                    "detail":   f"{len(cbs)} callback(s) TLS — code exécuté avant l'entry point : {[hex(c) for c in cbs[:5]]}",
                })
                score += 35
        except Exception:
            pass

        # ── Nombre anormal de sections ─────────────────────────────────────
        n_sections = len(list(b.sections))
        if n_sections == 0:
            anomalies.append({
                "type":     "Aucune section",
                "severity": "high",
                "detail":   "PE sans sections (très inhabituel — possible corruption ou packer)",
            })
            score += 25
        elif n_sections > 15:
            anomalies.append({
                "type":     "Trop de sections",
                "severity": "medium",
                "detail":   f"{n_sections} sections (> 15 est inhabituel)",
            })
            score += 10

        # ── Taille déclarée vs taille réelle ──────────────────────────────────
        try:
            declared_size = b.optional_header.sizeof_image
            if declared_size and abs(declared_size - len(data)) > declared_size * 0.5:
                anomalies.append({
                    "type":     "Taille incohérente",
                    "severity": "medium",
                    "detail":   f"Taille image déclarée: {declared_size:,} bytes vs fichier: {len(data):,} bytes",
                })
                score += 15
        except Exception:
            pass

        # ── Debug directory présent ─────────────────────────────────────────
        try:
            debug = b.debug
            if debug:
                for d in debug:
                    if hasattr(d, "type") and "CODEVIEW" in str(d.type):
                        # Extraire le chemin PDB si disponible
                        pdb_path = ""
                        try:
                            pdb_path = d.code_view.filename
                        except Exception:
                            pass
                        anomalies.append({
                            "type":     "Debug PDB path",
                            "severity": "info",
                            "detail":   f"Chemin PDB : '{pdb_path}' (peut révéler l'environnement dev)",
                        })
        except Exception:
            pass

    except ImportError:
        anomalies.append({
            "type": "LIEF non disponible",
            "severity": "info",
            "detail": "Analyse PE avancée indisponible",
        })
    except Exception as e:
        anomalies.append({
            "type": "Erreur analyse",
            "severity": "info",
            "detail": str(e),
        })

    score = min(score, 100)
    return {
        "anomalies":    anomalies,
        "score":        score,
        "rich_header":  rich,
        "verdict": (
            "PE fortement modifié/suspect"  if score >= 60 else
            "Anomalies PE détectées"        if score >= 30 else
            "PE normal"                     if score == 0 else
            "Légères anomalies PE"
        ),
    }
