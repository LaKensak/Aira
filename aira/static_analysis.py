from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

import lief


@dataclass
class BasicInfo:
    format: str
    entrypoint: int  # VA usable directly in angr
    imagebase: int
    architecture: str
    sections: list[dict[str, Any]]
    imports: list[dict[str, Any]]
    # Extra clarity for PE users: RVA of entrypoint (PE only)
    entrypoint_rva: int | None = None
    entrypoint_file_offset: int | None = None
    # Hex views (readability)
    imagebase_hex: str | None = None
    entrypoint_hex: str | None = None
    entrypoint_rva_hex: str | None = None


def load_binary(path: str | Path) -> lief.Binary:
    parsed = lief.parse(str(path))
    if parsed is None:
        raise ValueError(f"LIEF ne peut pas parser ce fichier : {path}")
    return parsed


def _detect_format(bin: lief.Binary) -> str:
    if isinstance(bin, lief.ELF.Binary):
        return "ELF"
    if hasattr(lief, "MachO") and isinstance(bin, lief.MachO.Binary):
        return "MachO"
    return "PE"


def _get_arch(bin: lief.Binary) -> str:
    header = bin.header
    for attr in ("machine_type", "machine", "cpu_type"):
        val = getattr(header, attr, None)
        if val is not None:
            name = getattr(val, "name", None)
            if name and isinstance(name, str):
                return name
            # Fallback : "lief._lief.PE.MACHINE_TYPES.AMD64" → "AMD64"
            return str(val).split(".")[-1]
    return "unknown"


def get_basic_info(path: str | Path) -> BasicInfo:
    bin = load_binary(path)
    fmt = _detect_format(bin)
    arch = _get_arch(bin)

    # ── 1. Imagebase (doit être calculé en premier, utilisé partout ensuite) ──
    if fmt == "PE":
        try:
            imagebase = int(getattr(getattr(bin, "optional_header", bin), "imagebase", 0))
        except Exception:
            imagebase = int(getattr(bin, "imagebase", 0) or 0)
    else:
        imagebase = int(getattr(bin, "imagebase", 0) or 0)

    # ── 2. Sections ──
    sections = []
    for s in bin.sections:
        if hasattr(s, "characteristics"):
            try:
                flags_val = int(s.characteristics)
            except Exception:
                flags_val = int(getattr(s, "characteristics", 0) or 0)
        elif hasattr(s, "flags"):
            try:
                flags_val = int(s.flags)
            except Exception:
                flags_val = int(getattr(s, "flags", 0) or 0)
        else:
            flags_val = 0
        va = int(getattr(s, "virtual_address", 0) or 0)
        file_off = int(getattr(s, "offset", getattr(s, "pointerto_raw_data", 0)) or 0)
        sec: dict[str, Any] = {
            "name": s.name,
            "virtual_address": va,
            "virtual_address_hex": f"0x{va:x}" if va else None,
            "virtual_size": int(getattr(s, "virtual_size", 0) or 0),
            "size": int(getattr(s, "size", 0) or 0),
            "file_offset": file_off,
            "flags": flags_val,
        }
        if imagebase:
            sec["rva"] = max(0, va - imagebase)
        sections.append(sec)

    # ── 3. Imports (logique séparée PE vs ELF/MachO) ──
    imports = []
    try:
        if fmt == "PE":
            # PE : bin.imports → list[lief.PE.Import], chaque import a .name et .entries
            for lib in bin.imports:
                for sym in lib.entries:
                    addr = int(getattr(sym, "iat_address", 0) or 0)
                    imp: dict[str, Any] = {
                        "library": lib.name,
                        "symbol": sym.name,
                        "address": addr,
                    }
                    if imagebase and addr:
                        imp["rva"] = max(0, addr - imagebase)
                    imports.append(imp)
        else:
            # ELF/MachO : imported_symbols retourne des Symbol directement (pas de lib.entries)
            for sym in getattr(bin, "imported_symbols", []):
                name = (getattr(sym, "name", "") or "").strip()
                if not name:
                    continue
                lib_obj = getattr(sym, "library", None)
                lib_name = ""
                if lib_obj is not None:
                    lib_name = getattr(lib_obj, "name", "") or ""
                addr = int(getattr(sym, "value", 0) or 0)
                imports.append({
                    "library": lib_name,
                    "symbol": name,
                    "address": addr,
                })
    except Exception:
        pass

    # ── 4. Entrypoint ──
    if fmt == "PE":
        try:
            ep_rva = int(getattr(getattr(bin, "optional_header", bin), "addressof_entrypoint", 0))
        except Exception:
            ep_rva = int(getattr(bin, "entrypoint", 0) or 0)
        ep_va = int(getattr(bin, "entrypoint", 0) or 0)
        if imagebase and ep_rva and (ep_va < imagebase or ep_va == 0):
            ep_va = imagebase + ep_rva
        entrypoint_va = ep_va
        entrypoint_rva = ep_rva if ep_rva else None
        entrypoint_file_offset: int | None = None
        try:
            if ep_rva:
                for s in bin.sections:
                    va_s = int(getattr(s, "virtual_address", 0) or 0)
                    vsz = int(getattr(s, "virtual_size", 0) or 0)
                    raw = int(getattr(s, "offset", getattr(s, "pointerto_raw_data", 0)) or 0)
                    end = va_s + max(vsz, int(getattr(s, "size", 0) or 0))
                    if va_s <= ep_rva < end:
                        entrypoint_file_offset = (ep_rva - va_s) + raw
                        break
        except Exception:
            entrypoint_file_offset = None
    else:
        # ELF/MachO : l'entrypoint est déjà une VA
        entrypoint_va = int(getattr(bin, "entrypoint", 0) or 0)
        entrypoint_rva = int(entrypoint_va - imagebase) if imagebase else None
        entrypoint_file_offset = None
        try:
            for seg in getattr(bin, "segments", []):
                vaddr = int(getattr(seg, "virtual_address", 0) or 0)
                foff = int(getattr(seg, "file_offset", 0) or 0)
                fsz = int(getattr(seg, "file_size", getattr(seg, "physical_size", 0)) or 0)
                vsz = int(getattr(seg, "virtual_size", 0) or fsz)
                span = max(fsz, vsz)
                if entrypoint_va >= vaddr and entrypoint_va < vaddr + span:
                    entrypoint_file_offset = (entrypoint_va - vaddr) + foff
                    break
        except Exception:
            entrypoint_file_offset = None

    return BasicInfo(
        format=fmt,
        entrypoint=entrypoint_va,
        imagebase=imagebase,
        architecture=arch,
        sections=sections,
        imports=imports,
        entrypoint_rva=entrypoint_rva,
        entrypoint_file_offset=entrypoint_file_offset,
        imagebase_hex=(f"0x{imagebase:x}" if imagebase else None),
        entrypoint_hex=(f"0x{entrypoint_va:x}" if entrypoint_va else None),
        entrypoint_rva_hex=(f"0x{entrypoint_rva:x}" if entrypoint_rva is not None else None),
    )


def extract_strings(path: str | Path, min_len: int = 4) -> list[str]:
    """Extract printable ASCII strings from a binary (equivalent to the `strings` tool)."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return []
    results: list[str] = []
    current: list[str] = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))
    return results


def export_basic_info(path: str | Path, out_json: Path) -> None:
    info = get_basic_info(path)
    out_json.write_text(lief.to_json(asdict(info)))
