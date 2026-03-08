"""Calcul des hashs et identifiction du type de fichier."""
from __future__ import annotations

import hashlib
from pathlib import Path


_MAGIC_SIGNATURES = {
    b"MZ":                          "PE (Windows Executable)",
    b"\x7fELF":                     "ELF (Linux/Unix)",
    b"\xfe\xed\xfa\xce":            "Mach-O 32-bit (big-endian)",
    b"\xfe\xed\xfa\xcf":            "Mach-O 64-bit (big-endian)",
    b"\xce\xfa\xed\xfe":            "Mach-O 32-bit (little-endian)",
    b"\xcf\xfa\xed\xfe":            "Mach-O 64-bit (little-endian)",
    b"PK\x03\x04":                  "ZIP / JAR / APK",
    b"\x1f\x8b":                    "GZIP",
    b"BZh":                         "BZIP2",
    b"\xfd7zXZ\x00":                "XZ",
    b"7z\xbc\xaf'\x1c":             "7-Zip",
    b"Rar!":                         "RAR",
    b"\x25\x50\x44\x46":            "PDF",
    b"\x4d\x5a\x90\x00":            "PE (standard MZ header)",
}


def _imphash(binary_path: str) -> str:
    """Import hash (imphash) pour PE — utile pour clustering malware."""
    try:
        import lief
        b = lief.parse(binary_path)
        if b is None or not isinstance(b, lief.PE.Binary):
            return ""
        entries: list[str] = []
        for lib in b.imports:
            libname = lib.name.lower().rstrip(".").replace(".dll", "").replace(".sys", "").replace(".ocx", "")
            for sym in lib.entries:
                if sym.name:
                    entries.append(f"{libname}.{sym.name.lower()}")
        if not entries:
            return ""
        return hashlib.md5(",".join(entries).encode()).hexdigest()
    except Exception:
        return ""


def compute_hashes(binary_path: str) -> dict:
    """MD5, SHA1, SHA256, imphash, type fichier, taille."""
    try:
        data = Path(binary_path).read_bytes()
    except OSError as e:
        return {"error": str(e)}

    # Magic bytes detection
    file_type = "Unknown"
    for magic, label in _MAGIC_SIGNATURES.items():
        if data[:len(magic)] == magic:
            file_type = label
            break

    return {
        "md5":       hashlib.md5(data).hexdigest(),
        "sha1":      hashlib.sha1(data).hexdigest(),
        "sha256":    hashlib.sha256(data).hexdigest(),
        "size":      len(data),
        "size_kb":   round(len(data) / 1024, 2),
        "file_type": file_type,
        "imphash":   _imphash(binary_path),
        "magic_hex": data[:4].hex(),
    }
