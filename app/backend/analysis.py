from __future__ import annotations

from pathlib import Path
from typing import Optional

from aira import static_analysis
from aira.static_detection import scan_with_yara

# Racine du projet : app/backend -> app -> root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def static_info(path: str) -> dict:
    info = static_analysis.get_basic_info(path)
    return {
        "format": info.format,
        "architecture": info.architecture,
        "imagebase": info.imagebase,
        "imagebase_hex": info.imagebase_hex,
        "entrypoint": info.entrypoint,
        "entrypoint_hex": info.entrypoint_hex,
        "entrypoint_rva": info.entrypoint_rva,
        "entrypoint_rva_hex": info.entrypoint_rva_hex,
        "entrypoint_file_offset": info.entrypoint_file_offset,
        "sections": info.sections,
        "imports": info.imports,
    }


def yara_antidebug(path: str, rules_path: Optional[str] = None) -> list[dict] | None:
    if rules_path:
        rules = Path(rules_path)
    else:
        rules = _PROJECT_ROOT / "signatures" / "anti_debug.yar"
    if not rules.exists():
        return None
    return scan_with_yara(path, str(rules))

