from __future__ import annotations

from pathlib import Path
from typing import Any

import yara


def scan_with_yara(binary_path: str | Path, rules_path: str | Path) -> list[dict[str, Any]]:
    rules = yara.compile(filepath=str(rules_path))
    matches = rules.match(str(binary_path))
    out: list[dict[str, Any]] = []
    for m in matches:
        out.append({
            "rule": m.rule,
            "meta": dict(m.meta or {}),
            "tags": list(m.tags or []),
        })
    return out

