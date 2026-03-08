from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterable

from rich.console import Console


console = Console()


def save_text(path: Path | str, text: str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def save_json(path: Path | str, data: dict) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def warn(msg: str) -> None:
    console.print(f"[yellow]⚠ {msg}")


def die(msg: str, code: int = 1) -> None:
    console.print(f"[red]✖ {msg}")
    sys.exit(code)


def as_hex(x: int) -> str:
    return f"0x{x:016X}"


def chunked(it: Iterable, n: int):
    buf = []
    for v in it:
        buf.append(v)
        if len(buf) >= n:
            yield buf
            buf = []
    if buf:
        yield buf

