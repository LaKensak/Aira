from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import requests

from aira.config import SYMEXEC_URL


@dataclass
class SolveRequest:
    binary_path: str
    addr_target: str
    addr_avoid: Optional[list[str]] = None
    stdin_len: int = 64
    input_mode: str = "stdin"  # "stdin" or "argv"
    argv_len: int = 32


def solve(req: SolveRequest) -> dict:
    url = f"{SYMEXEC_URL}/solve"
    r = requests.post(url, json={
        "binary_path": req.binary_path,
        "addr_target": req.addr_target,
        "addr_avoid": req.addr_avoid or [],
        "stdin_len": req.stdin_len,
        "input_mode": req.input_mode,
        "argv_len": req.argv_len,
    }, timeout=600)
    if not r.ok:
        # Surface detailed server error to the CLI caller
        try:
            data = r.json()
            detail = data.get("detail") if isinstance(data, dict) else data
        except Exception:
            detail = r.text
        raise RuntimeError(f"{r.status_code} {r.reason}: {detail}")
    return r.json()
