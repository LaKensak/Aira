from __future__ import annotations

import inspect
import os
from dataclasses import asdict
from typing import List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

try:
    from .solver import solve_path, build_cfg_dot
except ImportError:
    from services.symexec_service.solver import solve_path, build_cfg_dot


app = FastAPI(title="AIRA Symbolic Execution Service")


class SolveIn(BaseModel):
    binary_path: str
    addr_target: str
    addr_avoid: List[str] = []
    stdin_len: int = 64
    input_mode: str = "stdin"  # "stdin" or "argv"
    argv_len: int = 32


class CfgIn(BaseModel):
    binary_path: str
    address: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/solve")
def solve(inp: SolveIn):
    try:
        sig = inspect.signature(solve_path)
        args = [
            inp.binary_path,
            inp.addr_target,
            inp.addr_avoid,
            inp.stdin_len,
        ]
        kwargs = {}
        if "input_mode" in sig.parameters:
            kwargs["input_mode"] = inp.input_mode
        if "argv_len" in sig.parameters:
            kwargs["argv_len"] = inp.argv_len
        res = solve_path(*args, **kwargs)
        out = asdict(res)
        if res.stdin is not None:
            out["stdin_hex"] = res.stdin.hex()
            out["stdin_str"] = res.stdin.decode("utf-8", errors="replace")
        return out
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/cfg")
def cfg(inp: CfgIn):
    try:
        dot = build_cfg_dot(inp.binary_path, inp.address)
        return {"dot": dot}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port)
