from __future__ import annotations

import shlex
import subprocess
import sys
from typing import Optional

from aira.config import (
    GHIDRA_MCP_BRIDGE,
    GHIDRA_MCP_HOST,
    GHIDRA_MCP_PORT,
    GHIDRA_MCP_TRANSPORT,
    GHIDRA_SERVER_URL,
)
from aira.utils import console, warn


def run_bridge(
    *,
    transport: Optional[str] = None,
    ghidra_server: Optional[str] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    wait: bool = True,
) -> int | subprocess.Popen[bytes]:
    script = GHIDRA_MCP_BRIDGE
    if not script.exists():
        warn(f"Ghidra MCP bridge script not found: {script}")
        return 1

    transport = transport or GHIDRA_MCP_TRANSPORT
    ghidra_server = ghidra_server or GHIDRA_SERVER_URL
    host = host or GHIDRA_MCP_HOST
    port = port or GHIDRA_MCP_PORT

    cmd: list[str] = [sys.executable, str(script)]
    if ghidra_server:
        cmd += ["--ghidra-server", ghidra_server]
    if transport:
        cmd += ["--transport", transport]
    if transport == "sse":
        if host:
            cmd += ["--mcp-host", host]
        if port:
            cmd += ["--mcp-port", str(port)]

    console.print("Launching Ghidra MCP bridge:")
    console.print(" ".join(shlex.quote(str(part)) for part in cmd))
    if wait:
        try:
            proc_run = subprocess.run(cmd, check=False)
        except KeyboardInterrupt:
            console.print("Bridge interrupted by user.")
            return 0
        return int(proc_run.returncode)

    try:
        proc_spawn = subprocess.Popen(cmd)
    except OSError as exc:
        warn(f"Failed to start Ghidra MCP bridge: {exc}")
        return 1
    console.print(f"Ghidra MCP bridge running (PID={proc_spawn.pid})")
    return proc_spawn
