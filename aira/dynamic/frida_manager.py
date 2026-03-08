from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import frida


@dataclass
class AttachResult:
    pid: int
    script_message_log: list[str]


def _on_message(log: list[str]):
    def handler(message, data):
        if message["type"] == "send":
            log.append(str(message.get("payload")))
        elif message["type"] == "error":
            log.append("ERROR: " + json.dumps(message))
    return handler


def attach_and_inject(pid: int, script_js_path: str | Path, runtime: str = "v8") -> AttachResult:
    session = frida.attach(pid)
    code = Path(script_js_path).read_text(encoding="utf-8")
    logs: list[str] = []
    script = session.create_script(code, runtime=runtime)
    script.on("message", _on_message(logs))
    script.load()
    return AttachResult(pid=pid, script_message_log=logs)


def spawn_and_inject(exe_path: str | Path, script_js_path: str | Path, argv: Optional[list[str]] = None) -> int:
    device = frida.get_local_device()
    pid = device.spawn([str(exe_path)] + (argv or []))
    session = device.attach(pid)
    code = Path(script_js_path).read_text(encoding="utf-8")
    script = session.create_script(code)
    script.load()
    device.resume(pid)
    return pid


