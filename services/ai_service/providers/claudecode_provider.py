from __future__ import annotations

import os
import subprocess


SYSTEM = (
    "You are a reverse engineering assistant. "
    "Explain the provided assembly or decompiled code clearly and concisely. "
    "Keep focus on purpose, inputs/outputs, and potential vulnerabilities."
)


class ClaudeCodeProvider:
    def __init__(self):
        self.claude_bin = os.getenv("CLAUDE_BIN", "claude")

    def explain(self, code: str) -> str:
        prompt = f"{SYSTEM}\n\nExplain this code:\n\n{code}"
        result = subprocess.run(
            [self.claude_bin, "-p", prompt],
            capture_output=True,
            text=True,
            timeout=120,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr or "claude CLI returned an error")
        return result.stdout.strip()
