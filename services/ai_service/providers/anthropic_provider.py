from __future__ import annotations

import os

try:
    import anthropic
except Exception:  # pragma: no cover
    anthropic = None  # type: ignore

SYSTEM = (
    "You are a reverse engineering assistant. "
    "Explain the provided assembly or decompiled code clearly and concisely. "
    "Keep focus on purpose, inputs/outputs, and potential vulnerabilities."
)


class AnthropicProvider:
    def __init__(self):
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        if anthropic is None:
            raise RuntimeError("anthropic package not installed")
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")

    def explain(self, code: str) -> str:
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=2048,
            system=SYSTEM,
            messages=[
                {"role": "user", "content": f"Explain this code:\n\n{code}"},
            ],
        )
        return resp.content[0].text
