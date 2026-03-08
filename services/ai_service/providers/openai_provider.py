from __future__ import annotations

import os

try:
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None  # type: ignore


SYSTEM = (
    "You are a reverse engineering assistant. "
    "Explain the provided assembly or decompiled code clearly and concisely. "
    "Keep focus on purpose, inputs/outputs, and potential vulnerabilities."
)


class OpenAIProvider:
    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        if OpenAI is None:
            raise RuntimeError("openai package not installed")
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    def explain(self, code: str) -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"Explain this code:\n\n{code}"},
            ],
            temperature=0.2,
        )
        return resp.choices[0].message.content or ""

