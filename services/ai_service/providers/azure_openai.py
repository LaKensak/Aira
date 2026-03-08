from __future__ import annotations

import os

try:
    from openai import AzureOpenAI
except Exception:  # pragma: no cover
    AzureOpenAI = None  # type: ignore

SYSTEM_PROMPT = (
    "You are a reverse engineering assistant. "
    "Explain the provided assembly or decompiled code clearly and concisely. "
    "Keep focus on purpose, inputs/outputs, and potential vulnerabilities."
)


class AzureOpenAIProvider:
    def __init__(self):
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        api_key = os.getenv("AZURE_OPENAI_API_KEY")
        api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-05-01-preview")
        deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5-codex")

        if AzureOpenAI is None:
            raise RuntimeError("openai package not installed")
        if not endpoint:
            raise RuntimeError("AZURE_OPENAI_ENDPOINT is not set")
        if not api_key:
            raise RuntimeError("AZURE_OPENAI_API_KEY is not set")
        if not deployment:
            raise RuntimeError("AZURE_OPENAI_DEPLOYMENT is not set")

        self.client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=api_key,
            api_version=api_version,
        )
        self.deployment = deployment

    def explain(self, code: str) -> str:
        resp = self.client.chat.completions.create(
            model=self.deployment,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Explain this code:\n\n{code}"},
            ],
            temperature=0.2,
        )
        return resp.choices[0].message.content or ""
