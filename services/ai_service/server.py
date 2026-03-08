from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

try:
    from .providers.langflow import LangFlowProvider
    from .providers.openai_provider import OpenAIProvider
    from .providers.azure_openai import AzureOpenAIProvider
    from .providers.anthropic_provider import AnthropicProvider
    from .providers.claudecode_provider import ClaudeCodeProvider
except ImportError:
    try:
        from services.ai_service.providers.langflow import LangFlowProvider
        from services.ai_service.providers.openai_provider import OpenAIProvider
        from services.ai_service.providers.azure_openai import AzureOpenAIProvider
        from services.ai_service.providers.anthropic_provider import AnthropicProvider
        from services.ai_service.providers.claudecode_provider import ClaudeCodeProvider
    except ImportError:
        from providers.langflow import LangFlowProvider
        from providers.openai_provider import OpenAIProvider
        from providers.azure_openai import AzureOpenAIProvider
        from providers.anthropic_provider import AnthropicProvider
        from providers.claudecode_provider import ClaudeCodeProvider


app = FastAPI(title="AIRA AI Assistant Service")


class ExplainIn(BaseModel):
    code: str
    provider: Optional[str] = None  # 'langflow', 'openai', or 'azure'


def get_provider(name: Optional[str]):
    name = (name or os.getenv("LLM_PROVIDER", "langflow")).lower()
    if name == "langflow":
        return LangFlowProvider()
    elif name == "openai":
        return OpenAIProvider()
    elif name in {"azure", "azure-openai", "azure_openai"}:
        return AzureOpenAIProvider()
    elif name in {"anthropic", "claude"}:
        return AnthropicProvider()
    elif name in {"claudecode", "claude-code"}:
        return ClaudeCodeProvider()
    raise HTTPException(status_code=400, detail=f"Unknown provider: {name}")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/explain")
def explain(inp: ExplainIn):
    try:
        provider = get_provider(inp.provider)
        text = provider.explain(inp.code)
        return {"explanation": text}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8002"))
    uvicorn.run(app, host="0.0.0.0", port=port)
