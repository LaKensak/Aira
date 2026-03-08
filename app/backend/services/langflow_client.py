from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from aira.ai.langflow_client import LangflowClient, LangflowError
from aira.ghidra.client import GhidraClient, cascade_mcp_context

from ..config import get_settings
from ..schemas import Message

_BINARY_PATH_RE = re.compile(r"Fichier binaire analys[eé]\s*:\s*(.+)", re.IGNORECASE)


def _extract_binary_path(messages: List[Message]) -> str:
    """Extract the binary path injected by the frontend as a system message."""
    for msg in messages:
        if msg.role == "system":
            m = _BINARY_PATH_RE.search(msg.content)
            if m:
                return m.group(1).strip()
    return ""


def _extract_user_question(messages: List[Message]) -> str:
    """Return the last user message content."""
    for msg in reversed(messages):
        if msg.role == "user":
            return msg.content
    return ""


_CLIENT_CACHE: Dict[Tuple[str, str, str, str], LangflowClient] = {}


def _get_client(
    *,
    base_url: str,
    flow_id: str,
    endpoint: str,
    api_key: Optional[str],
) -> LangflowClient:
    key = (base_url, flow_id, endpoint, (api_key or ""))
    client = _CLIENT_CACHE.get(key)
    if client is None:
        client = LangflowClient(
            base_url=base_url,
            flow_id=flow_id,
            endpoint=endpoint,
            api_key=api_key,
        )
        _CLIENT_CACHE[key] = client
    return client


def run_flow(
    messages: List[Message],
    flow_id: Optional[str] = None,
    temperature: float = 0.2,
    top_p: float = 1.0,
):
    settings = get_settings()
    base_url = settings.langflow_base_url
    if not base_url:
        raise RuntimeError("LANGFLOW_BASE_URL is not set")

    use_flow_id = (flow_id or settings.langflow_flow_id or "").strip()
    if not use_flow_id:
        raise RuntimeError("Langflow flow id is not specified (LANGFLOW_FLOW_ID)")

    endpoint = getattr(settings, "langflow_endpoint", "/api/v1/run/") or "/api/v1/run/"
    api_key = getattr(settings, "langflow_api_key", None)

    client = _get_client(
        base_url=base_url.rstrip("/"),
        flow_id=use_flow_id,
        endpoint=endpoint,
        api_key=api_key,
    )

    binary_path = _extract_binary_path(messages)
    question = _extract_user_question(messages)

    ghidra_url = getattr(settings, "ghidra_server_url", "http://127.0.0.1:8080/") or "http://127.0.0.1:8080/"
    symexec_url = getattr(settings, "symexec_url", "http://127.0.0.1:8001") or "http://127.0.0.1:8001"
    ghidra = GhidraClient(base_url=ghidra_url) if binary_path else None

    mcp_result = (
        cascade_mcp_context(
            binary_path,
            question=question,
            ghidra_client=ghidra,
            symexec_url=symexec_url,
        )
        if binary_path and Path(binary_path).exists()
        else ""
    )
    context = f"Binary under analysis: {binary_path}" if binary_path else ""

    payload_messages = [{"role": m.role, "content": m.content} for m in messages]
    try:
        return client.run_flow(
            payload_messages,
            temperature=temperature,
            top_p=top_p,
            mcp_result=mcp_result,
            context=context,
        )
    except LangflowError as exc:
        raise RuntimeError(str(exc)) from exc
