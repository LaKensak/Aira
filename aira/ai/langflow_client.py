from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, MutableSequence, Sequence

import requests


__all__ = ["LangflowClient", "LangflowChatSession", "LangflowError"]


class LangflowError(RuntimeError):
    """Raised when the LangFlow API returns an error response."""


def _normalize_endpoint(endpoint: str | None) -> str:
    endpoint = (endpoint or "/api/v1/run/").strip()
    if not endpoint:
        endpoint = "/api/v1/run/"
    if not endpoint.startswith("/"):
        endpoint = f"/{endpoint}"
    if not endpoint.endswith("/"):
        endpoint = f"{endpoint}/"
    return endpoint


def _build_prompt(messages: Sequence[Mapping[str, str]]) -> str:
    parts: list[str] = []
    for msg in messages:
        role = msg.get("role")
        content = (msg.get("content") or "").strip()
        prefix = {
            "system": "[System]",
            "user": "[User]",
            "assistant": "[Assistant]",
        }.get(role, "[User]")
        parts.append(f"{prefix} {content}")
    return "\n\n".join(parts)


def _summarize_error(resp: requests.Response) -> str:
    try:
        data = resp.json()
    except ValueError:
        data = None

    if isinstance(data, dict):
        for key in ("detail", "message", "error"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    text = resp.text.strip()
    return text or f"HTTP {resp.status_code}"


def _extract_text(obj) -> str:
    if isinstance(obj, str):
        cleaned = obj.strip()
        if cleaned:
            return cleaned

    if isinstance(obj, dict):
        priority_keys = ("output", "result", "text", "answer", "message", "content")
        for key in priority_keys:
            if key in obj:
                candidate = _extract_text(obj[key])
                if candidate:
                    return candidate

        for key in ("outputs", "results", "data"):
            value = obj.get(key)
            candidate = _extract_text(value)
            if candidate:
                return candidate

        for value in obj.values():
            candidate = _extract_text(value)
            if candidate:
                return candidate

    if isinstance(obj, (list, tuple)):
        for item in obj:
            candidate = _extract_text(item)
            if candidate:
                return candidate

    if obj is None or obj == [] or obj == {}:
        return ""
    return str(obj)


@dataclass(slots=True)
class LangflowClient:
    """Thin client around a LangFlow deployment."""

    base_url: str
    flow_id: str
    endpoint: str = "/api/v1/run/"
    api_key: str | None = None
    timeout: int | None = None  # None = pas de timeout (attend la réponse finale)
    _session: requests.Session = field(init=False, repr=False)
    _headers: dict[str, str] = field(init=False, repr=False)
    _params: dict[str, str] | None = field(init=False, repr=False)

    def __post_init__(self) -> None:
        base = (self.base_url or "").strip()
        if not base:
            raise ValueError("LangFlow base URL is not configured")
        flow = (self.flow_id or "").strip()
        if not flow:
            raise ValueError("LangFlow flow id is not configured")

        self.base_url = base.rstrip("/")
        self.flow_id = flow
        self.endpoint = _normalize_endpoint(self.endpoint)
        token = (self.api_key or "").strip() or None
        self.api_key = token
        object.__setattr__(self, "_session", requests.Session())
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if token:
            headers.update(
                {
                    "Authorization": f"Bearer {token}",
                    "x-api-key": token,
                    "x-langflow-api-key": token,
                }
            )
        object.__setattr__(self, "_headers", headers)
        object.__setattr__(self, "_params", {"api_key": token} if token else None)

    @property
    def url(self) -> str:
        return f"{self.base_url}{self.endpoint}{self.flow_id}"

    def run_flow(
        self,
        messages: Sequence[Mapping[str, str]],
        *,
        temperature: float = 0.2,
        top_p: float = 1.0,
        mcp_result: str = "",
        context: str = "",
        extra_inputs: Mapping[str, str] | None = None,
    ) -> dict:
        question = _build_prompt(messages)

        # Prepend binary context to input_value so it reaches the LLM
        # regardless of LangFlow's internal variable routing.
        # mcp_result is already capped at 2000 chars by build_static_context.
        prefix_parts: list[str] = []
        if context:
            prefix_parts.append(f"[Binary] {context}")
        if mcp_result:
            prefix_parts.append(f"[Static Analysis]\n{mcp_result}")
        full_input = "\n\n".join(prefix_parts + [question]) if prefix_parts else question

        payload: dict[str, object] = {
            "input_value": full_input,
            "temperature": temperature,
            "top_p": top_p,
            "input_type": "chat",
            "output_type": "chat",
            "inputs": {
                "text": full_input,
                "question": question,
                "mcp_result": mcp_result,
                "context": context,
            },
        }
        if extra_inputs:
            payload["inputs"].update(extra_inputs)

        try:
            resp = self._session.post(
                self.url,
                json=payload,
                headers=self._headers,
                params=self._params,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:  # pragma: no cover - network failure
            raise LangflowError(str(exc)) from exc

        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            message = _summarize_error(resp)
            raise LangflowError(f"LangFlow request failed ({resp.status_code}): {message}") from exc

        data = resp.json()
        text = _extract_text(data)
        if not text:
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "LangFlow returned empty text. Raw response: %s",
                str(data)[:500],
            )
        return {
            "model": f"langflow:{self.flow_id}",
            "output_text": text,
            "raw": data,
        }


class LangflowChatSession:
    """Stateful helper to maintain a LangFlow conversation."""

    def __init__(
        self,
        client: LangflowClient,
        *,
        system_prompt: str | None = None,
        temperature: float = 0.2,
        top_p: float = 1.0,
    ):
        self.client = client
        self.temperature = temperature
        self.top_p = top_p
        self.messages: MutableSequence[dict[str, str]] = []
        if system_prompt:
            self.add_message("system", system_prompt)

    def add_message(self, role: str, content: str) -> None:
        if role not in {"system", "user", "assistant"}:
            raise ValueError(f"Unsupported role: {role}")
        self.messages.append({"role": role, "content": content})

    def ask(
        self,
        prompt: str,
        *,
        temperature: float | None = None,
        top_p: float | None = None,
        mcp_result: str = "",
        context: str = "",
    ) -> dict:
        self.add_message("user", prompt)
        response = self.client.run_flow(
            self.messages,
            temperature=temperature if temperature is not None else self.temperature,
            top_p=top_p if top_p is not None else self.top_p,
            mcp_result=mcp_result,
            context=context,
        )
        reply = response.get("output_text") or ""
        self.add_message("assistant", reply)
        response["messages"] = list(self.messages)
        return response

    def transcript(self) -> list[dict[str, str]]:
        return list(self.messages)
