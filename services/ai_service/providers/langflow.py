from __future__ import annotations

import json
import os
from typing import Any

import requests


def _normalize_endpoint(endpoint: str) -> str:
    endpoint = (endpoint or "/api/v1/run/").strip()
    if not endpoint:
        endpoint = "/api/v1/run/"
    if not endpoint.startswith("/"):
        endpoint = f"/{endpoint}"
    if not endpoint.endswith("/"):
        endpoint = f"{endpoint}/"
    return endpoint


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


class LangFlowProvider:
    def __init__(self):
        base = os.getenv("LANGFLOW_BASE_URL", "http://localhost:7860")
        flow_id = os.getenv("LANGFLOW_FLOW_ID", "")
        endpoint = _normalize_endpoint(os.getenv("LANGFLOW_ENDPOINT", "/api/v1/run/"))
        token = (os.getenv("LANGFLOW_API_KEY", "") or "").strip()
        self.url = f"{base.rstrip('/')}{endpoint}{flow_id}"
        headers = {"Content-Type": "application/json"}
        self.params: dict[str, str] | None = None
        if token:
            headers.update(
                {
                    "Authorization": f"Bearer {token}",
                    "x-api-key": token,
                    "x-langflow-api-key": token,
                }
            )
            self.params = {"api_key": token}
        self.headers = headers

    def explain(self, code: str) -> str:
        payload: dict[str, Any] = {
            "input_value": code,
            "inputs": {"code": code, "text": code, "question": code},
            "text": code,
            "question": code,
            "input_type": "chat",
            "output_type": "chat",
        }
        r = requests.post(
            self.url,
            headers=self.headers,
            params=self.params,
            json=payload,
            timeout=120,
        )
        try:
            r.raise_for_status()
        except requests.HTTPError as exc:
            message = _summarize_error(r)
            raise RuntimeError(f"Langflow request failed ({r.status_code}): {message}") from exc
        data = r.json()
        # Try common shapes, fallback to raw string
        if isinstance(data, dict):
            for key in ("text", "output", "result", "explanation"):
                if key in data and isinstance(data[key], str):
                    return data[key]
        return json.dumps(data)
