from __future__ import annotations

from typing import Literal

import requests

from aira.config import AI_SERVICE_URL


Provider = Literal["langflow", "openai", "azure"]


def explain(code: str, provider: Provider | None = None) -> str:
    url = f"{AI_SERVICE_URL}/explain"
    r = requests.post(url, json={"code": code, "provider": provider}, timeout=120)
    r.raise_for_status()
    return r.json()["explanation"]
