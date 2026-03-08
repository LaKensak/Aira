from functools import lru_cache
from typing import List, Optional

from openai import OpenAI

from ..config import get_settings
from ..schemas import Message


@lru_cache(maxsize=1)
def _get_client() -> OpenAI:
    """Get a cached OpenAI client instance."""
    settings = get_settings()
    api_key = settings.openai_api_key
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    return OpenAI(api_key=api_key, base_url=settings.openai_base_url)


def chat_completion(
    messages: List[Message],
    model: Optional[str] = None,
    temperature: float = 0.2,
    top_p: float = 1.0,
):
    settings = get_settings()
    client = _get_client()

    # Convert to OpenAI message format
    payload_messages = [m.model_dump() for m in messages]

    model_name = model or settings.openai_model

    resp = client.chat.completions.create(
        model=model_name,
        messages=payload_messages,  # type: ignore[arg-type]
        temperature=temperature,
        top_p=top_p,
    )

    text = resp.choices[0].message.content or ""
    return {
        "model": model_name,
        "output_text": text,
        "raw": resp.model_dump(),
    }
