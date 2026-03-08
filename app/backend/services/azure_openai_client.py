from functools import lru_cache
from typing import List, Optional, Tuple

import requests
from openai import AzureOpenAI, BadRequestError

from ..config import get_settings
from ..schemas import Message


@lru_cache(maxsize=1)
def _get_client() -> Tuple[AzureOpenAI, str, str, str, str]:
    """Get a cached Azure OpenAI client instance and settings."""
    settings = get_settings()
    endpoint = settings.azure_openai_endpoint
    api_key = settings.azure_openai_api_key
    api_version = settings.azure_openai_api_version
    deployment = settings.azure_openai_deployment

    if not endpoint:
        raise RuntimeError("AZURE_OPENAI_ENDPOINT is not set")
    if not api_key:
        raise RuntimeError("AZURE_OPENAI_API_KEY is not set")
    if not deployment:
        raise RuntimeError("AZURE_OPENAI_DEPLOYMENT is not set")

    client = AzureOpenAI(
        azure_endpoint=endpoint,
        api_key=api_key,
        api_version=api_version,
    )
    return client, endpoint, api_key, api_version, deployment


def chat_completion(
    messages: List[Message],
    model: Optional[str] = None,
    temperature: float = 0.2,
    top_p: float = 1.0,
):
    client, endpoint, api_key, api_version, default_deployment = _get_client()
    deployment = model or default_deployment

    payload_messages = [m.model_dump() for m in messages]

    if _should_use_responses_api(deployment):
        return _call_responses_api(
            endpoint=endpoint,
            deployment=deployment,
            api_version=api_version,
            api_key=api_key,
            messages=messages,
            temperature=temperature,
            top_p=top_p,
        )

    try:
        resp = client.chat.completions.create(
            model=deployment,
            messages=payload_messages,  # type: ignore[arg-type]
            temperature=temperature,
            top_p=top_p,
        )
    except BadRequestError as err:
        if err.code == "OperationNotSupported":
            return _call_responses_api(
                endpoint=endpoint,
                deployment=deployment,
                api_version=api_version,
                api_key=api_key,
                messages=messages,
                temperature=temperature,
                top_p=top_p,
            )
        raise

    text = resp.choices[0].message.content or ""
    return {
        "model": deployment,
        "output_text": text,
        "raw": resp.model_dump(),
    }


def _call_responses_api(
    *,
    endpoint: str,
    deployment: str,
    api_version: str,
    api_key: str,
    messages: List[Message],
    temperature: float,
    top_p: float,
):
    url = f"{endpoint.rstrip('/')}/openai/deployments/{deployment}/responses"
    headers = {
        "api-key": api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "input": _messages_to_responses_input(messages),
        "temperature": temperature,
        "top_p": top_p,
    }

    response = requests.post(
        url,
        params={"api-version": api_version},
        headers=headers,
        json=payload,
        timeout=60,
    )
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        message = _extract_error_message(exc.response)
        raise RuntimeError(f"Azure Responses API error: {message}") from exc

    data = response.json()
    text = _extract_output_text(data)

    return {
        "model": deployment,
        "output_text": text,
        "raw": data,
    }


def _messages_to_responses_input(messages: List[Message]) -> List[dict]:
    converted: List[dict] = []
    for msg in messages:
        converted.append(
            {
                "role": msg.role,
                "content": [
                    {
                        "type": "text",
                        "text": msg.content,
                    }
                ],
            }
        )
    return converted


def _extract_output_text(data: dict) -> str:
    if not isinstance(data, dict):
        return ""

    output_text = data.get("output_text")
    if isinstance(output_text, str) and output_text:
        return output_text

    output_items = data.get("output")
    if isinstance(output_items, list):
        collected: List[str] = []
        for item in output_items:
            if not isinstance(item, dict):
                continue
            if item.get("type") != "message" or item.get("role") != "assistant":
                continue
            contents = item.get("content")
            if not isinstance(contents, list):
                continue
            for content in contents:
                if not isinstance(content, dict):
                    continue
                if content.get("type") == "text":
                    text_segment = content.get("text")
                    if isinstance(text_segment, str):
                        collected.append(text_segment)
        if collected:
            return "".join(collected)

    return ""


def _extract_error_message(response: Optional[requests.Response]) -> str:
    if response is None:
        return "Unknown error"
    try:
        data = response.json()
    except ValueError:
        return response.text

    if isinstance(data, dict):
        message = data.get("message") or data.get("error")
        if isinstance(message, str):
            return message
        if isinstance(message, dict):
            nested = message.get("message")
            if isinstance(nested, str):
                return nested
    return response.text


def _should_use_responses_api(deployment: Optional[str]) -> bool:
    if not deployment:
        return False
    lowered = deployment.lower()
    return "gpt-5" in lowered or "codex" in lowered
