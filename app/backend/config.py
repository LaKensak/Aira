from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Racine du projet : app/backend -> app -> root
_ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)

    # Default provider — lit LLM_PROVIDER (cohérent avec aira/config.py)
    default_provider: str = Field(default="langflow", alias="LLM_PROVIDER")

    # OpenAI
    openai_api_key: Optional[str] = Field(default=None)
    openai_model: str = Field(default="gpt-4o-mini")
    openai_base_url: str = Field(default="https://api.openai.com/v1")

    # LangFlow
    langflow_base_url: Optional[str] = Field(default=None)
    langflow_api_key: Optional[str] = Field(default=None)
    langflow_flow_id: Optional[str] = Field(default=None)
    langflow_endpoint: str = Field(default="/api/v1/run/")

    # Ollama (provider "aira")
    ollama_base_url: str = Field(default="http://127.0.0.1:11434")
    ollama_model: str = Field(default="qwen2.5-coder:latest")
    ghidra_server_url: str = Field(default="http://127.0.0.1:8080/")
    symexec_url: str = Field(default="http://127.0.0.1:8001")

    # Azure OpenAI
    azure_openai_endpoint: Optional[str] = Field(default=None)
    azure_openai_api_key: Optional[str] = Field(default=None)
    azure_openai_api_version: str = Field(default="2024-05-01-preview")
    azure_openai_deployment: Optional[str] = Field(default="gpt-4o")

    # Upload settings
    max_upload_size: int = Field(default=50 * 1024 * 1024)  # 50 MB


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
