import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None  # type: ignore

if load_dotenv is not None:
    # Chemin absolu vers .env à la racine du projet
    _env_path = Path(__file__).resolve().parent.parent / ".env"
    load_dotenv(_env_path)


def env(key: str, default: str | None = None) -> str | None:
    v = os.getenv(key)
    return v if v is not None and v != "" else default


def env_int(key: str, default: int) -> int:
    value = env(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


BASE_DIR = Path(__file__).resolve().parent.parent
_out_val = env("OUTPUT_DIR", "output")
OUTPUT_DIR = Path(_out_val) if Path(_out_val).is_absolute() else BASE_DIR / _out_val
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Services
SYMEXEC_URL = env("SYMEXEC_URL", "http://127.0.0.1:8001")
AI_SERVICE_URL = env("AI_SERVICE_URL", "http://127.0.0.1:8002")

# LLM provider
LLM_PROVIDER = env("LLM_PROVIDER", "langflow")

# LangFlow
LANGFLOW_BASE_URL = env("LANGFLOW_BASE_URL", "http://localhost:7860")
LANGFLOW_FLOW_ID = env("LANGFLOW_FLOW_ID", "")
LANGFLOW_ENDPOINT = env("LANGFLOW_ENDPOINT", "/api/v1/run/")
LANGFLOW_API_KEY = env("LANGFLOW_API_KEY", "")

# OpenAI
OPENAI_API_KEY = env("OPENAI_API_KEY", "")
OPENAI_BASE_URL = env("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_MODEL = env("OPENAI_MODEL", "gpt-4o-mini")

# Azure OpenAI
AZURE_OPENAI_ENDPOINT = env("AZURE_OPENAI_ENDPOINT", "")
AZURE_OPENAI_API_KEY = env("AZURE_OPENAI_API_KEY", "")
AZURE_OPENAI_API_VERSION = env("AZURE_OPENAI_API_VERSION", "2024-05-01-preview")
AZURE_OPENAI_DEPLOYMENT = env("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")

# Ghidra MCP
GHIDRA_MCP_BRIDGE = BASE_DIR / "external" / "GhidraMCP" / "bridge_mcp_ghidra.py"
GHIDRA_SERVER_URL = env("GHIDRA_SERVER_URL", "http://127.0.0.1:8080/")
GHIDRA_MCP_TRANSPORT = env("GHIDRA_MCP_TRANSPORT", "sse")
GHIDRA_MCP_HOST = env("GHIDRA_MCP_HOST", "127.0.0.1")
GHIDRA_MCP_PORT = env_int("GHIDRA_MCP_PORT", 8081)
