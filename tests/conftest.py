"""
Fixtures globales pour les tests AIRA.
"""
import sys
import types
import tempfile
import json
from pathlib import Path
from typing import Generator, Any
from unittest.mock import Mock, MagicMock

import pytest


# ============================================================================
# PATH FIXTURES
# ============================================================================

@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Crée un répertoire temporaire pour les tests."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest.fixture
def temp_output_dir(temp_dir: Path) -> Path:
    """Crée un répertoire output temporaire."""
    output = temp_dir / "output"
    output.mkdir()
    return output


@pytest.fixture
def temp_binary_file(temp_dir: Path) -> Path:
    """Crée un fichier binaire temporaire factice."""
    binary = temp_dir / "test_binary.exe"
    # Header PE minimal factice
    binary.write_bytes(b"MZ" + b"\x00" * 62 + b"PE\x00\x00" + b"\x00" * 100)
    return binary


# ============================================================================
# BINARY MOCKS
# ============================================================================

@pytest.fixture
def fake_pe_binary() -> types.SimpleNamespace:
    """Simule un binaire PE parsé par LIEF."""
    section = types.SimpleNamespace(
        name=".text",
        size=0x1000,
        virtual_address=0x1000,
        characteristics=0x60000020,
    )

    import_entry = types.SimpleNamespace(name="kernel32.dll")

    optional_header = types.SimpleNamespace(
        imagebase=0x400000,
        addressof_entrypoint=0x1234,
    )

    binary = types.SimpleNamespace(
        format=types.SimpleNamespace(name="PE"),
        entrypoint=0x401234,  # imagebase + addressof_entrypoint
        sections=[section],
        imports=[import_entry],
        optional_header=optional_header,
        has_nx=True,
        has_pie=True,
        header=types.SimpleNamespace(
            machine=types.SimpleNamespace(name="AMD64"),
        ),
    )
    return binary


@pytest.fixture
def fake_elf_binary() -> types.SimpleNamespace:
    """Simule un binaire ELF parsé par LIEF."""
    section = types.SimpleNamespace(
        name=".text",
        size=0x2000,
        virtual_address=0x8048000,
        flags=0x6,
    )

    binary = types.SimpleNamespace(
        format=types.SimpleNamespace(name="ELF"),
        entrypoint=0x8048100,
        sections=[section],
        imported_libraries=["libc.so.6"],
        has_nx=True,
        has_pie=False,
        header=types.SimpleNamespace(
            machine_type=types.SimpleNamespace(name="x86_64"),
        ),
    )
    return binary


# ============================================================================
# HTTP/REQUESTS MOCKS
# ============================================================================

@pytest.fixture
def mock_requests_session(mocker) -> MagicMock:
    """Mock requests.Session pour les tests."""
    session = MagicMock()
    mocker.patch("requests.Session", return_value=session)
    return session


@pytest.fixture
def mock_requests_post(mocker) -> MagicMock:
    """Mock requests.post pour les tests."""
    return mocker.patch("requests.post")


@pytest.fixture
def mock_requests_get(mocker) -> MagicMock:
    """Mock requests.get pour les tests."""
    return mocker.patch("requests.get")


def make_response(
    status_code: int = 200,
    json_data: dict | None = None,
    text: str = "",
    ok: bool = True,
) -> Mock:
    """Helper pour créer des réponses HTTP mockées."""
    resp = Mock()
    resp.status_code = status_code
    resp.ok = ok
    resp.text = text
    resp.reason = "OK" if ok else "Error"
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("No JSON")
    return resp


# ============================================================================
# LANGFLOW MOCKS
# ============================================================================

@pytest.fixture
def mock_langflow_response() -> dict:
    """Réponse LangFlow typique."""
    return {
        "outputs": [
            {
                "outputs": [
                    {
                        "results": {
                            "message": {
                                "text": "This is an AI explanation of the code."
                            }
                        }
                    }
                ]
            }
        ]
    }


@pytest.fixture
def mock_langflow_error_response() -> dict:
    """Réponse d'erreur LangFlow."""
    return {
        "detail": "Flow execution failed: Invalid input"
    }


# ============================================================================
# FASTAPI TEST CLIENT
# ============================================================================

@pytest.fixture
def fastapi_test_client():
    """Client de test FastAPI."""
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        yield client


# ============================================================================
# SYMEXEC MOCKS
# ============================================================================

@pytest.fixture
def mock_symexec_solve_response() -> dict:
    """Réponse typique du service symexec."""
    return {
        "stdin": "flag{test_input}",
        "found_addr": 0x401234,
        "steps": 150,
    }


@pytest.fixture
def mock_symexec_cfg_response() -> dict:
    """Réponse CFG du service symexec."""
    return {
        "dot": 'digraph G { "0x1000" -> "0x1010"; "0x1010" -> "0x1020"; }'
    }


# ============================================================================
# CONFIG MOCKS
# ============================================================================

@pytest.fixture
def mock_env_vars(monkeypatch) -> dict:
    """Configure les variables d'environnement pour les tests."""
    env = {
        "OPENAI_API_KEY": "sk-test-key-12345",
        "AZURE_OPENAI_API_KEY": "azure-test-key",
        "AZURE_OPENAI_ENDPOINT": "https://test.openai.azure.com",
        "LANGFLOW_BASE_URL": "http://localhost:7860",
        "LANGFLOW_API_KEY": "langflow-test-key",
        "LANGFLOW_FLOW_ID": "test-flow-id-12345",
        "SYMEXEC_URL": "http://localhost:8001",
        "AI_SERVICE_URL": "http://localhost:8002",
        "GHIDRA_SERVER_URL": "http://localhost:8080",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return env


# ============================================================================
# CLEANUP HELPERS
# ============================================================================

@pytest.fixture(autouse=True)
def cleanup_output_dir():
    """Nettoie le répertoire output après chaque test."""
    yield
    output_dir = Path("output")
    if output_dir.exists():
        for f in output_dir.glob("test_*"):
            try:
                f.unlink()
            except OSError:
                pass


# ============================================================================
# MARKERS HELPERS
# ============================================================================

def pytest_configure(config):
    """Configure les markers personnalisés."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow running"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests requiring external services"
    )
    config.addinivalue_line(
        "markers", "security: marks security-related tests"
    )
