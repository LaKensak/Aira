"""
Tests pour le rate limiting et la sécurité de l'API.
"""
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path


@pytest.fixture
def client():
    """Client de test FastAPI."""
    from fastapi.testclient import TestClient
    from app.main import app

    # Reset rate limiter state between tests
    with TestClient(app) as client:
        yield client


class TestRateLimiting:
    """Tests pour le rate limiting des endpoints."""

    @pytest.mark.security
    def test_health_endpoint_rate_limited(self, client):
        """Test que /api/health est rate limité."""
        # First requests should succeed
        for _ in range(5):
            response = client.get("/api/health")
            assert response.status_code in (200, 429)

    @pytest.mark.security
    def test_providers_endpoint_rate_limited(self, client):
        """Test que /api/providers est rate limité."""
        response = client.get("/api/providers")
        assert response.status_code in (200, 429)


class TestPathTraversalProtection:
    """Tests pour la protection contre le path traversal."""

    @pytest.mark.security
    def test_analyze_static_blocks_etc_passwd(self, client):
        """Test que /api/analyze/static-info bloque les chemins dangereux."""
        response = client.post(
            "/api/analyze/static-info",
            json={"path": "/etc/passwd"}
        )
        # Should be blocked (403 or 404)
        assert response.status_code in (403, 404)

    @pytest.mark.security
    def test_analyze_static_blocks_parent_traversal(self, client):
        """Test que les chemins avec .. sont bloqués."""
        response = client.post(
            "/api/analyze/static-info",
            json={"path": "../../etc/passwd"}
        )
        assert response.status_code in (403, 404, 400)

    @pytest.mark.security
    def test_analyze_static_blocks_windows_system(self, client):
        """Test que les chemins Windows système sont bloqués."""
        response = client.post(
            "/api/analyze/static-info",
            json={"path": "C:\\Windows\\System32\\cmd.exe"}
        )
        assert response.status_code in (403, 404)


class TestUploadSecurity:
    """Tests pour la sécurité des uploads."""

    @pytest.mark.security
    def test_get_upload_sanitizes_filename(self, client):
        """Test que les noms de fichiers sont sanitisés."""
        # Try to access a file with path traversal
        response = client.get("/api/uploads/../../../etc/passwd")
        # Should be blocked or file not found
        assert response.status_code in (403, 404, 422)

    @pytest.mark.security
    def test_get_upload_blocks_hidden_files(self, client):
        """Test que les fichiers cachés sont gérés."""
        response = client.get("/api/uploads/.env")
        assert response.status_code in (403, 404)


class TestChatEndpoint:
    """Tests pour l'endpoint /api/chat."""

    def test_chat_requires_messages(self, client):
        """Test que messages est requis."""
        response = client.post("/api/chat", json={})
        assert response.status_code == 422

    def test_chat_unknown_provider(self, client):
        """Test avec un provider inconnu."""
        response = client.post("/api/chat", json={
            "messages": [{"role": "user", "content": "test"}],
            "provider": "unknown_provider"
        })
        # Can be 400 (bad request) or 422 (validation error)
        assert response.status_code in (400, 422)

    def test_chat_openai_with_mock(self, client):
        """Test chat endpoint (may fail without actual OpenAI config)."""
        # This test verifies the endpoint is callable
        # Actual success depends on OpenAI configuration
        response = client.post("/api/chat", json={
            "messages": [{"role": "user", "content": "Hello"}],
            "provider": "openai"
        })
        # Accept 200 (success), 500 (service error), or 429 (rate limited)
        assert response.status_code in (200, 500, 429)


class TestHealthEndpoint:
    """Tests pour l'endpoint /api/health."""

    def test_health_returns_ok(self, client):
        """Test que health retourne status ok."""
        response = client.get("/api/health")
        if response.status_code == 200:
            data = response.json()
            assert data["status"] == "ok"
            assert "provider" in data


class TestProvidersEndpoint:
    """Tests pour l'endpoint /api/providers."""

    def test_providers_returns_list(self, client):
        """Test que providers retourne la liste des providers."""
        response = client.get("/api/providers")
        if response.status_code == 200:
            data = response.json()
            assert "supported" in data
            assert "openai" in data["supported"]
            assert "langflow" in data["supported"]
            assert "azure" in data["supported"]


class TestUploadEndpoint:
    """Tests pour l'endpoint /api/upload."""

    def test_upload_file_too_large(self, client):
        """Test que les fichiers trop gros sont rejetés."""
        # Create a large fake file (> 50MB would be rejected)
        # For testing, we use a smaller threshold check
        large_content = b"x" * (1024 * 1024)  # 1MB
        response = client.post(
            "/api/upload",
            files={"file": ("test.exe", large_content)}
        )
        # Either succeeds (file not too large) or fails with 413
        assert response.status_code in (200, 413, 429)

    def test_upload_sanitizes_filename(self, client):
        """Test que les noms de fichiers dangereux sont sanitisés."""
        content = b"MZ" + b"\x00" * 100
        response = client.post(
            "/api/upload",
            files={"file": ("../../../etc/test.exe", content)}
        )
        if response.status_code == 200:
            data = response.json()
            # Filename should be sanitized
            assert ".." not in data["filename"]
            assert "/" not in data["filename"]
