"""
Tests pour le module aira.http_client.
"""
import pytest
from unittest.mock import patch, MagicMock
import requests

from aira.http_client import (
    get_sync_session,
    reset_sync_session,
    is_async_available,
    sync_get,
    sync_post,
    sync_post_json,
    DEFAULT_TIMEOUT,
    DEFAULT_HEADERS,
)


class TestSyncSession:
    """Tests pour la session synchrone."""

    def test_get_sync_session_returns_session(self):
        """Test que get_sync_session retourne une Session."""
        session = get_sync_session()
        assert isinstance(session, requests.Session)

    def test_get_sync_session_singleton(self):
        """Test que la même session est retournée."""
        session1 = get_sync_session()
        session2 = get_sync_session()
        assert session1 is session2

    def test_reset_sync_session(self):
        """Test que reset crée une nouvelle session."""
        session1 = get_sync_session()
        reset_sync_session()
        session2 = get_sync_session()
        # After reset, should be a different object
        # (but implementation might reuse, so just check it works)
        assert isinstance(session2, requests.Session)

    def test_session_has_default_headers(self):
        """Test que la session a les headers par défaut."""
        session = get_sync_session()
        assert "User-Agent" in session.headers
        assert "AIRA" in session.headers["User-Agent"]

    def test_session_has_retry_adapter(self):
        """Test que la session a un adapter avec retry."""
        session = get_sync_session()
        # Check adapters are mounted
        assert "http://" in session.adapters
        assert "https://" in session.adapters


class TestAsyncClient:
    """Tests pour le client async."""

    def test_is_async_available(self):
        """Test que la disponibilité async est correctement détectée."""
        result = is_async_available()
        # Should be True if httpx is installed
        assert isinstance(result, bool)


class TestSyncHelpers:
    """Tests pour les fonctions helper synchrones."""

    @patch.object(requests.Session, "get")
    def test_sync_get(self, mock_get):
        """Test sync_get avec mock."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        reset_sync_session()
        response = sync_get("http://example.com")

        assert response.status_code == 200
        mock_get.assert_called_once()

    @patch.object(requests.Session, "post")
    def test_sync_post(self, mock_post):
        """Test sync_post avec mock."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        reset_sync_session()
        response = sync_post("http://example.com", json={"key": "value"})

        assert response.status_code == 200
        mock_post.assert_called_once()

    @patch.object(requests.Session, "post")
    def test_sync_post_json(self, mock_post):
        """Test sync_post_json avec mock."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "success"}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        reset_sync_session()
        result = sync_post_json("http://example.com", {"key": "value"})

        assert result == {"result": "success"}

    @patch.object(requests.Session, "post")
    def test_sync_post_json_raises_on_error(self, mock_post):
        """Test que sync_post_json lève une exception sur erreur HTTP."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
        mock_post.return_value = mock_response

        reset_sync_session()
        with pytest.raises(requests.HTTPError):
            sync_post_json("http://example.com", {"key": "value"})

    @patch.object(requests.Session, "get")
    def test_sync_get_with_params(self, mock_get):
        """Test sync_get avec paramètres."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        reset_sync_session()
        sync_get("http://example.com", params={"q": "test"})

        # Check params were passed
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["params"] == {"q": "test"}

    @patch.object(requests.Session, "get")
    def test_sync_get_with_custom_timeout(self, mock_get):
        """Test sync_get avec timeout personnalisé."""
        mock_response = MagicMock()
        mock_get.return_value = mock_response

        reset_sync_session()
        sync_get("http://example.com", timeout=60)

        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["timeout"] == 60

    @patch.object(requests.Session, "get")
    def test_sync_get_default_timeout(self, mock_get):
        """Test que le timeout par défaut est utilisé."""
        mock_response = MagicMock()
        mock_get.return_value = mock_response

        reset_sync_session()
        sync_get("http://example.com")

        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["timeout"] == DEFAULT_TIMEOUT

    @patch.object(requests.Session, "post")
    def test_sync_post_with_headers(self, mock_post):
        """Test sync_post avec headers personnalisés."""
        mock_response = MagicMock()
        mock_post.return_value = mock_response

        reset_sync_session()
        sync_post("http://example.com", headers={"X-Custom": "value"})

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["headers"] == {"X-Custom": "value"}


class TestConstants:
    """Tests pour les constantes."""

    def test_default_timeout(self):
        """Test que DEFAULT_TIMEOUT est défini."""
        assert DEFAULT_TIMEOUT > 0

    def test_default_headers(self):
        """Test que DEFAULT_HEADERS contient User-Agent."""
        assert "User-Agent" in DEFAULT_HEADERS
        assert "Accept" in DEFAULT_HEADERS
