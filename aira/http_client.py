"""
Clients HTTP partagés avec connection pooling.

Usage:
    from aira.http_client import get_sync_session, get_async_client

    # Synchrone
    session = get_sync_session()
    response = session.get("http://example.com")

    # Asynchrone
    async with get_async_client() as client:
        response = await client.get("http://example.com")
"""
from __future__ import annotations

import atexit
from functools import lru_cache
from typing import Any

import requests

from .logging_config import get_logger

logger = get_logger(__name__)


# ============================================================================
# CONFIGURATION
# ============================================================================

# Timeouts par défaut (en secondes)
DEFAULT_TIMEOUT = 30
DEFAULT_CONNECT_TIMEOUT = 10

# Limites de connexion
MAX_CONNECTIONS = 100
MAX_KEEPALIVE_CONNECTIONS = 20

# Headers par défaut
DEFAULT_HEADERS = {
    "User-Agent": "AIRA/1.0 (AI-Assisted Reversing Analyser)",
    "Accept": "application/json",
}


# ============================================================================
# SYNCHRONOUS CLIENT (requests)
# ============================================================================

_sync_session: requests.Session | None = None


def get_sync_session() -> requests.Session:
    """
    Obtient une session requests partagée avec connection pooling.

    La session est réutilisée entre les appels pour bénéficier
    du keep-alive et du connection pooling.

    Returns:
        Session requests configurée
    """
    global _sync_session

    if _sync_session is None:
        _sync_session = _create_sync_session()
        # Enregistrer le cleanup à la fermeture
        atexit.register(_cleanup_sync_session)
        logger.debug("Created new sync HTTP session")

    return _sync_session


def _create_sync_session() -> requests.Session:
    """Crée une nouvelle session requests."""
    session = requests.Session()

    # Headers par défaut
    session.headers.update(DEFAULT_HEADERS)

    # Configurer le pool de connexions
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=MAX_KEEPALIVE_CONNECTIONS,
        pool_maxsize=MAX_CONNECTIONS,
        max_retries=requests.adapters.Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
        ),
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


def _cleanup_sync_session() -> None:
    """Ferme la session synchrone."""
    global _sync_session
    if _sync_session is not None:
        try:
            _sync_session.close()
            logger.debug("Closed sync HTTP session")
        except Exception as e:
            logger.warning(f"Error closing sync session: {e}")
        _sync_session = None


def reset_sync_session() -> None:
    """Force la recréation de la session synchrone."""
    _cleanup_sync_session()


# ============================================================================
# ASYNC CLIENT (httpx)
# ============================================================================

# Import conditionnel de httpx
try:
    import httpx

    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False
    httpx = None

_async_client: Any | None = None


def is_async_available() -> bool:
    """Vérifie si le client async est disponible."""
    return _HTTPX_AVAILABLE


def get_async_client() -> Any:
    """
    Obtient un client httpx async partagé.

    Note: httpx.AsyncClient doit être utilisé comme context manager
    ou fermé explicitement.

    Returns:
        Client httpx.AsyncClient

    Raises:
        ImportError: Si httpx n'est pas installé
    """
    if not _HTTPX_AVAILABLE:
        raise ImportError(
            "httpx is required for async HTTP client. "
            "Install with: pip install httpx"
        )

    global _async_client

    if _async_client is None:
        _async_client = _create_async_client()
        logger.debug("Created new async HTTP client")

    return _async_client


def _create_async_client() -> Any:
    """Crée un nouveau client httpx async."""
    if not _HTTPX_AVAILABLE:
        raise ImportError("httpx not available")

    limits = httpx.Limits(
        max_connections=MAX_CONNECTIONS,
        max_keepalive_connections=MAX_KEEPALIVE_CONNECTIONS,
    )

    timeout = httpx.Timeout(
        connect=DEFAULT_CONNECT_TIMEOUT,
        read=DEFAULT_TIMEOUT,
        write=DEFAULT_TIMEOUT,
        pool=DEFAULT_TIMEOUT,
    )

    return httpx.AsyncClient(
        headers=DEFAULT_HEADERS,
        limits=limits,
        timeout=timeout,
        follow_redirects=True,
    )


async def close_async_client() -> None:
    """Ferme le client async."""
    global _async_client
    if _async_client is not None:
        try:
            await _async_client.aclose()
            logger.debug("Closed async HTTP client")
        except Exception as e:
            logger.warning(f"Error closing async client: {e}")
        _async_client = None


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def sync_get(
    url: str,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: float | None = None,
    **kwargs,
) -> requests.Response:
    """
    Effectue une requête GET synchrone.

    Args:
        url: URL à requêter
        params: Paramètres de requête
        headers: Headers additionnels
        timeout: Timeout en secondes
        **kwargs: Arguments additionnels pour requests

    Returns:
        Response requests
    """
    session = get_sync_session()
    return session.get(
        url,
        params=params,
        headers=headers,
        timeout=timeout or DEFAULT_TIMEOUT,
        **kwargs,
    )


def sync_post(
    url: str,
    data: dict | None = None,
    json: dict | None = None,
    headers: dict | None = None,
    timeout: float | None = None,
    **kwargs,
) -> requests.Response:
    """
    Effectue une requête POST synchrone.

    Args:
        url: URL à requêter
        data: Données form-encoded
        json: Données JSON
        headers: Headers additionnels
        timeout: Timeout en secondes
        **kwargs: Arguments additionnels pour requests

    Returns:
        Response requests
    """
    session = get_sync_session()
    return session.post(
        url,
        data=data,
        json=json,
        headers=headers,
        timeout=timeout or DEFAULT_TIMEOUT,
        **kwargs,
    )


def sync_post_json(
    url: str,
    payload: dict,
    timeout: float | None = None,
) -> dict:
    """
    Effectue une requête POST JSON et retourne le JSON de réponse.

    Args:
        url: URL à requêter
        payload: Payload JSON
        timeout: Timeout en secondes

    Returns:
        Réponse JSON décodée

    Raises:
        requests.HTTPError: Si la requête échoue
        ValueError: Si la réponse n'est pas du JSON
    """
    response = sync_post(url, json=payload, timeout=timeout)
    response.raise_for_status()
    return response.json()


# ============================================================================
# ASYNC HELPER FUNCTIONS
# ============================================================================


async def async_get(
    url: str,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: float | None = None,
) -> Any:
    """
    Effectue une requête GET asynchrone.

    Args:
        url: URL à requêter
        params: Paramètres de requête
        headers: Headers additionnels
        timeout: Timeout en secondes

    Returns:
        Response httpx
    """
    client = get_async_client()
    return await client.get(
        url,
        params=params,
        headers=headers,
        timeout=timeout or DEFAULT_TIMEOUT,
    )


async def async_post(
    url: str,
    data: dict | None = None,
    json: dict | None = None,
    headers: dict | None = None,
    timeout: float | None = None,
) -> Any:
    """
    Effectue une requête POST asynchrone.

    Args:
        url: URL à requêter
        data: Données form-encoded
        json: Données JSON
        headers: Headers additionnels
        timeout: Timeout en secondes

    Returns:
        Response httpx
    """
    client = get_async_client()
    return await client.post(
        url,
        data=data,
        json=json,
        headers=headers,
        timeout=timeout or DEFAULT_TIMEOUT,
    )


async def async_post_json(
    url: str,
    payload: dict,
    timeout: float | None = None,
) -> dict:
    """
    Effectue une requête POST JSON async et retourne le JSON.

    Args:
        url: URL à requêter
        payload: Payload JSON
        timeout: Timeout en secondes

    Returns:
        Réponse JSON décodée
    """
    response = await async_post(url, json=payload, timeout=timeout)
    response.raise_for_status()
    return response.json()
