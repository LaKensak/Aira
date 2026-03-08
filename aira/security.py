"""
Fonctions de sécurité pour AIRA.

- Protection SSRF (Server-Side Request Forgery)
- Validation et sanitisation des chemins
- Validation des URLs
"""
from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path
from urllib.parse import urlparse

from .exceptions import SSRFError, PathTraversalError, InvalidURLError
from .logging_config import get_logger

logger = get_logger(__name__)


# ============================================================================
# SSRF PROTECTION
# ============================================================================

# Plages d'IP privées/locales à bloquer
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
]

# Hostnames locaux à bloquer
LOCAL_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "local",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}

# Schémas autorisés
ALLOWED_SCHEMES = {"http", "https"}


def is_private_ip(ip: str) -> bool:
    """
    Vérifie si une IP est privée ou locale.

    Args:
        ip: Adresse IP sous forme de chaîne

    Returns:
        True si l'IP est privée/locale
    """
    try:
        addr = ipaddress.ip_address(ip)
        for network in PRIVATE_IP_RANGES:
            if addr in network:
                return True
        return False
    except ValueError:
        # Pas une IP valide
        return False


def resolve_hostname(hostname: str) -> list[str]:
    """
    Résout un hostname en adresses IP.

    Args:
        hostname: Nom d'hôte à résoudre

    Returns:
        Liste d'adresses IP

    Raises:
        SSRFError: Si la résolution échoue
    """
    try:
        # getaddrinfo retourne une liste de tuples (family, type, proto, canonname, sockaddr)
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        ips = []
        for result in results:
            sockaddr = result[4]
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except socket.gaierror as e:
        logger.warning(f"Failed to resolve hostname {hostname}: {e}")
        return []


def validate_url_ssrf(
    url: str,
    allowed_hosts: list[str] | None = None,
    allow_private: bool = False,
    resolve_dns: bool = True,
) -> str:
    """
    Valide une URL contre les attaques SSRF.

    Args:
        url: URL à valider
        allowed_hosts: Liste optionnelle de hosts autorisés
        allow_private: Autoriser les IPs privées (défaut False)
        resolve_dns: Résoudre le DNS pour vérifier l'IP (défaut True)

    Returns:
        URL validée

    Raises:
        SSRFError: Si l'URL est dangereuse
        InvalidURLError: Si l'URL est malformée
    """
    if not url:
        raise InvalidURLError(url, "URL cannot be empty")

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise InvalidURLError(url, str(e))

    # Vérifier le schéma
    if not parsed.scheme:
        raise InvalidURLError(url, "Missing scheme (http/https)")

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise SSRFError(f"Scheme not allowed: {parsed.scheme}")

    # Vérifier le hostname
    hostname = parsed.hostname
    if not hostname:
        raise InvalidURLError(url, "Missing hostname")

    # Vérifier contre les hostnames locaux connus
    if hostname.lower() in LOCAL_HOSTNAMES:
        if not allow_private:
            raise SSRFError(f"Local hostname not allowed: {hostname}")

    # Vérifier la whitelist si fournie
    if allowed_hosts:
        if hostname.lower() not in [h.lower() for h in allowed_hosts]:
            raise SSRFError(f"Host not in allowed list: {hostname}")

    # Vérifier si c'est directement une IP
    if is_private_ip(hostname):
        if not allow_private:
            raise SSRFError(f"Private IP not allowed: {hostname}")

    # Résoudre le DNS et vérifier les IPs
    if resolve_dns and not allow_private:
        ips = resolve_hostname(hostname)
        for ip in ips:
            if is_private_ip(ip):
                raise SSRFError(f"Host resolves to private IP: {hostname} -> {ip}")

    logger.debug(f"URL validated: {url}")
    return url


def validate_service_url(url: str, service_name: str = "service") -> str:
    """
    Valide une URL de service interne.

    Pour les services internes (localhost autorisé).

    Args:
        url: URL du service
        service_name: Nom du service (pour les logs)

    Returns:
        URL validée
    """
    if not url:
        raise InvalidURLError(url, f"{service_name} URL cannot be empty")

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise InvalidURLError(url, str(e))

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise InvalidURLError(url, f"Invalid scheme for {service_name}")

    if not parsed.hostname:
        raise InvalidURLError(url, f"Missing hostname for {service_name}")

    logger.debug(f"Service URL validated: {service_name} = {url}")
    return url


# ============================================================================
# PATH VALIDATION
# ============================================================================

# Patterns dangereux dans les chemins
DANGEROUS_PATH_PATTERNS = [
    r"\.\.",              # Parent directory
    r"^/etc/",            # Linux config
    r"^/proc/",           # Linux proc
    r"^/sys/",            # Linux sys
    r"^/dev/",            # Devices
    r"^C:\\Windows\\",    # Windows system (case insensitive handled separately)
    r"^C:\\Program Files",
    r"\\\\",              # UNC paths
    r"^~",                # Home expansion non résolue
]


def is_path_safe(path: str | Path, base_dir: Path | None = None) -> bool:
    """
    Vérifie si un chemin est sûr (pas de traversal).

    Args:
        path: Chemin à vérifier
        base_dir: Répertoire de base optionnel

    Returns:
        True si le chemin est sûr
    """
    try:
        path_obj = Path(path).resolve()

        # Vérifier les patterns dangereux
        path_str = str(path)
        for pattern in DANGEROUS_PATH_PATTERNS:
            if re.search(pattern, path_str, re.IGNORECASE):
                return False

        # Si un base_dir est fourni, vérifier que le chemin est dedans
        if base_dir:
            base_resolved = Path(base_dir).resolve()
            try:
                path_obj.relative_to(base_resolved)
            except ValueError:
                return False

        return True
    except Exception:
        return False


def sanitize_path(
    path: str | Path,
    base_dir: Path,
    must_exist: bool = False,
) -> Path:
    """
    Sanitise un chemin et vérifie qu'il est dans le répertoire de base.

    Args:
        path: Chemin à sanitiser
        base_dir: Répertoire de base autorisé
        must_exist: Le fichier doit exister

    Returns:
        Chemin résolu et validé

    Raises:
        PathTraversalError: Si path traversal détecté
        FileNotFoundError: Si le fichier n'existe pas (et must_exist=True)
    """
    if not path:
        raise PathTraversalError("Empty path")

    try:
        # Résoudre les chemins
        path_obj = Path(path)
        base_resolved = Path(base_dir).resolve()

        # Joindre si le chemin est relatif
        if not path_obj.is_absolute():
            full_path = (base_resolved / path_obj).resolve()
        else:
            full_path = path_obj.resolve()

        # Vérifier que le chemin est dans base_dir
        try:
            full_path.relative_to(base_resolved)
        except ValueError:
            logger.warning(f"Path traversal attempt: {path} (base: {base_dir})")
            raise PathTraversalError(str(path))

        # Vérifier l'existence si demandé
        if must_exist and not full_path.exists():
            from .exceptions import FileNotFoundError as AIRAFileNotFoundError
            raise AIRAFileNotFoundError(str(path))

        logger.debug(f"Path sanitized: {path} -> {full_path}")
        return full_path

    except PathTraversalError:
        raise
    except Exception as e:
        logger.error(f"Path sanitization failed: {path} - {e}")
        raise PathTraversalError(str(path))


def sanitize_filename(filename: str) -> str:
    """
    Sanitise un nom de fichier (sans chemin).

    Args:
        filename: Nom de fichier à sanitiser

    Returns:
        Nom de fichier sûr
    """
    if not filename:
        return "unnamed"

    # Garder seulement le nom de base
    filename = Path(filename).name

    # Remplacer les caractères dangereux
    # Autorise: lettres, chiffres, -, _, .
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)

    # Éviter les noms spéciaux Windows
    reserved = {"CON", "PRN", "AUX", "NUL", "COM1", "LPT1"}
    name_without_ext = Path(safe).stem.upper()
    if name_without_ext in reserved:
        safe = f"_{safe}"

    # Éviter les fichiers cachés accidentels
    if safe.startswith("."):
        safe = f"_{safe}"

    # Limiter la longueur
    if len(safe) > 200:
        stem = Path(safe).stem[:190]
        suffix = Path(safe).suffix
        safe = f"{stem}{suffix}"

    return safe or "unnamed"


# ============================================================================
# INPUT SANITIZATION
# ============================================================================


def sanitize_command_arg(arg: str) -> str:
    """
    Sanitise un argument de commande contre l'injection.

    Args:
        arg: Argument à sanitiser

    Returns:
        Argument sûr

    Note:
        Préférer l'utilisation de subprocess avec liste d'arguments
        plutôt que de construire des commandes shell.
    """
    if not arg:
        return ""

    # Échapper les caractères shell dangereux
    dangerous_chars = ['`', '$', '|', '&', ';', '\n', '\r', '>', '<', '(', ')']
    result = arg
    for char in dangerous_chars:
        result = result.replace(char, "")

    return result


def validate_yara_rule_path(path: str | Path, rules_dir: Path) -> Path:
    """
    Valide un chemin de règle YARA.

    Args:
        path: Chemin de la règle
        rules_dir: Répertoire des règles autorisé

    Returns:
        Chemin validé
    """
    validated = sanitize_path(path, rules_dir, must_exist=True)

    # Vérifier l'extension
    if validated.suffix.lower() not in (".yar", ".yara"):
        raise PathTraversalError(f"Invalid YARA rule extension: {path}")

    return validated
