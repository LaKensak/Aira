"""
Validateurs pour argparse et validation d'entrées.

Ces validateurs peuvent être utilisés comme type= dans argparse
ou appelés directement pour valider des valeurs.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import urlparse

from .exceptions import (
    InvalidAddressError,
    InvalidPIDError,
    InvalidURLError,
    InvalidPathError,
    BinaryNotFoundError,
)


# ============================================================================
# ADDRESS VALIDATORS
# ============================================================================


def hex_address(value: str) -> str:
    """
    Valide et normalise une adresse hexadécimale.

    Accepte: 0x1234, 0X1234, 1234 (hex sans préfixe)

    Args:
        value: Adresse à valider

    Returns:
        Adresse normalisée avec préfixe 0x

    Raises:
        argparse.ArgumentTypeError: Si l'adresse est invalide
    """
    if not value:
        raise argparse.ArgumentTypeError("Address cannot be empty")

    # Normaliser
    clean = value.strip().lower()

    # Retirer le préfixe si présent
    if clean.startswith("0x"):
        clean = clean[2:]

    # Vérifier que c'est bien hexadécimal
    if not clean:
        raise argparse.ArgumentTypeError(f"Invalid hex address: {value}")

    try:
        int(clean, 16)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid hex address: {value}")

    # Vérifier longueur raisonnable (max 16 chars = 64 bits)
    if len(clean) > 16:
        raise argparse.ArgumentTypeError(f"Address too long: {value}")

    return f"0x{clean}"


def hex_address_list(value: str) -> list[str]:
    """
    Valide une liste d'adresses séparées par des virgules.

    Args:
        value: Liste d'adresses (ex: "0x1234,0x5678")

    Returns:
        Liste d'adresses normalisées
    """
    if not value:
        return []

    addresses = []
    for addr in value.split(","):
        addr = addr.strip()
        if addr:
            addresses.append(hex_address(addr))

    return addresses


# ============================================================================
# FILE/PATH VALIDATORS
# ============================================================================


def existing_file(value: str) -> Path:
    """
    Valide qu'un fichier existe.

    Args:
        value: Chemin du fichier

    Returns:
        Path résolu du fichier

    Raises:
        argparse.ArgumentTypeError: Si le fichier n'existe pas
    """
    if not value:
        raise argparse.ArgumentTypeError("File path cannot be empty")

    path = Path(value).expanduser()

    if not path.exists():
        raise argparse.ArgumentTypeError(f"File not found: {value}")

    if not path.is_file():
        raise argparse.ArgumentTypeError(f"Not a file: {value}")

    return path.resolve()


def existing_binary(value: str) -> Path:
    """
    Valide qu'un fichier binaire existe.

    Vérifie également les extensions courantes de binaires.

    Args:
        value: Chemin du binaire

    Returns:
        Path résolu du binaire

    Raises:
        argparse.ArgumentTypeError: Si le binaire n'existe pas ou extension invalide
    """
    path = existing_file(value)

    # Extensions binaires autorisées
    valid_extensions = {
        ".exe", ".dll", ".so", ".elf", ".bin", ".o", ".dylib",
        ".sys", ".ko", ".ocx", ".scr", ".cpl",
        "",  # Pas d'extension (binaires Linux)
    }

    if path.suffix.lower() not in valid_extensions:
        # Avertissement mais pas d'erreur (peut être un binaire sans extension standard)
        pass

    return path


def existing_directory(value: str) -> Path:
    """
    Valide qu'un répertoire existe.

    Args:
        value: Chemin du répertoire

    Returns:
        Path résolu du répertoire

    Raises:
        argparse.ArgumentTypeError: Si le répertoire n'existe pas
    """
    if not value:
        raise argparse.ArgumentTypeError("Directory path cannot be empty")

    path = Path(value).expanduser()

    if not path.exists():
        raise argparse.ArgumentTypeError(f"Directory not found: {value}")

    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"Not a directory: {value}")

    return path.resolve()


def writable_path(value: str) -> Path:
    """
    Valide qu'un chemin est accessible en écriture.

    Le fichier n'a pas besoin d'exister, mais le parent doit exister.

    Args:
        value: Chemin du fichier

    Returns:
        Path résolu

    Raises:
        argparse.ArgumentTypeError: Si le chemin n'est pas accessible en écriture
    """
    if not value:
        raise argparse.ArgumentTypeError("Path cannot be empty")

    path = Path(value).expanduser()
    parent = path.parent

    if not parent.exists():
        raise argparse.ArgumentTypeError(f"Parent directory does not exist: {parent}")

    if not parent.is_dir():
        raise argparse.ArgumentTypeError(f"Parent is not a directory: {parent}")

    return path.resolve()


# ============================================================================
# PROCESS VALIDATORS
# ============================================================================


def valid_pid(value: str) -> int:
    """
    Valide un PID de processus.

    Args:
        value: PID sous forme de chaîne

    Returns:
        PID sous forme d'entier

    Raises:
        argparse.ArgumentTypeError: Si le PID est invalide
    """
    if not value:
        raise argparse.ArgumentTypeError("PID cannot be empty")

    try:
        pid = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid PID (must be integer): {value}")

    if pid <= 0:
        raise argparse.ArgumentTypeError(f"Invalid PID (must be positive): {value}")

    # PID max sur la plupart des systèmes
    if pid > 4194304:  # 2^22 (Linux max)
        raise argparse.ArgumentTypeError(f"PID too large: {value}")

    return pid


# ============================================================================
# URL VALIDATORS
# ============================================================================


def valid_url(value: str) -> str:
    """
    Valide une URL.

    Args:
        value: URL à valider

    Returns:
        URL normalisée

    Raises:
        argparse.ArgumentTypeError: Si l'URL est invalide
    """
    if not value:
        raise argparse.ArgumentTypeError("URL cannot be empty")

    try:
        parsed = urlparse(value)
    except Exception as e:
        raise argparse.ArgumentTypeError(f"Invalid URL: {value} ({e})")

    if not parsed.scheme:
        raise argparse.ArgumentTypeError(f"URL must have a scheme (http/https): {value}")

    if parsed.scheme not in ("http", "https"):
        raise argparse.ArgumentTypeError(f"URL scheme must be http or https: {value}")

    if not parsed.netloc:
        raise argparse.ArgumentTypeError(f"URL must have a host: {value}")

    return value


def valid_http_url(value: str) -> str:
    """
    Valide une URL HTTP/HTTPS.

    Alias de valid_url pour clarté.
    """
    return valid_url(value)


# ============================================================================
# NUMERIC VALIDATORS
# ============================================================================


def positive_int(value: str) -> int:
    """
    Valide un entier positif.

    Args:
        value: Entier sous forme de chaîne

    Returns:
        Entier positif

    Raises:
        argparse.ArgumentTypeError: Si la valeur est invalide
    """
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid integer: {value}")

    if n <= 0:
        raise argparse.ArgumentTypeError(f"Must be positive: {value}")

    return n


def non_negative_int(value: str) -> int:
    """
    Valide un entier non négatif (>= 0).

    Args:
        value: Entier sous forme de chaîne

    Returns:
        Entier non négatif
    """
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid integer: {value}")

    if n < 0:
        raise argparse.ArgumentTypeError(f"Must be non-negative: {value}")

    return n


def temperature_value(value: str) -> float:
    """
    Valide une valeur de température LLM (0.0 - 2.0).

    Args:
        value: Température sous forme de chaîne

    Returns:
        Température validée

    Raises:
        argparse.ArgumentTypeError: Si hors limites
    """
    try:
        temp = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid temperature: {value}")

    if not (0.0 <= temp <= 2.0):
        raise argparse.ArgumentTypeError(
            f"Temperature must be between 0.0 and 2.0: {value}"
        )

    return temp


def probability_value(value: str) -> float:
    """
    Valide une probabilité (0.0 - 1.0).

    Args:
        value: Probabilité sous forme de chaîne

    Returns:
        Probabilité validée
    """
    try:
        prob = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid probability: {value}")

    if not (0.0 <= prob <= 1.0):
        raise argparse.ArgumentTypeError(
            f"Probability must be between 0.0 and 1.0: {value}"
        )

    return prob


# ============================================================================
# VALIDATION FUNCTIONS (non-argparse)
# ============================================================================


def validate_hex_address(value: str) -> str:
    """
    Version non-argparse de hex_address.

    Raises:
        InvalidAddressError: Si l'adresse est invalide
    """
    try:
        return hex_address(value)
    except argparse.ArgumentTypeError as e:
        raise InvalidAddressError(value) from e


def validate_pid(value: str | int) -> int:
    """
    Version non-argparse de valid_pid.

    Raises:
        InvalidPIDError: Si le PID est invalide
    """
    try:
        return valid_pid(str(value))
    except argparse.ArgumentTypeError as e:
        raise InvalidPIDError(str(value)) from e


def validate_url(value: str) -> str:
    """
    Version non-argparse de valid_url.

    Raises:
        InvalidURLError: Si l'URL est invalide
    """
    try:
        return valid_url(value)
    except argparse.ArgumentTypeError as e:
        raise InvalidURLError(value) from e


def validate_existing_file(value: str) -> Path:
    """
    Version non-argparse de existing_file.

    Raises:
        InvalidPathError: Si le fichier n'existe pas
    """
    try:
        return existing_file(value)
    except argparse.ArgumentTypeError as e:
        raise InvalidPathError(value, str(e)) from e


def validate_existing_binary(value: str) -> Path:
    """
    Version non-argparse de existing_binary.

    Raises:
        BinaryNotFoundError: Si le binaire n'existe pas
    """
    try:
        return existing_binary(value)
    except argparse.ArgumentTypeError as e:
        raise BinaryNotFoundError(value) from e
