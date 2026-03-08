"""
Configuration centralisée du logging pour AIRA.

Usage:
    from aira.logging_config import setup_logging, get_logger

    # Au démarrage de l'application
    setup_logging(level="DEBUG", log_file=Path("aira.log"))

    # Dans chaque module
    logger = get_logger(__name__)
    logger.info("Message")
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TextIO


# Format par défaut
DEFAULT_FORMAT = "[%(levelname)s] %(name)s: %(message)s"
DETAILED_FORMAT = "%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s"
JSON_FORMAT = '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}'


class ColoredFormatter(logging.Formatter):
    """Formatter avec couleurs pour la console."""

    # Codes ANSI
    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Vert
        "WARNING": "\033[33m",   # Jaune
        "ERROR": "\033[31m",     # Rouge
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def __init__(self, fmt: str | None = None, use_colors: bool = True):
        super().__init__(fmt or DEFAULT_FORMAT)
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        if self.use_colors and record.levelname in self.COLORS:
            record.levelname = (
                f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
            )
        return super().format(record)


def setup_logging(
    level: str = "INFO",
    log_file: Path | str | None = None,
    stream: TextIO | None = None,
    format_style: str = "default",
    use_colors: bool = True,
) -> logging.Logger:
    """
    Configure le logging global pour AIRA.

    Args:
        level: Niveau de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Chemin optionnel vers un fichier de log
        stream: Stream de sortie (par défaut stderr)
        format_style: Style de format ("default", "detailed", "json")
        use_colors: Utiliser les couleurs dans la console

    Returns:
        Logger racine configuré
    """
    # Sélectionner le format
    if format_style == "detailed":
        fmt = DETAILED_FORMAT
    elif format_style == "json":
        fmt = JSON_FORMAT
    else:
        fmt = DEFAULT_FORMAT

    # Logger racine AIRA
    logger = logging.getLogger("aira")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Supprimer les handlers existants
    logger.handlers.clear()

    # Handler console
    console_handler = logging.StreamHandler(stream or sys.stderr)
    console_handler.setLevel(logging.DEBUG)

    # Utiliser le formatter coloré pour la console
    if format_style != "json" and use_colors:
        console_handler.setFormatter(ColoredFormatter(fmt, use_colors=True))
    else:
        console_handler.setFormatter(logging.Formatter(fmt))

    logger.addHandler(console_handler)

    # Handler fichier (optionnel)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        # Pas de couleurs dans les fichiers
        file_handler.setFormatter(logging.Formatter(DETAILED_FORMAT))
        logger.addHandler(file_handler)

    # Ne pas propager au root logger
    logger.propagate = False

    return logger


def get_logger(name: str = "aira") -> logging.Logger:
    """
    Obtient un logger pour un module.

    Args:
        name: Nom du logger (utiliser __name__ pour le module courant)

    Returns:
        Logger configuré

    Usage:
        logger = get_logger(__name__)
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")
    """
    # Si le nom ne commence pas par "aira", le préfixer
    if not name.startswith("aira"):
        name = f"aira.{name}"

    return logging.getLogger(name)


def set_level(level: str) -> None:
    """
    Change le niveau de log dynamiquement.

    Args:
        level: Nouveau niveau (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    logger = logging.getLogger("aira")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))


def add_file_handler(log_file: Path | str) -> logging.FileHandler:
    """
    Ajoute un handler de fichier au logger existant.

    Args:
        log_file: Chemin du fichier de log

    Returns:
        Handler créé
    """
    logger = logging.getLogger("aira")
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(DETAILED_FORMAT))
    logger.addHandler(handler)

    return handler


def remove_file_handlers() -> None:
    """Supprime tous les handlers de fichier."""
    logger = logging.getLogger("aira")
    logger.handlers = [
        h for h in logger.handlers
        if not isinstance(h, logging.FileHandler)
    ]


# ============================================================================
# CONTEXT MANAGERS
# ============================================================================


class LogContext:
    """Context manager pour logging temporaire avec niveau différent."""

    def __init__(self, level: str):
        self.level = level
        self.original_level = None

    def __enter__(self):
        logger = logging.getLogger("aira")
        self.original_level = logger.level
        logger.setLevel(getattr(logging, self.level.upper(), logging.INFO))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        logger = logging.getLogger("aira")
        if self.original_level is not None:
            logger.setLevel(self.original_level)
        return False


def debug_context():
    """Context manager pour activer temporairement le mode DEBUG."""
    return LogContext("DEBUG")


# ============================================================================
# HELPERS
# ============================================================================


def log_exception(logger: logging.Logger, exc: Exception, message: str = "") -> None:
    """
    Log une exception avec stack trace en mode debug.

    Args:
        logger: Logger à utiliser
        exc: Exception à logger
        message: Message optionnel
    """
    if message:
        logger.error(f"{message}: {exc}")
    else:
        logger.error(str(exc))

    # Stack trace en mode debug
    logger.debug("Exception details:", exc_info=exc)


def log_request(
    logger: logging.Logger,
    method: str,
    url: str,
    status: int | None = None,
    duration_ms: float | None = None,
) -> None:
    """
    Log une requête HTTP de manière structurée.

    Args:
        logger: Logger à utiliser
        method: Méthode HTTP (GET, POST, etc.)
        url: URL de la requête
        status: Code de statut de la réponse
        duration_ms: Durée en millisecondes
    """
    parts = [f"{method} {url}"]
    if status is not None:
        parts.append(f"status={status}")
    if duration_ms is not None:
        parts.append(f"duration={duration_ms:.0f}ms")

    logger.debug(" ".join(parts))
