"""
Hiérarchie d'exceptions personnalisées pour AIRA.

Codes de sortie POSIX:
- 0: Succès
- 1: Erreur d'exécution (service, IO, runtime)
- 2: Mauvaise invocation (argument invalide, fichier manquant)
"""
from __future__ import annotations


class AIRAError(Exception):
    """Exception de base pour toutes les erreurs AIRA."""

    exit_code: int = 1
    message: str = "An error occurred"

    def __init__(self, message: str | None = None, *args, **kwargs):
        self.message = message or self.message
        super().__init__(self.message, *args, **kwargs)


# ============================================================================
# VALIDATION ERRORS (Exit code 2)
# ============================================================================


class ValidationError(AIRAError):
    """Erreur de validation des entrées utilisateur."""

    exit_code = 2
    message = "Validation error"


class BinaryNotFoundError(ValidationError):
    """Fichier binaire introuvable."""

    message = "Binary file not found"

    def __init__(self, path: str | None = None):
        msg = f"Binary file not found: {path}" if path else self.message
        super().__init__(msg)


class InvalidAddressError(ValidationError):
    """Format d'adresse hexadécimale invalide."""

    message = "Invalid hexadecimal address"

    def __init__(self, address: str | None = None):
        msg = f"Invalid hexadecimal address: {address}" if address else self.message
        super().__init__(msg)


class InvalidPIDError(ValidationError):
    """PID de processus invalide."""

    message = "Invalid process ID"

    def __init__(self, pid: str | None = None):
        msg = f"Invalid process ID: {pid}" if pid else self.message
        super().__init__(msg)


class InvalidURLError(ValidationError):
    """URL invalide ou non autorisée."""

    message = "Invalid or disallowed URL"

    def __init__(self, url: str | None = None, reason: str | None = None):
        if url and reason:
            msg = f"Invalid URL '{url}': {reason}"
        elif url:
            msg = f"Invalid URL: {url}"
        else:
            msg = self.message
        super().__init__(msg)


class InvalidPathError(ValidationError):
    """Chemin de fichier invalide ou non autorisé."""

    message = "Invalid or disallowed path"

    def __init__(self, path: str | None = None, reason: str | None = None):
        if path and reason:
            msg = f"Invalid path '{path}': {reason}"
        elif path:
            msg = f"Invalid path: {path}"
        else:
            msg = self.message
        super().__init__(msg)


class FileNotFoundError(ValidationError):
    """Fichier introuvable."""

    message = "File not found"

    def __init__(self, path: str | None = None):
        msg = f"File not found: {path}" if path else self.message
        super().__init__(msg)


class InvalidParameterError(ValidationError):
    """Paramètre invalide."""

    message = "Invalid parameter"

    def __init__(self, param: str | None = None, reason: str | None = None):
        if param and reason:
            msg = f"Invalid parameter '{param}': {reason}"
        elif param:
            msg = f"Invalid parameter: {param}"
        else:
            msg = self.message
        super().__init__(msg)


# ============================================================================
# SERVICE ERRORS (Exit code 1)
# ============================================================================


class ServiceError(AIRAError):
    """Erreur lors de l'appel à un service externe."""

    exit_code = 1
    message = "Service error"


class SymexecServiceError(ServiceError):
    """Erreur du service d'exécution symbolique."""

    message = "Symbolic execution service error"

    def __init__(self, detail: str | None = None):
        msg = f"Symbolic execution failed: {detail}" if detail else self.message
        super().__init__(msg)


class AIServiceError(ServiceError):
    """Erreur du service IA."""

    message = "AI service error"

    def __init__(self, provider: str | None = None, detail: str | None = None):
        if provider and detail:
            msg = f"AI service error ({provider}): {detail}"
        elif detail:
            msg = f"AI service error: {detail}"
        else:
            msg = self.message
        super().__init__(msg)


class LangflowError(ServiceError):
    """Erreur spécifique à LangFlow."""

    message = "LangFlow error"

    def __init__(self, detail: str | None = None):
        msg = f"LangFlow error: {detail}" if detail else self.message
        super().__init__(msg)


class GhidraError(ServiceError):
    """Erreur de communication avec Ghidra."""

    message = "Ghidra service error"

    def __init__(self, detail: str | None = None):
        msg = f"Ghidra error: {detail}" if detail else self.message
        super().__init__(msg)


class FridaError(ServiceError):
    """Erreur Frida (injection, attach)."""

    message = "Frida error"

    def __init__(self, detail: str | None = None):
        msg = f"Frida error: {detail}" if detail else self.message
        super().__init__(msg)


class NetworkError(ServiceError):
    """Erreur réseau (timeout, connexion refusée)."""

    message = "Network error"

    def __init__(self, detail: str | None = None):
        msg = f"Network error: {detail}" if detail else self.message
        super().__init__(msg)


# ============================================================================
# CONFIG ERRORS (Exit code 1)
# ============================================================================


class ConfigError(AIRAError):
    """Erreur de configuration."""

    exit_code = 1
    message = "Configuration error"


class MissingConfigError(ConfigError):
    """Configuration manquante."""

    message = "Missing configuration"

    def __init__(self, key: str | None = None):
        msg = f"Missing configuration: {key}" if key else self.message
        super().__init__(msg)


class InvalidConfigError(ConfigError):
    """Configuration invalide."""

    message = "Invalid configuration"

    def __init__(self, key: str | None = None, reason: str | None = None):
        if key and reason:
            msg = f"Invalid configuration '{key}': {reason}"
        elif key:
            msg = f"Invalid configuration: {key}"
        else:
            msg = self.message
        super().__init__(msg)


# ============================================================================
# SECURITY ERRORS (Exit code 1)
# ============================================================================


class SecurityError(AIRAError):
    """Erreur de sécurité."""

    exit_code = 1
    message = "Security error"


class SSRFError(SecurityError):
    """Tentative de SSRF détectée."""

    message = "SSRF attempt blocked"

    def __init__(self, url: str | None = None):
        msg = f"SSRF attempt blocked: {url}" if url else self.message
        super().__init__(msg)


class PathTraversalError(SecurityError):
    """Tentative de path traversal détectée."""

    message = "Path traversal attempt blocked"

    def __init__(self, path: str | None = None):
        msg = f"Path traversal blocked: {path}" if path else self.message
        super().__init__(msg)


class RateLimitError(SecurityError):
    """Limite de requêtes atteinte."""

    message = "Rate limit exceeded"

    def __init__(self, limit: str | None = None):
        msg = f"Rate limit exceeded: {limit}" if limit else self.message
        super().__init__(msg)


# ============================================================================
# ANALYSIS ERRORS (Exit code 1)
# ============================================================================


class AnalysisError(AIRAError):
    """Erreur lors de l'analyse."""

    exit_code = 1
    message = "Analysis error"


class BinaryParseError(AnalysisError):
    """Impossible de parser le binaire."""

    message = "Failed to parse binary"

    def __init__(self, path: str | None = None, detail: str | None = None):
        if path and detail:
            msg = f"Failed to parse binary '{path}': {detail}"
        elif path:
            msg = f"Failed to parse binary: {path}"
        else:
            msg = self.message
        super().__init__(msg)


class YARAError(AnalysisError):
    """Erreur YARA (règles, scan)."""

    message = "YARA error"

    def __init__(self, detail: str | None = None):
        msg = f"YARA error: {detail}" if detail else self.message
        super().__init__(msg)
