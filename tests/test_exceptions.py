"""
Tests pour le module aira.exceptions.
"""
import pytest

from aira.exceptions import (
    AIRAError,
    ValidationError,
    BinaryNotFoundError,
    InvalidAddressError,
    InvalidPIDError,
    InvalidURLError,
    InvalidPathError,
    ServiceError,
    SymexecServiceError,
    AIServiceError,
    LangflowError,
    GhidraError,
    FridaError,
    NetworkError,
    ConfigError,
    MissingConfigError,
    InvalidConfigError,
    SecurityError,
    SSRFError,
    PathTraversalError,
    RateLimitError,
    AnalysisError,
    BinaryParseError,
    YARAError,
)


class TestAIRAError:
    """Tests pour la classe de base AIRAError."""

    def test_default_message(self):
        exc = AIRAError()
        assert str(exc) == "An error occurred"
        assert exc.exit_code == 1

    def test_custom_message(self):
        exc = AIRAError("Custom error message")
        assert str(exc) == "Custom error message"

    def test_inheritance(self):
        exc = AIRAError("test")
        assert isinstance(exc, Exception)


class TestValidationErrors:
    """Tests pour les erreurs de validation (exit code 2)."""

    def test_validation_error_exit_code(self):
        exc = ValidationError("Invalid input")
        assert exc.exit_code == 2

    def test_binary_not_found_error(self):
        exc = BinaryNotFoundError("/path/to/binary.exe")
        assert "Binary file not found" in str(exc)
        assert "/path/to/binary.exe" in str(exc)
        assert exc.exit_code == 2

    def test_binary_not_found_error_no_path(self):
        exc = BinaryNotFoundError()
        assert "Binary file not found" in str(exc)

    def test_invalid_address_error(self):
        exc = InvalidAddressError("0xGGGG")
        assert "Invalid hexadecimal address" in str(exc)
        assert "0xGGGG" in str(exc)
        assert exc.exit_code == 2

    def test_invalid_pid_error(self):
        exc = InvalidPIDError("-1")
        assert "Invalid process ID" in str(exc)
        assert "-1" in str(exc)
        assert exc.exit_code == 2

    def test_invalid_url_error(self):
        exc = InvalidURLError("ftp://example.com", "Invalid scheme")
        assert "ftp://example.com" in str(exc)
        assert "Invalid scheme" in str(exc)
        assert exc.exit_code == 2

    def test_invalid_path_error(self):
        exc = InvalidPathError("/etc/passwd", "Outside allowed directory")
        assert "/etc/passwd" in str(exc)
        assert "Outside allowed directory" in str(exc)


class TestServiceErrors:
    """Tests pour les erreurs de service (exit code 1)."""

    def test_service_error_exit_code(self):
        exc = ServiceError("Service unavailable")
        assert exc.exit_code == 1

    def test_symexec_service_error(self):
        exc = SymexecServiceError("Timeout during exploration")
        assert "Symbolic execution failed" in str(exc)
        assert "Timeout" in str(exc)

    def test_ai_service_error_with_provider(self):
        exc = AIServiceError(provider="openai", detail="Rate limit exceeded")
        assert "openai" in str(exc)
        assert "Rate limit exceeded" in str(exc)

    def test_ai_service_error_without_provider(self):
        exc = AIServiceError(detail="Connection refused")
        assert "AI service error" in str(exc)
        assert "Connection refused" in str(exc)

    def test_langflow_error(self):
        exc = LangflowError("Flow not found")
        assert "LangFlow error" in str(exc)
        assert "Flow not found" in str(exc)

    def test_ghidra_error(self):
        exc = GhidraError("Server not responding")
        assert "Ghidra error" in str(exc)

    def test_frida_error(self):
        exc = FridaError("Failed to attach to process")
        assert "Frida error" in str(exc)

    def test_network_error(self):
        exc = NetworkError("Connection timed out")
        assert "Network error" in str(exc)
        assert "Connection timed out" in str(exc)


class TestConfigErrors:
    """Tests pour les erreurs de configuration."""

    def test_config_error_exit_code(self):
        exc = ConfigError("Invalid configuration")
        assert exc.exit_code == 1

    def test_missing_config_error(self):
        exc = MissingConfigError("OPENAI_API_KEY")
        assert "Missing configuration" in str(exc)
        assert "OPENAI_API_KEY" in str(exc)

    def test_invalid_config_error(self):
        exc = InvalidConfigError("temperature", "must be between 0 and 2")
        assert "Invalid configuration" in str(exc)
        assert "temperature" in str(exc)
        assert "must be between 0 and 2" in str(exc)


class TestSecurityErrors:
    """Tests pour les erreurs de sécurité."""

    def test_security_error_exit_code(self):
        exc = SecurityError("Security violation")
        assert exc.exit_code == 1

    def test_ssrf_error(self):
        exc = SSRFError("http://localhost:8080")
        assert "SSRF attempt blocked" in str(exc)
        assert "http://localhost:8080" in str(exc)

    def test_path_traversal_error(self):
        exc = PathTraversalError("../../etc/passwd")
        assert "Path traversal blocked" in str(exc)
        assert "../../etc/passwd" in str(exc)

    def test_rate_limit_error(self):
        exc = RateLimitError("10 requests per minute")
        assert "Rate limit exceeded" in str(exc)


class TestAnalysisErrors:
    """Tests pour les erreurs d'analyse."""

    def test_analysis_error_exit_code(self):
        exc = AnalysisError("Analysis failed")
        assert exc.exit_code == 1

    def test_binary_parse_error(self):
        exc = BinaryParseError("/path/to/file.exe", "Invalid PE header")
        assert "Failed to parse binary" in str(exc)
        assert "/path/to/file.exe" in str(exc)
        assert "Invalid PE header" in str(exc)

    def test_yara_error(self):
        exc = YARAError("Syntax error in rule")
        assert "YARA error" in str(exc)
        assert "Syntax error" in str(exc)


class TestExceptionHierarchy:
    """Tests pour la hiérarchie des exceptions."""

    def test_validation_inherits_from_aira(self):
        assert issubclass(ValidationError, AIRAError)

    def test_service_inherits_from_aira(self):
        assert issubclass(ServiceError, AIRAError)

    def test_config_inherits_from_aira(self):
        assert issubclass(ConfigError, AIRAError)

    def test_security_inherits_from_aira(self):
        assert issubclass(SecurityError, AIRAError)

    def test_binary_not_found_inherits_from_validation(self):
        assert issubclass(BinaryNotFoundError, ValidationError)

    def test_ssrf_inherits_from_security(self):
        assert issubclass(SSRFError, SecurityError)

    def test_langflow_inherits_from_service(self):
        assert issubclass(LangflowError, ServiceError)


class TestExceptionCatching:
    """Tests pour vérifier que les exceptions sont bien catchées."""

    def test_catch_aira_error_catches_validation(self):
        try:
            raise BinaryNotFoundError("/test")
        except AIRAError as e:
            assert "Binary" in str(e)

    def test_catch_aira_error_catches_service(self):
        try:
            raise LangflowError("test")
        except AIRAError as e:
            assert "LangFlow" in str(e)

    def test_catch_validation_doesnt_catch_service(self):
        with pytest.raises(ServiceError):
            try:
                raise SymexecServiceError("test")
            except ValidationError:
                pass  # Should not be caught
