"""
Tests pour le module aira.security.
"""
import pytest
from pathlib import Path

from aira.security import (
    is_private_ip,
    validate_url_ssrf,
    validate_service_url,
    is_path_safe,
    sanitize_path,
    sanitize_filename,
    sanitize_command_arg,
)
from aira.exceptions import SSRFError, PathTraversalError, InvalidURLError


class TestIsPrivateIp:
    """Tests pour is_private_ip."""

    def test_localhost_ipv4(self):
        assert is_private_ip("127.0.0.1") is True
        assert is_private_ip("127.0.0.255") is True

    def test_localhost_ipv6(self):
        assert is_private_ip("::1") is True

    def test_private_class_a(self):
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.255") is True

    def test_private_class_b(self):
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.255") is True

    def test_private_class_c(self):
        assert is_private_ip("192.168.0.1") is True
        assert is_private_ip("192.168.255.255") is True

    def test_link_local(self):
        assert is_private_ip("169.254.1.1") is True

    def test_public_ip(self):
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False
        assert is_private_ip("142.250.80.46") is False

    def test_invalid_ip(self):
        assert is_private_ip("not-an-ip") is False
        assert is_private_ip("") is False


class TestValidateUrlSsrf:
    """Tests pour validate_url_ssrf."""

    def test_valid_public_url(self):
        url = "https://example.com/api"
        # Note: This might fail if DNS resolution is blocked
        # We test with allow_private=True to skip DNS checks
        result = validate_url_ssrf(url, resolve_dns=False)
        assert result == url

    def test_localhost_blocked(self):
        with pytest.raises(SSRFError, match="Local hostname"):
            validate_url_ssrf("http://localhost:8080", allow_private=False)

    def test_localhost_allowed(self):
        result = validate_url_ssrf("http://localhost:8080", allow_private=True)
        assert result == "http://localhost:8080"

    def test_127_0_0_1_blocked(self):
        with pytest.raises(SSRFError):
            validate_url_ssrf("http://127.0.0.1:8080", allow_private=False)

    def test_private_ip_blocked(self):
        with pytest.raises(SSRFError, match="Private IP"):
            validate_url_ssrf("http://192.168.1.1", allow_private=False)

    def test_invalid_scheme(self):
        with pytest.raises(SSRFError, match="Scheme not allowed"):
            validate_url_ssrf("ftp://example.com")

    def test_file_scheme_blocked(self):
        with pytest.raises(SSRFError, match="Scheme not allowed"):
            validate_url_ssrf("file:///etc/passwd")

    def test_missing_hostname(self):
        with pytest.raises(InvalidURLError, match="Missing hostname"):
            validate_url_ssrf("http://")

    def test_empty_url(self):
        with pytest.raises(InvalidURLError):
            validate_url_ssrf("")

    def test_allowed_hosts_whitelist(self):
        result = validate_url_ssrf(
            "http://api.example.com",
            allowed_hosts=["api.example.com"],
            resolve_dns=False,
        )
        assert result == "http://api.example.com"

    def test_allowed_hosts_blocked(self):
        with pytest.raises(SSRFError, match="not in allowed list"):
            validate_url_ssrf(
                "http://evil.com",
                allowed_hosts=["api.example.com"],
            )


class TestValidateServiceUrl:
    """Tests pour validate_service_url."""

    def test_valid_localhost(self):
        result = validate_service_url("http://localhost:8001", "symexec")
        assert result == "http://localhost:8001"

    def test_valid_127(self):
        result = validate_service_url("http://127.0.0.1:8002", "ai_service")
        assert result == "http://127.0.0.1:8002"

    def test_invalid_scheme(self):
        with pytest.raises(InvalidURLError):
            validate_service_url("ftp://localhost:8001", "test")

    def test_empty_url(self):
        with pytest.raises(InvalidURLError):
            validate_service_url("", "test")


class TestIsPathSafe:
    """Tests pour is_path_safe."""

    def test_safe_absolute_path(self, temp_dir):
        # Test with absolute path within base
        test_file = temp_dir / "file.txt"
        test_file.touch()
        assert is_path_safe(str(test_file), temp_dir) is True

    def test_unsafe_parent_traversal(self, temp_dir):
        assert is_path_safe("../file.txt", temp_dir) is False
        assert is_path_safe("../../etc/passwd", temp_dir) is False

    def test_unsafe_absolute_linux_paths(self):
        assert is_path_safe("/etc/passwd") is False
        assert is_path_safe("/proc/self/environ") is False

    def test_safe_absolute_path_in_base(self, temp_dir):
        test_file = temp_dir / "test.txt"
        test_file.touch()
        assert is_path_safe(str(test_file), temp_dir) is True


class TestSanitizePath:
    """Tests pour sanitize_path."""

    def test_valid_path(self, temp_dir):
        test_file = temp_dir / "test.txt"
        test_file.touch()
        result = sanitize_path("test.txt", temp_dir, must_exist=True)
        assert result == test_file.resolve()

    def test_path_traversal_blocked(self, temp_dir):
        with pytest.raises(PathTraversalError):
            sanitize_path("../../../etc/passwd", temp_dir)

    def test_absolute_path_outside_base(self, temp_dir):
        with pytest.raises(PathTraversalError):
            sanitize_path("/etc/passwd", temp_dir)

    def test_must_exist_fails(self, temp_dir):
        # When file doesn't exist and must_exist=True, it raises an exception
        # Could be FileNotFoundError or PathTraversalError depending on implementation
        from aira.exceptions import FileNotFoundError as AIRAFileNotFoundError
        with pytest.raises((AIRAFileNotFoundError, PathTraversalError)):
            sanitize_path("nonexistent.txt", temp_dir, must_exist=True)

    def test_empty_path(self, temp_dir):
        with pytest.raises(PathTraversalError, match="Empty path"):
            sanitize_path("", temp_dir)


class TestSanitizeFilename:
    """Tests pour sanitize_filename."""

    def test_safe_filename(self):
        assert sanitize_filename("test.exe") == "test.exe"
        assert sanitize_filename("my-file_v1.dll") == "my-file_v1.dll"

    def test_removes_path_components(self):
        assert sanitize_filename("/etc/passwd") == "passwd"
        assert sanitize_filename("C:\\Windows\\system32\\cmd.exe") == "cmd.exe"

    def test_replaces_dangerous_chars(self):
        result = sanitize_filename("file<>:test.exe")
        assert "<" not in result
        assert ">" not in result
        assert ":" not in result

    def test_handles_hidden_files(self):
        result = sanitize_filename(".hidden")
        assert not result.startswith(".")

    def test_empty_filename(self):
        assert sanitize_filename("") == "unnamed"

    def test_truncates_long_names(self):
        long_name = "a" * 300 + ".exe"
        result = sanitize_filename(long_name)
        assert len(result) <= 200

    def test_reserved_windows_names(self):
        result = sanitize_filename("CON.exe")
        assert result != "CON.exe"


class TestSanitizeCommandArg:
    """Tests pour sanitize_command_arg."""

    def test_safe_arg(self):
        assert sanitize_command_arg("normal_argument") == "normal_argument"

    def test_removes_backticks(self):
        result = sanitize_command_arg("test`whoami`")
        assert "`" not in result

    def test_removes_dollar(self):
        result = sanitize_command_arg("$HOME/file")
        assert "$" not in result

    def test_removes_pipe(self):
        result = sanitize_command_arg("file | cat")
        assert "|" not in result

    def test_removes_semicolon(self):
        result = sanitize_command_arg("cmd; rm -rf /")
        assert ";" not in result

    def test_removes_redirect(self):
        result = sanitize_command_arg("file > /dev/null")
        assert ">" not in result

    def test_empty_arg(self):
        assert sanitize_command_arg("") == ""
