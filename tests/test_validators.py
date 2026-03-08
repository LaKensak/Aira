"""
Tests pour le module aira.validators.
"""
import argparse
from pathlib import Path
import tempfile

import pytest

from aira.validators import (
    hex_address,
    hex_address_list,
    existing_file,
    existing_binary,
    existing_directory,
    valid_pid,
    valid_url,
    positive_int,
    non_negative_int,
    temperature_value,
    probability_value,
    validate_hex_address,
    validate_pid,
    validate_url,
)
from aira.exceptions import InvalidAddressError, InvalidPIDError, InvalidURLError


class TestHexAddress:
    """Tests pour hex_address validator."""

    def test_valid_with_prefix(self):
        assert hex_address("0x1234") == "0x1234"
        assert hex_address("0X1234") == "0x1234"

    def test_valid_without_prefix(self):
        assert hex_address("1234") == "0x1234"
        assert hex_address("abcdef") == "0xabcdef"

    def test_valid_mixed_case(self):
        assert hex_address("0xAbCdEf") == "0xabcdef"

    def test_valid_full_64bit(self):
        assert hex_address("0xffffffffffffffff") == "0xffffffffffffffff"

    def test_invalid_empty(self):
        with pytest.raises(argparse.ArgumentTypeError):
            hex_address("")

    def test_invalid_non_hex(self):
        with pytest.raises(argparse.ArgumentTypeError):
            hex_address("0xGHIJ")

    def test_invalid_too_long(self):
        with pytest.raises(argparse.ArgumentTypeError):
            hex_address("0x" + "f" * 20)

    def test_invalid_only_prefix(self):
        with pytest.raises(argparse.ArgumentTypeError):
            hex_address("0x")


class TestHexAddressList:
    """Tests pour hex_address_list validator."""

    def test_empty(self):
        assert hex_address_list("") == []

    def test_single(self):
        assert hex_address_list("0x1234") == ["0x1234"]

    def test_multiple(self):
        result = hex_address_list("0x1234,0x5678,0xabcd")
        assert result == ["0x1234", "0x5678", "0xabcd"]

    def test_with_spaces(self):
        result = hex_address_list("0x1234, 0x5678 , 0xabcd")
        assert result == ["0x1234", "0x5678", "0xabcd"]


class TestExistingFile:
    """Tests pour existing_file validator."""

    def test_valid_file(self, temp_dir):
        test_file = temp_dir / "test.txt"
        test_file.write_text("content")
        result = existing_file(str(test_file))
        assert result == test_file.resolve()

    def test_nonexistent_file(self):
        with pytest.raises(argparse.ArgumentTypeError, match="File not found"):
            existing_file("/nonexistent/path/file.txt")

    def test_directory_not_file(self, temp_dir):
        with pytest.raises(argparse.ArgumentTypeError, match="Not a file"):
            existing_file(str(temp_dir))

    def test_empty_path(self):
        with pytest.raises(argparse.ArgumentTypeError, match="cannot be empty"):
            existing_file("")


class TestExistingBinary:
    """Tests pour existing_binary validator."""

    def test_valid_binary(self, temp_binary_file):
        result = existing_binary(str(temp_binary_file))
        assert result == temp_binary_file.resolve()

    def test_nonexistent_binary(self):
        with pytest.raises(argparse.ArgumentTypeError):
            existing_binary("/nonexistent/binary.exe")


class TestValidPid:
    """Tests pour valid_pid validator."""

    def test_valid_pid(self):
        assert valid_pid("1234") == 1234
        assert valid_pid("1") == 1

    def test_invalid_zero(self):
        with pytest.raises(argparse.ArgumentTypeError, match="must be positive"):
            valid_pid("0")

    def test_invalid_negative(self):
        with pytest.raises(argparse.ArgumentTypeError, match="must be positive"):
            valid_pid("-1")

    def test_invalid_non_numeric(self):
        with pytest.raises(argparse.ArgumentTypeError, match="must be integer"):
            valid_pid("abc")

    def test_invalid_empty(self):
        with pytest.raises(argparse.ArgumentTypeError, match="cannot be empty"):
            valid_pid("")

    def test_invalid_too_large(self):
        with pytest.raises(argparse.ArgumentTypeError, match="too large"):
            valid_pid("9999999999")


class TestValidUrl:
    """Tests pour valid_url validator."""

    def test_valid_http(self):
        assert valid_url("http://example.com") == "http://example.com"

    def test_valid_https(self):
        assert valid_url("https://example.com/path") == "https://example.com/path"

    def test_valid_with_port(self):
        assert valid_url("http://localhost:8080") == "http://localhost:8080"

    def test_invalid_no_scheme(self):
        with pytest.raises(argparse.ArgumentTypeError, match="scheme"):
            valid_url("example.com")

    def test_invalid_ftp_scheme(self):
        with pytest.raises(argparse.ArgumentTypeError, match="http or https"):
            valid_url("ftp://example.com")

    def test_invalid_no_host(self):
        with pytest.raises(argparse.ArgumentTypeError, match="host"):
            valid_url("http://")

    def test_invalid_empty(self):
        with pytest.raises(argparse.ArgumentTypeError, match="cannot be empty"):
            valid_url("")


class TestNumericValidators:
    """Tests pour les validateurs numériques."""

    def test_positive_int_valid(self):
        assert positive_int("42") == 42
        assert positive_int("1") == 1

    def test_positive_int_invalid_zero(self):
        with pytest.raises(argparse.ArgumentTypeError, match="Must be positive"):
            positive_int("0")

    def test_positive_int_invalid_negative(self):
        with pytest.raises(argparse.ArgumentTypeError, match="Must be positive"):
            positive_int("-5")

    def test_non_negative_int_valid(self):
        assert non_negative_int("0") == 0
        assert non_negative_int("42") == 42

    def test_non_negative_int_invalid(self):
        with pytest.raises(argparse.ArgumentTypeError, match="Must be non-negative"):
            non_negative_int("-1")

    def test_temperature_valid(self):
        assert temperature_value("0.0") == 0.0
        assert temperature_value("1.0") == 1.0
        assert temperature_value("2.0") == 2.0
        assert temperature_value("0.5") == 0.5

    def test_temperature_invalid_high(self):
        with pytest.raises(argparse.ArgumentTypeError, match="between 0.0 and 2.0"):
            temperature_value("2.5")

    def test_temperature_invalid_negative(self):
        with pytest.raises(argparse.ArgumentTypeError, match="between 0.0 and 2.0"):
            temperature_value("-0.1")

    def test_probability_valid(self):
        assert probability_value("0.0") == 0.0
        assert probability_value("0.5") == 0.5
        assert probability_value("1.0") == 1.0

    def test_probability_invalid_high(self):
        with pytest.raises(argparse.ArgumentTypeError, match="between 0.0 and 1.0"):
            probability_value("1.5")


class TestValidationFunctions:
    """Tests pour les fonctions validate_* (non-argparse)."""

    def test_validate_hex_address_valid(self):
        assert validate_hex_address("0x1234") == "0x1234"

    def test_validate_hex_address_invalid(self):
        with pytest.raises(InvalidAddressError):
            validate_hex_address("invalid")

    def test_validate_pid_valid(self):
        assert validate_pid(1234) == 1234
        assert validate_pid("1234") == 1234

    def test_validate_pid_invalid(self):
        with pytest.raises(InvalidPIDError):
            validate_pid(-1)

    def test_validate_url_valid(self):
        assert validate_url("https://example.com") == "https://example.com"

    def test_validate_url_invalid(self):
        with pytest.raises(InvalidURLError):
            validate_url("not-a-url")
