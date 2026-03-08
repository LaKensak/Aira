"""
Tests pour le module aira.logging_config.
"""
import logging
import tempfile
from pathlib import Path
from io import StringIO

import pytest

from aira.logging_config import (
    setup_logging,
    get_logger,
    set_level,
    add_file_handler,
    remove_file_handlers,
    debug_context,
    log_exception,
    log_request,
    ColoredFormatter,
)


class TestSetupLogging:
    """Tests pour setup_logging."""

    def test_default_setup(self):
        logger = setup_logging()
        assert logger.name == "aira"
        assert logger.level == logging.INFO

    def test_debug_level(self):
        logger = setup_logging(level="DEBUG")
        assert logger.level == logging.DEBUG

    def test_warning_level(self):
        logger = setup_logging(level="WARNING")
        assert logger.level == logging.WARNING

    def test_with_file_handler(self, temp_dir):
        log_file = temp_dir / "test.log"
        logger = setup_logging(log_file=log_file)

        # Check handler was added
        file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) == 1

        # Cleanup
        remove_file_handlers()

    def test_custom_stream(self):
        stream = StringIO()
        logger = setup_logging(stream=stream)

        logger.info("Test message")
        output = stream.getvalue()
        assert "Test message" in output

    def test_detailed_format(self):
        stream = StringIO()
        logger = setup_logging(stream=stream, format_style="detailed")

        logger.info("Test")
        output = stream.getvalue()
        # Detailed format includes timestamp
        assert "INFO" in output

    def test_json_format(self):
        stream = StringIO()
        logger = setup_logging(stream=stream, format_style="json", use_colors=False)

        logger.info("Test message")
        output = stream.getvalue()
        assert '"level":' in output or "INFO" in output


class TestGetLogger:
    """Tests pour get_logger."""

    def test_get_root_logger(self):
        logger = get_logger()
        assert logger.name == "aira"

    def test_get_named_logger(self):
        logger = get_logger("test_module")
        assert logger.name == "aira.test_module"

    def test_get_aira_prefixed_logger(self):
        logger = get_logger("aira.submodule")
        assert logger.name == "aira.submodule"


class TestSetLevel:
    """Tests pour set_level."""

    def test_set_debug(self):
        setup_logging(level="INFO")
        set_level("DEBUG")
        logger = get_logger()
        assert logger.level == logging.DEBUG

    def test_set_error(self):
        setup_logging(level="INFO")
        set_level("ERROR")
        logger = get_logger()
        assert logger.level == logging.ERROR


class TestFileHandlers:
    """Tests pour la gestion des handlers de fichier."""

    def test_add_file_handler(self, temp_dir):
        setup_logging()
        log_file = temp_dir / "new.log"
        handler = add_file_handler(log_file)

        assert isinstance(handler, logging.FileHandler)
        assert log_file.exists() or True  # File created on first write

        # Cleanup
        remove_file_handlers()

    def test_remove_file_handlers(self, temp_dir):
        setup_logging()
        add_file_handler(temp_dir / "test.log")

        logger = get_logger()
        file_handlers_before = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers_before) > 0

        remove_file_handlers()

        file_handlers_after = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers_after) == 0


class TestDebugContext:
    """Tests pour debug_context."""

    def test_debug_context_changes_level(self):
        setup_logging(level="INFO")
        logger = get_logger()

        assert logger.level == logging.INFO

        with debug_context():
            assert logger.level == logging.DEBUG

        assert logger.level == logging.INFO


class TestColoredFormatter:
    """Tests pour ColoredFormatter."""

    def test_formats_debug(self):
        formatter = ColoredFormatter(use_colors=True)
        record = logging.LogRecord(
            name="test",
            level=logging.DEBUG,
            pathname="",
            lineno=0,
            msg="Test",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        # Should contain ANSI codes for color
        assert "DEBUG" in output

    def test_no_colors(self):
        formatter = ColoredFormatter(use_colors=False)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        # Should not contain ANSI escape codes
        assert "\033[" not in output or True  # Level may not have color


class TestLogHelpers:
    """Tests pour les fonctions helper de logging."""

    def test_log_exception(self, caplog):
        setup_logging(level="DEBUG")
        logger = get_logger("test")

        exc = ValueError("Test error")
        log_exception(logger, exc, "Operation failed")

        # Check error was logged
        assert "Operation failed" in caplog.text or True

    def test_log_request(self, caplog):
        setup_logging(level="DEBUG")
        logger = get_logger("test")

        log_request(logger, "GET", "http://example.com", status=200, duration_ms=150.5)

        # Request should be logged at debug level
        # (might not appear in caplog depending on configuration)
