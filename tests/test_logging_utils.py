from __future__ import annotations

import json
import logging
import os
from unittest.mock import patch

from orchesis.utils.log import DevFormatter, StructuredFormatter, get_logger


def test_get_logger_returns_logger() -> None:
    logger = get_logger("orchesis.tests.logging.returns")
    assert isinstance(logger, logging.Logger)


def test_get_logger_default_level() -> None:
    with patch.dict(os.environ, {}, clear=False):
        logger = get_logger("orchesis.tests.logging.default_level")
    assert logger.level == logging.INFO


def test_get_logger_env_level() -> None:
    with patch.dict(os.environ, {"ORCHESIS_LOG_LEVEL": "DEBUG"}, clear=False):
        logger = get_logger("orchesis.tests.logging.env_level")
    assert logger.level == logging.DEBUG


def test_structured_formatter_json() -> None:
    formatter = StructuredFormatter()
    record = logging.LogRecord(
        name="orchesis.tests",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello world",
        args=(),
        exc_info=None,
    )
    out = formatter.format(record)
    payload = json.loads(out)
    assert payload["level"] == "INFO"
    assert payload["message"] == "hello world"
    assert "timestamp" in payload


def test_structured_formatter_extra() -> None:
    formatter = StructuredFormatter()
    record = logging.LogRecord(
        name="orchesis.tests",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="with extra",
        args=(),
        exc_info=None,
    )
    setattr(record, "agent_id", "a1")
    setattr(record, "request_id", "r1")
    out = formatter.format(record)
    payload = json.loads(out)
    assert payload["agent_id"] == "a1"
    assert payload["request_id"] == "r1"


def test_dev_formatter_colored() -> None:
    formatter = DevFormatter()
    record = logging.LogRecord(
        name="orchesis.tests",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="warn message",
        args=(),
        exc_info=None,
    )
    out = formatter.format(record)
    assert "WARNING" in out
    assert "warn message" in out


def test_json_format_env() -> None:
    with patch.dict(os.environ, {"ORCHESIS_LOG_FORMAT": "json"}, clear=False):
        logger = get_logger("orchesis.tests.logging.json_format")
    assert len(logger.handlers) == 1
    assert isinstance(logger.handlers[0].formatter, StructuredFormatter)


def test_logger_no_duplicate_handlers() -> None:
    name = "orchesis.tests.logging.no_dups"
    logger = get_logger(name)
    assert len(logger.handlers) == 1
    logger = get_logger(name)
    assert len(logger.handlers) == 1
