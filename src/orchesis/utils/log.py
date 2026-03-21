"""Orchesis structured logging utility.

Usage:
    from orchesis.utils.log import get_logger
    logger = get_logger(__name__)
    logger.info("Processing request", extra={"agent_id": "a1", "component": "serve"})
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Optional


class StructuredFormatter(logging.Formatter):
    """JSON-lines formatter with context fields."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("module", "agent_id", "request_id", "channel_type", "session_id", "component"):
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)


class DevFormatter(logging.Formatter):
    """Colored dev-friendly formatter."""

    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[35m",
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        reset = self.RESET if color else ""
        prefix = f"{color}[{record.levelname}]{reset}"
        msg = f"{prefix} {record.name}: {record.getMessage()}"
        context_parts = []
        for key in ("agent_id", "request_id", "channel_type", "component"):
            val = getattr(record, key, None)
            if val is not None:
                context_parts.append(f"{key}={val}")
        if context_parts:
            msg += f" [{', '.join(context_parts)}]"
        if record.exc_info and record.exc_info[0]:
            msg += f"\n{self.formatException(record.exc_info)}"
        return msg


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """Get a configured Orchesis logger."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)

        log_format = os.environ.get("ORCHESIS_LOG_FORMAT", "dev")
        if log_format == "json":
            handler.setFormatter(StructuredFormatter())
        else:
            handler.setFormatter(DevFormatter())

        log_level = level or os.environ.get("ORCHESIS_LOG_LEVEL", "INFO")
        resolved_level = getattr(logging, str(log_level).upper(), logging.INFO)
        handler.setLevel(resolved_level)
        logger.setLevel(resolved_level)

        logger.addHandler(handler)
        logger.propagate = False

    return logger
