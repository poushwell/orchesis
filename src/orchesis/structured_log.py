"""Structured JSON logging for Orchesis components."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any, TextIO

_LEVEL_ORDER = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}


class StructuredLogger:
    """JSON-structured logger for Orchesis components."""

    def __init__(self, component: str, output: str = "stderr", level: str = "INFO"):
        self._component = component
        self._level = level.strip().upper() if isinstance(level, str) else "INFO"
        self._stream: TextIO = sys.stderr if output != "stdout" else sys.stdout

    def info(self, message: str, **context) -> None:
        self._emit("INFO", message, **context)

    def warn(self, message: str, **context) -> None:
        self._emit("WARN", message, **context)

    def error(self, message: str, **context) -> None:
        self._emit("ERROR", message, **context)

    def debug(self, message: str, **context) -> None:
        self._emit("DEBUG", message, **context)

    def _emit(self, level: str, message: str, **context) -> None:
        configured = _LEVEL_ORDER.get(self._level, _LEVEL_ORDER["INFO"])
        current = _LEVEL_ORDER.get(level, _LEVEL_ORDER["INFO"])
        if current < configured:
            return
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": level,
            "component": self._component,
            "msg": message,
        }
        payload.update(context)
        self._stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self._stream.flush()
