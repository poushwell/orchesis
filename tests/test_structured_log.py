from __future__ import annotations

import json
from io import StringIO

from orchesis.structured_log import StructuredLogger


def test_structured_log_format() -> None:
    stream = StringIO()
    logger = StructuredLogger("engine")
    logger._stream = stream
    logger.info("Policy reloaded", old_version="abc", new_version="def")
    payload = json.loads(stream.getvalue().strip())
    assert "ts" in payload
    assert payload["level"] == "INFO"
    assert payload["component"] == "engine"
    assert payload["msg"] == "Policy reloaded"


def test_log_levels() -> None:
    stream = StringIO()
    logger = StructuredLogger("proxy", level="DEBUG")
    logger._stream = stream
    logger.info("i")
    logger.warn("w")
    logger.error("e")
    logger.debug("d")
    rows = [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]
    assert [item["level"] for item in rows] == ["INFO", "WARN", "ERROR", "DEBUG"]


def test_log_context_fields() -> None:
    stream = StringIO()
    logger = StructuredLogger("api")
    logger._stream = stream
    logger.error("failed", request_id="r1", status=500)
    payload = json.loads(stream.getvalue().strip())
    assert payload["request_id"] == "r1"
    assert payload["status"] == 500


def test_log_level_filtering() -> None:
    stream = StringIO()
    logger = StructuredLogger("cli", level="WARN")
    logger._stream = stream
    logger.debug("d")
    logger.info("i")
    logger.warn("w")
    rows = [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]
    assert len(rows) == 1
    assert rows[0]["level"] == "WARN"
