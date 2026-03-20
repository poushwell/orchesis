from __future__ import annotations

import os
import tempfile
import time

import pytest
import yaml


def test_empty_request() -> None:
    from orchesis.engine import evaluate

    result = evaluate({}, {})
    assert result is not None
    assert hasattr(result, "allowed")


def test_none_values_in_request() -> None:
    from orchesis.engine import evaluate

    result = evaluate({"tool": None, "params": None, "cost": None, "context": None}, {})
    assert result is not None


def test_giant_request_10mb() -> None:
    """10MB request doesn't crash, returns result."""
    from orchesis.engine import evaluate

    giant = {"tool": "test", "params": {"content": "x" * 10_000_000}, "cost": 0.0, "context": {}}
    result = evaluate(giant, {"rules": []})
    assert result is not None


def test_deeply_nested_policy() -> None:
    """100-level nested policy dict doesn't cause recursion error."""
    from orchesis.engine import evaluate

    policy: dict = {"rules": []}
    nested = policy
    for _ in range(100):
        nested["nested"] = {}
        nested = nested["nested"]
    result = evaluate({"tool": "t", "params": {}, "cost": 0.0, "context": {}}, policy)
    assert result is not None


def test_1000_rules_in_policy() -> None:
    """Policy with 1000 rules evaluates in reasonable time."""
    from orchesis.engine import evaluate

    rules = [
        {
            "name": f"rule_{i}",
            "type": "regex_match",
            "field": "params.content",
            "deny_patterns": [f"pattern_{i}"],
        }
        for i in range(1000)
    ]
    policy = {"rules": rules}
    req = {"tool": "t", "params": {"content": "hello world"}, "cost": 0.0, "context": {}}
    start = time.time()
    _ = evaluate(req, policy)
    assert time.time() - start < 5.0


def test_unicode_extremes() -> None:
    """All Unicode planes don't crash the engine."""
    from orchesis.engine import evaluate

    texts = [
        "Hello 🌍",
        "中文日本語한국어",
        "\u0000\u0001\u001f",
        "\ud800\udfff",
        "a" * 100000,
    ]
    for text in texts:
        try:
            _ = evaluate({"tool": "t", "params": {"content": text}, "cost": 0.0, "context": {}}, {})
        except Exception as error:  # pragma: no cover - defensive regression check
            pytest.fail(f"Crashed on input: {repr(text[:50])}: {error}")


def test_rapid_policy_reload() -> None:
    """Policy reloaded 100 times rapidly doesn't corrupt state."""
    from orchesis.config import load_policy

    for i in range(100):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as file:
            yaml.dump({"proxy": {"port": 8080 + i}}, file)
            name = file.name
        result = load_policy(name)
        os.unlink(name)
        assert isinstance(result, dict)


def test_all_contrib_modules_no_crash() -> None:
    """All contrib modules handle empty/None/binary input."""
    from orchesis.contrib.pii_detector import PiiDetector
    from orchesis.contrib.secret_scanner import SecretScanner

    scanner = SecretScanner()
    detector = PiiDetector()
    for value in ["", None, b"binary", "x" * 100000, "\x00\xff\xfe"]:
        try:
            _ = scanner.scan(value)  # type: ignore[arg-type]
            _ = detector.detect(value)  # type: ignore[arg-type]
        except Exception as error:  # pragma: no cover - defensive regression check
            pytest.fail(f"Crashed on {repr(value)}: {error}")
