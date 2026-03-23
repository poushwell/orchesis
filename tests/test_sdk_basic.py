"""Minimal coverage for orchesis.sdk (import + safe paths + edge inputs)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

import orchesis.sdk as sdk_mod
from orchesis.sdk import OrchesisClient, SDKConfig


def test_sdk_imports_cleanly() -> None:
    assert sdk_mod.__doc__
    assert OrchesisClient is not None


def test_sdk_OrchesisClient_instantiates() -> None:
    client = OrchesisClient()
    assert client.api_url == "http://localhost:8080"
    cfg = SDKConfig()
    assert "8080" in cfg.base_url


def test_sdk_evaluate_basic_usage() -> None:
    with patch.object(OrchesisClient, "_request_safe", return_value={"allowed": True}) as mock_safe:
        client = OrchesisClient()
        out = client.evaluate({"tool": "read_file", "params": {"path": "/tmp/x"}})
    assert out["allowed"] is True
    mock_safe.assert_called_once()
    args, kwargs = mock_safe.call_args
    assert args[0] == "POST"
    assert "/api/v1/evaluate" in args[1]


def test_sdk_handles_empty_input() -> None:
    with patch.object(OrchesisClient, "_request_safe", return_value={"error": "offline"}) as mock_safe:
        client = OrchesisClient()
        out = client.evaluate({})
    assert "error" in out
    body = mock_safe.call_args[0][2]
    assert body == {}


def test_sdk_handles_none_input() -> None:
    with patch.object(OrchesisClient, "_request_safe", return_value={"ok": True}) as mock_safe:
        client = OrchesisClient()
        out = client.classify_intent(None)  # type: ignore[arg-type]
    assert out.get("ok") is True
    sent = mock_safe.call_args[0][2]
    assert sent == {"text": None}


def test_sdk_classify_intent_empty_string() -> None:
    """Edge: empty prompt text still serializes."""
    with patch.object(OrchesisClient, "_request_safe", return_value={"label": "unknown"}) as mock_safe:
        client = OrchesisClient()
        out = client.classify_intent("")
    assert out["label"] == "unknown"
    assert mock_safe.call_args[0][2] == {"text": ""}
