import json
import os
import tempfile
import unittest.mock as mock

import pytest

from orchesis.config import _load_yaml, load_policy


def test_json_config_loads_without_yaml():
    """JSON config works without pyyaml installed."""
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False, encoding="utf-8") as f:
        json.dump({"proxy": {"target": "https://api.openai.com"}}, f)
        f.flush()
        path = f.name
    try:
        policy = load_policy(path)
    finally:
        os.unlink(path)
    assert policy["proxy"]["target"] == "https://api.openai.com"


def test_yaml_config_loads_with_yaml_installed():
    """YAML config works when pyyaml is installed."""
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False, encoding="utf-8") as f:
        f.write("proxy:\n  target: https://api.openai.com\n")
        f.flush()
        path = f.name
    try:
        policy = load_policy(path)
    finally:
        os.unlink(path)
    assert policy["proxy"]["target"] == "https://api.openai.com"


def test_json_fallback_for_unknown_extension():
    """Files without .yaml/.json extension try JSON first."""
    with tempfile.NamedTemporaryFile(suffix=".conf", mode="w", delete=False, encoding="utf-8") as f:
        json.dump({"security": {"enabled": True}}, f)
        f.flush()
        path = f.name
    try:
        policy = load_policy(path)
    finally:
        os.unlink(path)
    assert policy["security"]["enabled"] is True


def test_yaml_import_error_message():
    """Clear error message when YAML needed but pyyaml not installed."""

    def _fake_import(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("No module named yaml")
        return __import__(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=_fake_import):
        with pytest.raises(ImportError, match=r"orchesis\[yaml\]"):
            _load_yaml("key: value")


def test_empty_json_config():
    """Empty JSON returns empty dict."""
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False, encoding="utf-8") as f:
        f.write("{}")
        f.flush()
        path = f.name
    try:
        policy = load_policy(path)
    finally:
        os.unlink(path)
    assert isinstance(policy, dict)
    assert policy.get("proxy") is not None
