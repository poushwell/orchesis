from __future__ import annotations

import importlib
import sys
import warnings
from pathlib import Path


def test_runner_no_click_import() -> None:
    text = Path("src/orchesis/agent/runner.py").read_text(encoding="utf-8")
    assert "import click" not in text


def test_sync_no_top_level_httpx() -> None:
    sys.modules.pop("httpx", None)
    importlib.invalidate_caches()
    importlib.import_module("orchesis.sync")
    assert "httpx" not in sys.modules


def test_alerting_deprecation_warning() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        module = importlib.import_module("orchesis.alerting")
        importlib.reload(module)
    assert any(isinstance(item.message, DeprecationWarning) for item in caught)
