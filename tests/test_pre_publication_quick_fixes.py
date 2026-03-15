from __future__ import annotations

import ast
import importlib
import warnings
from pathlib import Path


def test_runner_no_click_import() -> None:
    text = Path("src/orchesis/agent/runner.py").read_text(encoding="utf-8")
    assert "import click" not in text


def test_sync_no_top_level_httpx() -> None:
    source = Path("src/orchesis/sync.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    top_level_imports: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            top_level_imports.extend(alias.name for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            top_level_imports.append(node.module)
    assert "httpx" not in top_level_imports


def test_alerting_deprecation_warning() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        module = importlib.import_module("orchesis.alerting")
        importlib.reload(module)
    assert any(isinstance(item.message, DeprecationWarning) for item in caught)
