"""Test that all ecosystem modules use unified logging."""

from __future__ import annotations

import importlib
import inspect
import re


ECOSYSTEM_MODULES = [
    "orchesis.casura.incident_db",
    "orchesis.casura.intelligence",
    "orchesis.casura.api_v2",
    "orchesis.aabb.benchmark",
    "orchesis.are.framework",
    "orchesis.serve",
    "orchesis.vibe_watch",
    "orchesis.channel_monitor",
    "orchesis.persona_guardian",
    "orchesis.monitoring.parsers",
    "orchesis.monitoring.competitive",
]


def test_all_modules_import_get_logger() -> None:
    """Every ecosystem module imports from orchesis.utils.log."""
    for mod_name in ECOSYSTEM_MODULES:
        mod = importlib.import_module(mod_name)
        source = inspect.getsource(mod)
        assert "orchesis.utils.log" in source or "get_logger" in source, (
            f"{mod_name} does not use orchesis.utils.log"
        )


def test_no_fallback_logging() -> None:
    """No module uses try/except ImportError fallback for logging."""
    for mod_name in ECOSYSTEM_MODULES:
        mod = importlib.import_module(mod_name)
        source = inspect.getsource(mod)
        assert "except ImportError" not in source or "get_logger" not in source.split("except ImportError")[0][-200:], (
            f"{mod_name} still has fallback logging"
        )


def test_no_bare_print_in_ecosystem() -> None:
    """No bare print() calls in ecosystem modules (except serve.py banner)."""
    for mod_name in ECOSYSTEM_MODULES:
        if "serve" in mod_name:
            continue
        mod = importlib.import_module(mod_name)
        source = inspect.getsource(mod)
        prints = re.findall(r"^\s+print\(", source, re.MULTILINE)
        assert len(prints) == 0, f"{mod_name} has {len(prints)} print() calls"


def test_casura_incident_db_has_logger() -> None:
    mod = importlib.import_module("orchesis.casura.incident_db")
    assert hasattr(mod, "logger")


def test_casura_api_v2_has_logger() -> None:
    mod = importlib.import_module("orchesis.casura.api_v2")
    assert hasattr(mod, "logger")


def test_aabb_benchmark_has_logger() -> None:
    mod = importlib.import_module("orchesis.aabb.benchmark")
    assert hasattr(mod, "logger")


def test_are_framework_has_logger() -> None:
    mod = importlib.import_module("orchesis.are.framework")
    assert hasattr(mod, "logger")


def test_structured_extra_used() -> None:
    """At least some log calls use extra= for structured context."""
    for mod_name in ["orchesis.casura.incident_db", "orchesis.aabb.benchmark"]:
        mod = importlib.import_module(mod_name)
        source = inspect.getsource(mod)
        assert "extra=" in source, f"{mod_name} missing structured extra"
