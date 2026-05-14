from __future__ import annotations

from orchesis.module_registry import ModuleRegistry


def test_registry_has_categories() -> None:
    registry = ModuleRegistry()
    categories = registry.get_categories()
    assert isinstance(categories, list)
    assert "core" in categories
    assert "research" in categories


def test_get_all_modules_returns_list() -> None:
    registry = ModuleRegistry()
    modules = registry.get_all_modules()
    assert isinstance(modules, list)
    assert len(modules) > 0


def test_get_by_category_works() -> None:
    registry = ModuleRegistry()
    core = registry.get_by_category("core")
    assert isinstance(core, list)
    assert "api" in core


def test_count_total_above_50() -> None:
    registry = ModuleRegistry()
    stats = registry.count()
    assert stats["total"] > 50


def test_core_modules_present() -> None:
    registry = ModuleRegistry()
    core = registry.get_by_category("core")
    assert "proxy" in core
    assert "engine" in core
    assert "config" in core


def test_ecosystem_modules_present() -> None:
    registry = ModuleRegistry()
    ecosystem = registry.get_by_category("ecosystem")
    assert "casura.incident_db" in ecosystem
    assert "aabb.benchmark" in ecosystem
    assert "are.framework" in ecosystem
