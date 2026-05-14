from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest


def test_version_is_040() -> None:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib

    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    from orchesis import __version__

    assert __version__ == pyproject["project"]["version"]


def test_changelog_has_current_release_section() -> None:
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib

    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    version = pyproject["project"]["version"]
    assert f"## [{version}]" in changelog
    assert "passing" in changelog.lower()


def test_build_artifacts_exist() -> None:
    if os.getenv("CI"):
        pytest.skip("Build artifacts not available in CI")
    dist = Path("dist")
    if not dist.exists() or not list(dist.iterdir()):
        pytest.skip("dist/ not built in this environment")
    version = importlib.import_module("orchesis").__version__
    files = [f.name for f in dist.iterdir()]
    assert any(name.endswith(".whl") for name in files), f"Missing wheel for {version} in {files}"
    assert any(name.endswith(".tar.gz") for name in files), (
        f"Missing sdist for {version} in {files}"
    )


def test_all_new_modules_importable() -> None:
    from orchesis.fallback_reasoner import FallbackReasoner
    from orchesis.quality_control import QualityController
    from orchesis.adaptive_controller import AdaptiveController
    from orchesis.behavior_sync import BehaviorSync
    from orchesis.efficiency_metric import EfficiencyMetricCalculator
    from orchesis.adversarial_tracker import RedQueenMonitor
    from orchesis.content_importance import ContentImportance
    from orchesis.solution_space import SolutionSpaceMapper
    from orchesis.casura.incident_db import CASURAIncidentDB
    from orchesis.aabb.benchmark import AABBBenchmark
    from orchesis.are.framework import AREFramework
    from orchesis.agent_diagnostics import AgentDiagnostics
    from orchesis.sdk import OrchesisClient
    from orchesis.system_health_report import SystemHealthReport
    from orchesis.config_validator import ConfigValidator

    _ = (
        FallbackReasoner,
        QualityController,
        AdaptiveController,
        BehaviorSync,
        EfficiencyMetricCalculator,
        RedQueenMonitor,
        ContentImportance,
        SolutionSpaceMapper,
        CASURAIncidentDB,
        AABBBenchmark,
        AREFramework,
        AgentDiagnostics,
        OrchesisClient,
        SystemHealthReport,
        ConfigValidator,
    )
    assert True
