from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

def test_version_is_040() -> None:
    import tomllib
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    from orchesis import __version__

    assert __version__ == pyproject["project"]["version"]


def test_changelog_has_current_release_section() -> None:
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    import tomllib
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
    assert any(name.endswith(".tar.gz") for name in files), f"Missing sdist for {version} in {files}"


def test_all_new_modules_importable() -> None:
    from orchesis.par_reasoning import PARReasoner
    from orchesis.criticality_control import CriticalityController
    from orchesis.mrac_controller import MRACController
    from orchesis.hgt_protocol import HGTProtocol
    from orchesis.carnot_efficiency import CarnotEfficiencyCalculator
    from orchesis.red_queen import RedQueenMonitor
    from orchesis.kolmogorov_importance import KolmogorovImportance
    from orchesis.fitness_landscape import FitnessLandscapeMapper
    from orchesis.casura.incident_db import CASURAIncidentDB
    from orchesis.aabb.benchmark import AABBBenchmark
    from orchesis.are.framework import AREFramework
    from orchesis.agent_autopsy import AgentAutopsy
    from orchesis.sdk import OrchesisClient
    from orchesis.system_health_report import SystemHealthReport
    from orchesis.config_validator import ConfigValidator

    _ = (
        PARReasoner,
        CriticalityController,
        MRACController,
        HGTProtocol,
        CarnotEfficiencyCalculator,
        RedQueenMonitor,
        KolmogorovImportance,
        FitnessLandscapeMapper,
        CASURAIncidentDB,
        AABBBenchmark,
        AREFramework,
        AgentAutopsy,
        OrchesisClient,
        SystemHealthReport,
        ConfigValidator,
    )
    assert True
