from __future__ import annotations

from pathlib import Path


def test_version_is_040() -> None:
    from orchesis import __version__

    assert __version__ == "0.4.0"


def test_changelog_has_040_section() -> None:
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [0.4.0] — 2026-03-19" in changelog
    assert "4038 passing (was 3512 at v0.3.0)" in changelog
    assert "+526 new tests" in changelog


def test_build_artifacts_exist() -> None:
    dist = Path("dist")
    files = [p.name for p in dist.glob("orchesis-0.4.0*")]
    assert any(name.endswith(".whl") for name in files), f"Missing wheel for 0.4.0 in {files}"
    assert any(name.endswith(".tar.gz") for name in files), f"Missing sdist for 0.4.0 in {files}"


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
