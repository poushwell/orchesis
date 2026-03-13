from __future__ import annotations

from pathlib import Path

import yaml


def test_dockerfile_exists() -> None:
    assert Path("Dockerfile").exists()


def test_docker_compose_valid_yaml() -> None:
    compose = Path("docker-compose.yml")
    assert compose.exists()
    parsed = yaml.safe_load(compose.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    assert "services" in parsed
    assert "orchesis" in parsed["services"]


def test_example_config_exists() -> None:
    assert Path("config/orchesis_example.yaml").exists()


def test_example_config_valid_yaml() -> None:
    parsed = yaml.safe_load(Path("config/orchesis_example.yaml").read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    assert "proxy" in parsed
    assert "budgets" in parsed


def test_openclaw_config_exists() -> None:
    assert Path("config/orchesis_openclaw.yaml").exists()

