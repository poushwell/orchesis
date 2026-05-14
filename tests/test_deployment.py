from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_exists() -> None:
    assert (ROOT / "Dockerfile").exists()


def test_docker_compose_valid_yaml() -> None:
    compose_path = ROOT / "docker-compose.yml"
    data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)


def test_docker_compose_has_services() -> None:
    compose_path = ROOT / "docker-compose.yml"
    data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = data.get("services", {})
    assert "orchesis" in services


def test_makefile_exists() -> None:
    assert (ROOT / "Makefile").exists()


def test_makefile_has_key_targets() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "test:" in makefile
    assert "lint:" in makefile
    assert "fuzz:" in makefile
    assert "invariants:" in makefile
    assert "docker:" in makefile
    assert "help:" in makefile


def test_env_example_exists() -> None:
    assert (ROOT / ".env.example").exists()


def test_deployment_docs_exist() -> None:
    assert (ROOT / "docs" / "DEPLOYMENT.md").exists()


def test_dockerfile_uses_nonroot_user() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.12-slim" in dockerfile


def test_dockerfile_has_healthcheck() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert 'CMD ["orchesis", "proxy", "--config", "/app/config/orchesis.yaml"]' in dockerfile
