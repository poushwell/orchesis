from __future__ import annotations

from pathlib import Path

from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis.serve import (
    ServeConfig,
    build_startup_banner,
    generate_self_signed_cert,
    validate_config,
)


def test_serve_module_imports() -> None:
    from orchesis import serve as serve_module

    assert hasattr(serve_module, "ServeConfig")
    assert hasattr(serve_module, "start_server")


def test_self_signed_cert_generation(tmp_path: Path) -> None:
    cert_path, key_path = generate_self_signed_cert(tmp_path)
    cert = Path(cert_path)
    key = Path(key_path)
    assert cert.exists() and cert.stat().st_size > 0
    assert key.exists() and key.stat().st_size > 0


def test_self_signed_cert_pem_format(tmp_path: Path) -> None:
    cert_path, _ = generate_self_signed_cert(tmp_path)
    content = Path(cert_path).read_text(encoding="utf-8")
    assert "BEGIN CERTIFICATE" in content


def test_startup_banner_plain() -> None:
    config = ServeConfig(port=8100, policy="orchesis.yaml")
    banner = build_startup_banner(config, "disabled")
    assert "http://localhost:8100" in banner
    assert "TLS: disabled" in banner


def test_startup_banner_tls() -> None:
    config = ServeConfig(port=8100, tls_cert="/tmp/cert.pem", tls_key="/tmp/key.pem", policy="orchesis.yaml")
    banner = build_startup_banner(config, "cert.pem")
    assert "https://localhost:8100" in banner
    assert "cert.pem" in banner


def test_startup_banner_self_signed() -> None:
    config = ServeConfig(port=8100, tls_self_signed=True, policy="orchesis.yaml")
    banner = build_startup_banner(config, "self-signed")
    assert "self-signed" in banner


def test_cli_serve_invalid_port() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["serve", "--tls-self-signed", "--port", "99999", "--skip-verify"])
    assert result.exit_code != 0
    assert "port must be in range 1..65535" in result.output


def test_cli_serve_missing_key(tmp_path: Path) -> None:
    cert = tmp_path / "cert.pem"
    cert.write_text("dummy", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["serve", "--tls-cert", str(cert), "--skip-verify"])
    assert result.exit_code != 0
    assert "tls-key is required" in result.output


def test_default_config() -> None:
    cfg = ServeConfig()
    assert cfg.host == "0.0.0.0"
    assert cfg.port == 8100
    assert cfg.tls_cert is None
    assert cfg.tls_key is None
    assert cfg.workers == 1


def test_valid_port() -> None:
    cfg = ServeConfig(port=8100)
    assert validate_config(cfg) == []


def test_negative_workers() -> None:
    cfg = ServeConfig(workers=0)
    errors = validate_config(cfg)
    assert any("workers must be >= 1" in item for item in errors)


def test_cli_serve_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["serve", "--help"])
    assert result.exit_code == 0
    assert "tls" in result.output.lower()
