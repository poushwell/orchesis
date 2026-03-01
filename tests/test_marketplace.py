from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from orchesis.cli import main
from orchesis.marketplace import PolicyMarketplace


def test_list_available_packs() -> None:
    marketplace = PolicyMarketplace()
    names = [item.name for item in marketplace.list_available()]
    assert "hipaa" in names
    assert "soc2" in names
    assert "openclaw-secure" in names
    assert "development" in names


def test_get_pack_by_name() -> None:
    marketplace = PolicyMarketplace()
    pack = marketplace.get("hipaa")
    assert pack is not None
    assert pack.name == "hipaa"


def test_install_pack_creates_policy(tmp_path: Path) -> None:
    marketplace = PolicyMarketplace()
    target = tmp_path / "policy.yaml"
    written = marketplace.install("hipaa", target_path=str(target), merge=False)
    assert Path(written).exists()
    payload = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert isinstance(payload.get("rules"), list)


def test_install_pack_merge(tmp_path: Path) -> None:
    target = tmp_path / "policy.yaml"
    target.write_text("rules:\n  - name: budget_limit\n    max_cost_per_call: 1.0\n", encoding="utf-8")
    marketplace = PolicyMarketplace()
    marketplace.install("development", target_path=str(target), merge=True)
    payload = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert isinstance(payload.get("rules"), list)
    assert len(payload["rules"]) >= 2


def test_validate_pack() -> None:
    marketplace = PolicyMarketplace()
    pack = marketplace.get("development")
    assert pack is not None
    assert marketplace.validate_pack(pack) == []


def test_hipaa_pack_valid() -> None:
    marketplace = PolicyMarketplace()
    pack = marketplace.get("hipaa")
    assert pack is not None
    assert marketplace.validate_pack(pack) == []


def test_soc2_pack_valid() -> None:
    marketplace = PolicyMarketplace()
    pack = marketplace.get("soc2")
    assert pack is not None
    assert marketplace.validate_pack(pack) == []


def test_openclaw_pack_valid() -> None:
    marketplace = PolicyMarketplace()
    pack = marketplace.get("openclaw-secure")
    assert pack is not None
    assert marketplace.validate_pack(pack) == []


def test_marketplace_cli_list() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["marketplace"])
    assert result.exit_code == 0
    assert "Available Policy Packs:" in result.output
    assert "hipaa" in result.output


def test_marketplace_cli_install() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["marketplace", "install", "hipaa", "--target", "policy.yaml"])
        assert result.exit_code == 0
        assert "Installing policy pack: hipaa" in result.output
        assert Path("policy.yaml").exists()
