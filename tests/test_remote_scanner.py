from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis.contrib.remote_scanner import RemoteSkillScanner


def test_scan_url_fetches_and_scans(monkeypatch) -> None:
    scanner = RemoteSkillScanner()
    monkeypatch.setattr(
        scanner,
        "_fetch_text",
        lambda url: (url, "Use subprocess.run and token sk-abcdefghijklmnopqrstuvwxyz123"),
    )
    report = scanner.scan_url("https://example.com/SKILL.md")
    assert report.findings


def test_scan_url_timeout(monkeypatch) -> None:
    scanner = RemoteSkillScanner()

    def _raise(url):
        _ = url
        raise TimeoutError("timeout")

    monkeypatch.setattr(scanner, "_fetch_text", _raise)
    with pytest.raises(TimeoutError):
        scanner.scan_url("https://example.com/SKILL.md")


def test_scan_url_too_large(monkeypatch) -> None:
    scanner = RemoteSkillScanner()

    def _raise(url):
        _ = url
        raise ValueError("Remote content too large (>1MB)")

    monkeypatch.setattr(scanner, "_fetch_text", _raise)
    with pytest.raises(ValueError):
        scanner.scan_url("https://example.com/large.md")


def test_scan_url_invalid_scheme() -> None:
    scanner = RemoteSkillScanner()
    with pytest.raises(ValueError):
        scanner.scan_url("file:///tmp/SKILL.md")


def test_scan_clawhub_constructs_url(monkeypatch) -> None:
    scanner = RemoteSkillScanner()
    calls: list[str] = []
    original_scan_url = scanner.scan_url

    def _scan_url(url: str):
        calls.append(url)
        return original_scan_url(url)

    monkeypatch.setattr(scanner, "_fetch_text", lambda url: (url, "Safe instructions"))
    monkeypatch.setattr(scanner, "scan_url", _scan_url)
    scanner.scan_clawhub("clawhub:moltyverse-email")
    assert calls[0] == "https://clawhub.com/skills/moltyverse-email/SKILL.md"


def test_scan_npm_young_package_warning(monkeypatch) -> None:
    scanner = RemoteSkillScanner()
    metadata = {
        "name": "pkg",
        "time": {"created": "2026-01-01T00:00:00.000Z"},
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {"scripts": {}}},
    }
    monkeypatch.setattr(scanner, "_fetch_text", lambda url: (url, json.dumps(metadata)))
    monkeypatch.setattr("time.time", lambda: 1767312000.0)  # 2026-01-02
    report = scanner.scan_npm_package("npm:pkg")
    assert any(item.category == "new_package_risk" for item in report.findings)


def test_scan_npm_typosquat_detection(monkeypatch) -> None:
    scanner = RemoteSkillScanner()
    metadata = {"name": "n0de", "dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {"scripts": {}}}}
    monkeypatch.setattr(scanner, "_fetch_text", lambda url: (url, json.dumps(metadata)))
    report = scanner.scan_npm_package("npm:n0de")
    assert any(item.category == "typosquat_risk" for item in report.findings)


def test_batch_scan_multiple(monkeypatch) -> None:
    scanner = RemoteSkillScanner()
    monkeypatch.setattr(scanner, "scan_clawhub", lambda target: scanner.scan_url("https://example.com/SKILL.md"))
    monkeypatch.setattr(scanner, "scan_npm_package", lambda target: scanner.scan_url("https://example.com/SKILL.md"))
    monkeypatch.setattr(scanner, "scan_github", lambda target: scanner.scan_url("https://example.com/SKILL.md"))
    monkeypatch.setattr(scanner, "_fetch_text", lambda url: (url, "Safe instructions"))
    reports = scanner.batch_scan(["clawhub:a", "npm:a", "https://github.com/a/b/blob/main/SKILL.md"])
    assert len(reports) == 3


def test_remote_cli_integration(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "orchesis.contrib.remote_scanner.RemoteSkillScanner.scan_url",
        lambda self, target: self.batch_scan(["https://example.com/SKILL.md"])[0],
    )
    monkeypatch.setattr(
        "orchesis.contrib.remote_scanner.RemoteSkillScanner.batch_scan",
        lambda self, targets: [
            type("R", (), {"target": targets[0], "target_type": "remote", "findings": [], "risk_score": 0, "summary": "No findings detected.", "scanned_at": "now"})()  # type: ignore[misc]
        ],
    )
    runner = CliRunner()
    with runner.isolated_filesystem():
        batch = Path("skills.txt")
        batch.write_text("https://example.com/SKILL.md\n", encoding="utf-8")
        result = runner.invoke(main, ["scan-remote", "--batch", str(batch)])
    assert result.exit_code == 0
    assert "Scanning:" in result.output
