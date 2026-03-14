from __future__ import annotations

import json
from pathlib import Path

from orchesis.scanner import (
    REMEDIATION_GUIDE,
    McpConfigScanner,
    ScanFinding,
    format_report_markdown,
    format_report_text,
)


def _scan_servers(tmp_path: Path, servers: dict) -> tuple[list, object]:
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    report = McpConfigScanner().scan(str(path))
    return report.findings, report


def _has(findings: list, category: str, severity: str | None = None, needle: str | None = None) -> bool:
    for item in findings:
        if item.category != category:
            continue
        if severity is not None and item.severity != severity:
            continue
        if needle is not None and needle not in item.description and needle not in item.evidence:
            continue
        return True
    return False


def test_remediation_field_exists() -> None:
    finding = ScanFinding("high", "secret_leak", "desc", "loc", "ev")
    assert hasattr(finding, "remediation")


def test_remediation_populated(tmp_path: Path) -> None:
    findings, _report = _scan_servers(tmp_path, {"s1": {"command": "npx", "args": ["mcp-remote@0.1.15"], "auth": "token"}})
    assert any(item.remediation for item in findings)


def test_remediation_guide_coverage() -> None:
    required = {
        "supply_chain_cve",
        "malicious_package",
        "typosquatting",
        "supply_chain",
        "version_pinning",
        "secret_leak",
        "docker_security",
        "permissions",
        "transport_security",
        "shell_execution",
        "privilege_escalation",
        "path_traversal",
        "file_access",
        "exfiltration_risk",
        "attack_surface",
        "credential_sharing",
        "cors_missing",
        "binding_exposure",
        "no_auth",
        "websocket_no_origin_check",
        "suspicious_url",
        "dangerous_tools",
    }
    assert required.issubset(set(REMEDIATION_GUIDE.keys()))


def test_server_scores_populated(tmp_path: Path) -> None:
    _findings, report = _scan_servers(tmp_path, {"alpha": {"command": "node", "auth": "token"}})
    assert isinstance(report.server_scores, dict)
    assert "alpha" in report.server_scores


def test_server_scores_high_risk(tmp_path: Path) -> None:
    _findings, report = _scan_servers(tmp_path, {"risk": {"url": "http://0.0.0.0:8080"}})
    assert report.server_scores["risk"] >= 40


def test_server_scores_clean(tmp_path: Path) -> None:
    _findings, report = _scan_servers(
        tmp_path,
        {"clean": {"command": "node", "auth": "token", "url": "https://localhost:8443", "cors": {"allow": ["*"]}}},
    )
    assert report.server_scores["clean"] == 0


def test_attack_surface_score_exists(tmp_path: Path) -> None:
    _findings, report = _scan_servers(tmp_path, {"s1": {"command": "node", "auth": "token"}})
    assert isinstance(report.attack_surface_score, int)


def test_attack_surface_increases_with_findings(tmp_path: Path) -> None:
    _a_findings, report_a = _scan_servers(tmp_path, {"a": {"command": "node", "auth": "token"}})
    _b_findings, report_b = _scan_servers(tmp_path, {"a": {"url": "http://0.0.0.0:8080"}})
    assert report_b.attack_surface_score >= report_a.attack_surface_score


def test_deprecated_package_detected(tmp_path: Path) -> None:
    findings, _report = _scan_servers(tmp_path, {"s1": {"command": "npx", "args": ["mcp-tools@1.0.0"], "auth": "token"}})
    assert _has(findings, "deprecated_package", "low")


def test_deprecated_no_false_positive(tmp_path: Path) -> None:
    findings, _report = _scan_servers(tmp_path, {"s1": {"command": "npx", "args": ["my-safe-package@1.0.0"], "auth": "token"}})
    assert not _has(findings, "deprecated_package")


def test_format_text_includes_remediation(tmp_path: Path) -> None:
    _findings, report = _scan_servers(tmp_path, {"s1": {"command": "npx", "args": ["mcp-remote@0.1.15"], "auth": "token"}})
    rendered = format_report_text(report)
    assert "→" in rendered


def test_format_markdown_includes_remediation(tmp_path: Path) -> None:
    _findings, report = _scan_servers(tmp_path, {"s1": {"command": "npx", "args": ["mcp-remote@0.1.15"], "auth": "token"}})
    rendered = format_report_markdown(report)
    assert "**Remediation:**" in rendered


def test_format_text_server_scores(tmp_path: Path) -> None:
    _findings, report = _scan_servers(tmp_path, {"s1": {"url": "http://0.0.0.0:8080"}})
    rendered = format_report_text(report)
    assert "Server Risk Scores:" in rendered


def test_server_scores_capped_100(tmp_path: Path) -> None:
    _findings, report = _scan_servers(
        tmp_path,
        {"s1": {"url": "http://0.0.0.0:8080", "command": "bash", "args": ["sudo", "../../../etc/passwd"], "tools": ["*"]}},
    )
    assert report.server_scores["s1"] <= 100


def test_remediation_default_fallback() -> None:
    finding = ScanFinding("low", "unknown_category", "desc", "loc", "ev")
    assert finding.remediation == "Review and address this security issue."


def test_scan_report_backward_compatible(tmp_path: Path) -> None:
    _findings, report = _scan_servers(tmp_path, {"s1": {"command": "node", "auth": "token"}})
    assert hasattr(report, "target")
    assert hasattr(report, "target_type")
    assert hasattr(report, "findings")
    assert hasattr(report, "risk_score")
    assert hasattr(report, "summary")
    assert hasattr(report, "scanned_at")


def test_all_phases_still_pass(tmp_path: Path) -> None:
    findings, _report = _scan_servers(
        tmp_path,
        {
            "s1": {"command": "npx", "args": ["mcp-remote@0.1.15"], "auth": "token", "autoApprove": True},
            "s2": {"command": "bash", "args": ["sudo", "../../../etc/passwd"], "auth": "token"},
        },
    )
    assert _has(findings, "supply_chain_cve", "critical")
    assert _has(findings, "permissions", "high")
    assert _has(findings, "privilege_escalation", "critical")


def test_server_score_location_matching(tmp_path: Path) -> None:
    _findings, report = _scan_servers(
        tmp_path,
        {
            "one": {"url": "http://0.0.0.0:8080"},
            "two": {"command": "node", "auth": "token"},
        },
    )
    assert report.server_scores["one"] > report.server_scores["two"]

