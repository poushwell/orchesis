"""orchesis verify - instant value before any security features.

Finds config schema injection bug -> ~$270/month overspend at defaults.
First command a new user runs.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class OrchesisVerifier:
    """Runs pre-flight checks on Orchesis + OpenClaw config."""

    CHECKS = {
        "proxy_reachable": "Proxy is running and reachable",
        "policy_valid": "Policy file is valid YAML",
        "schema_injection_risk": "Config schema not leaking to LLM context",
        "openclaw_routing": "OpenClaw is routed through Orchesis proxy",
        "loop_detection_enabled": "Loop detection is active",
        "loop_calibration": "Loop detection threshold is properly calibrated",
        "budget_configured": "Spending budget is configured",
        "recording_enabled": "Session recording is enabled",
        "threat_intel_active": "Threat intelligence is active",
    }

    CONFIG_SCHEMA_ISSUE = {
        "id": "ISSUE-9828",
        "title": "Config schema injection in default OpenClaw setup",
        "impact": "~100,000 extra tokens per request at defaults",
        "monthly_cost": "$270/month at Sonnet rates",
        "fix": "Set includeConfigSchema: false in OpenClaw config",
        "severity": "HIGH",
    }

    def run(self, policy_path: str = "orchesis.yaml", proxy_url: str = "http://localhost:8090") -> dict[str, Any]:
        results: dict[str, dict[str, Any]] = {}
        for check_id in self.CHECKS:
            results[check_id] = self._run_check(check_id, policy_path, proxy_url)

        passed = sum(1 for r in results.values() if r["status"] == "PASS")
        failed = sum(1 for r in results.values() if r["status"] == "FAIL")
        warnings = sum(1 for r in results.values() if r["status"] == "WARN")

        return {
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "total": len(results),
            "checks": results,
            "ready": failed == 0,
            "schema_injection_found": results.get("schema_injection_risk", {}).get("status") == "FAIL",
        }

    def _run_check(self, check_id: str, policy_path: str, proxy_url: str) -> dict[str, Any]:
        try:
            if check_id == "proxy_reachable":
                return self._check_proxy(proxy_url)
            if check_id == "policy_valid":
                return self._check_policy(policy_path)
            if check_id == "schema_injection_risk":
                return self._check_schema_injection()
            if check_id == "openclaw_routing":
                return self._check_openclaw_routing(proxy_url)
            if check_id == "loop_detection_enabled":
                return self._check_policy_flag(policy_path, "loop_detection")
            if check_id == "loop_calibration":
                return self._check_loop_calibration(policy_path)
            if check_id == "budget_configured":
                return self._check_policy_flag(policy_path, "budgets")
            if check_id == "recording_enabled":
                return self._check_policy_flag(policy_path, "recording")
            if check_id == "threat_intel_active":
                return self._check_policy_flag(policy_path, "threat_intel")
        except Exception as error:  # pragma: no cover - defensive fallback
            return {"status": "WARN", "message": str(error)}
        return {"status": "WARN", "message": "Unknown check"}

    def _check_proxy(self, proxy_url: str) -> dict[str, Any]:
        import urllib.request

        try:
            url = proxy_url.rstrip("/") + "/health"
            urllib.request.urlopen(url, timeout=2)
            return {"status": "PASS", "message": "Proxy is running"}
        except Exception:
            return {"status": "WARN", "message": "Proxy not running (start with: orchesis proxy)"}

    def _check_policy(self, policy_path: str) -> dict[str, Any]:
        import yaml

        p = Path(policy_path)
        if not p.exists():
            return {"status": "WARN", "message": f"No policy file at {policy_path}"}
        try:
            yaml.safe_load(p.read_text(encoding="utf-8"))
            return {"status": "PASS", "message": "Policy file is valid"}
        except Exception as error:
            return {"status": "FAIL", "message": f"Invalid YAML: {error}"}

    def _check_schema_injection(self) -> dict[str, Any]:
        """Check for OpenClaw config schema injection (Issue #9828)."""
        openclaw_config_paths = [
            Path.home() / ".openclaw" / "config.json",
            Path(".openclaw") / "config.json",
            Path("openclaw.config.json"),
        ]
        for config_path in openclaw_config_paths:
            if config_path.exists():
                try:
                    cfg = json.loads(config_path.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if not isinstance(cfg, dict):
                    continue
                include_schema = cfg.get("includeConfigSchema", True)
                if include_schema:
                    return {
                        "status": "FAIL",
                        "message": (
                            "Config schema injection detected! "
                            f"~$270/month overspend. Fix: {self.CONFIG_SCHEMA_ISSUE['fix']}"
                        ),
                        "issue": self.CONFIG_SCHEMA_ISSUE,
                    }
                return {"status": "PASS", "message": "Config schema not injected"}
        return {"status": "WARN", "message": "OpenClaw config not found - manual check recommended"}

    def _check_openclaw_routing(self, proxy_url: str) -> dict[str, Any]:
        """Check if OpenClaw is routed through Orchesis proxy."""
        openclaw_config_paths = [
            Path.home() / ".openclaw" / "config.json",
            Path(".openclaw") / "config.json",
        ]
        for config_path in openclaw_config_paths:
            if config_path.exists():
                try:
                    cfg = json.loads(config_path.read_text(encoding="utf-8"))
                    api_base = cfg.get("apiBaseUrl", "") or cfg.get("baseUrl", "")
                    proxy_host = proxy_url.replace("http://", "").replace("https://", "")
                    if proxy_host in api_base or "localhost:8080" in api_base:
                        return {
                            "status": "PASS",
                            "message": f"OpenClaw routed through proxy: {api_base}",
                        }
                    return {
                        "status": "FAIL",
                        "message": (
                            "OpenClaw NOT routed through proxy. "
                            f"Current: {api_base}. "
                            f"Fix: set apiBaseUrl to {proxy_url}"
                        ),
                    }
                except Exception as error:
                    return {"status": "WARN", "message": f"Could not parse config: {error}"}
        return {"status": "WARN", "message": "OpenClaw config not found"}

    def _check_loop_calibration(self, policy_path: str) -> dict[str, Any]:
        """Check loop detection thresholds - Issue #34574."""
        import yaml

        policy = Path(policy_path)
        if not policy.exists():
            return {"status": "WARN", "message": "No policy file"}
        cfg = yaml.safe_load(policy.read_text(encoding="utf-8")) or {}
        if not isinstance(cfg, dict):
            return {"status": "WARN", "message": "No policy file"}
        loop_detection = cfg.get("loop_detection", {})
        if not isinstance(loop_detection, dict) or not loop_detection.get("enabled"):
            return {
                "status": "WARN",
                "message": "Loop detection disabled - Issue #34574: 122 identical calls undetected",
            }
        threshold = loop_detection.get("block_threshold", 10)
        try:
            threshold_value = int(threshold)
        except (TypeError, ValueError):
            threshold_value = 10
        if threshold_value > 5:
            return {
                "status": "WARN",
                "message": (
                    f"Loop threshold {threshold_value} may be too high. "
                    "Recommend <= 5. Cost at default: $23.90/loop session"
                ),
            }
        return {
            "status": "PASS",
            "message": f"Loop detection active (threshold: {threshold_value})",
        }

    def _check_policy_flag(self, policy_path: str, section: str) -> dict[str, Any]:
        import yaml

        p = Path(policy_path)
        if not p.exists():
            return {"status": "WARN", "message": f"No policy file - {section} not configured"}
        cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(cfg, dict):
            return {"status": "WARN", "message": f"{section} not enabled in policy"}
        section_data = cfg.get(section)
        if isinstance(section_data, dict) and bool(section_data.get("enabled", False)):
            return {"status": "PASS", "message": f"{section} is enabled"}
        return {"status": "WARN", "message": f"{section} not enabled in policy"}

    def format_report(self, result: dict[str, Any]) -> str:
        lines = ["\norchesis verify\n" + "-" * 40]
        icons = {"PASS": "OK", "FAIL": "FAIL", "WARN": "WARN"}
        for check_id, check in result["checks"].items():
            icon = icons.get(check["status"], "?")
            lines.append(f"[{icon}] {check_id}: {check['message']}")
        lines.append("-" * 40)
        lines.append(
            f"{'Ready' if result['ready'] else 'Issues found'} "
            f"- {result['passed']}/{result['total']} checks passed"
        )
        if result.get("schema_injection_found"):
            lines.append("\nConfig schema injection found!")
            lines.append("   Fix: set includeConfigSchema: false")
            lines.append("   Savings: ~$270/month")
        return "\n".join(lines)


class Severity(str, Enum):
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    INFO = "info"


@dataclass
class CheckResult:
    name: str
    severity: Severity
    message: str
    detail: str | None = None
    fix: str | None = None
    doc_url: str | None = None
    estimated_monthly_cost: float | None = None


@dataclass
class VerifyReport:
    results: list[CheckResult] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return any(result.severity == Severity.CRITICAL for result in self.results)

    @property
    def has_warnings(self) -> bool:
        return any(result.severity == Severity.WARNING for result in self.results)

    def add(self, result: CheckResult) -> None:
        self.results.append(result)


def check_config_schema_injection(openclaw_config_path: Path | None = None) -> CheckResult:
    candidates = []
    if openclaw_config_path is not None:
        candidates.append(openclaw_config_path)
    candidates.extend(
        [
            Path.home() / ".openclaw" / "openclaw.json",
            Path.home() / ".openclaw" / "config.json",
            Path(".openclaw") / "config.json",
            Path("openclaw.config.json"),
            Path("openclaw.json"),
        ]
    )

    config_file = next((path for path in candidates if path.exists()), None)
    if config_file is None:
        return CheckResult(
            name="config_schema_injection",
            severity=Severity.WARNING,
            message="OpenClaw config not found - cannot verify schema injection setting",
            fix="Set includeConfigSchema: false in OpenClaw config",
        )

    try:
        cfg = json.loads(config_file.read_text(encoding="utf-8"))
    except Exception as error:
        return CheckResult(
            name="config_schema_injection",
            severity=Severity.WARNING,
            message=f"Could not parse OpenClaw config: {error}",
            fix="Ensure OpenClaw config is valid JSON",
        )

    if not isinstance(cfg, dict):
        return CheckResult(
            name="config_schema_injection",
            severity=Severity.WARNING,
            message="OpenClaw config format is unexpected",
        )

    inject_legacy = cfg.get("agents", {}).get("defaults", {}).get("injectConfigSchema", True)
    inject_new = cfg.get("includeConfigSchema", inject_legacy)
    if inject_new:
        return CheckResult(
            name="config_schema_injection",
            severity=Severity.CRITICAL,
            message="Config schema injection is ON - adding ~100,000 extra tokens to every LLM request",
            detail="OpenClaw Issue #9828. Default config leaks schema into prompt context.",
            fix="Set includeConfigSchema: false in OpenClaw config",
            doc_url="https://github.com/openclaw/openclaw/issues/9828",
            estimated_monthly_cost=270.0,
        )

    return CheckResult(
        name="config_schema_injection",
        severity=Severity.OK,
        message="Config schema injection is OFF - prompt caching enabled",
        detail="includeConfigSchema = false",
    )


def check_proxy_connectivity(proxy_host: str = "127.0.0.1", proxy_port: int = 8080) -> CheckResult:
    try:
        with socket.create_connection((proxy_host, proxy_port), timeout=2):
            return CheckResult(
                name="proxy_connectivity",
                severity=Severity.OK,
                message=f"Orchesis proxy reachable at {proxy_host}:{proxy_port}",
            )
    except Exception:
        return CheckResult(
            name="proxy_connectivity",
            severity=Severity.CRITICAL,
            message=f"Orchesis proxy not reachable at {proxy_host}:{proxy_port}",
            fix="Run: orchesis proxy --config orchesis.yaml",
        )


def check_openclaw_proxy_routing(openclaw_config_path: Path | None = None) -> CheckResult:
    candidates = []
    if openclaw_config_path is not None:
        candidates.append(openclaw_config_path)
    candidates.extend([Path.home() / ".openclaw" / "openclaw.json", Path("openclaw.json")])
    config_file = next((path for path in candidates if path.exists()), None)

    if config_file is None:
        return CheckResult(
            name="openclaw_proxy_routing",
            severity=Severity.WARNING,
            message="OpenClaw config not found - cannot verify proxy routing",
            fix='Set "proxy": {"url":"http://localhost:8080","enabled":true}',
        )

    try:
        cfg = json.loads(config_file.read_text(encoding="utf-8"))
    except Exception:
        return CheckResult(
            name="openclaw_proxy_routing",
            severity=Severity.WARNING,
            message="Could not parse OpenClaw config",
        )

    proxy_cfg = cfg.get("proxy", {}) if isinstance(cfg, dict) else {}
    proxy_url = str(proxy_cfg.get("url", "")) if isinstance(proxy_cfg, dict) else ""
    proxy_enabled = bool(proxy_cfg.get("enabled", False)) if isinstance(proxy_cfg, dict) else False

    if proxy_enabled and ("localhost:8080" in proxy_url or "127.0.0.1:8080" in proxy_url):
        return CheckResult(
            name="openclaw_proxy_routing",
            severity=Severity.OK,
            message="OpenClaw is routing through Orchesis proxy",
        )
    if not proxy_url:
        return CheckResult(
            name="openclaw_proxy_routing",
            severity=Severity.CRITICAL,
            message="OpenClaw proxy not configured - traffic bypasses Orchesis",
            fix='Set "proxy": {"url":"http://localhost:8080","enabled":true}',
        )
    return CheckResult(
        name="openclaw_proxy_routing",
        severity=Severity.WARNING,
        message=f"OpenClaw proxy not fully enabled (url={proxy_url}, enabled={proxy_enabled})",
        fix='Set "proxy": {"url":"http://localhost:8080","enabled":true}',
    )


def run_all_checks(
    openclaw_config_path: Path | None = None,
    orchesis_config_path: Path | None = None,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8080,
) -> VerifyReport:
    del orchesis_config_path
    report = VerifyReport()
    report.add(check_config_schema_injection(openclaw_config_path))
    report.add(check_proxy_connectivity(proxy_host=proxy_host, proxy_port=proxy_port))
    report.add(check_openclaw_proxy_routing(openclaw_config_path=openclaw_config_path))
    return report
