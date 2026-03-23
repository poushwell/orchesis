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


def discover_mcp_config_paths() -> list[Path]:
    """Return known MCP JSON config paths that exist (delegates to ``discover_mcp_configs``)."""
    from orchesis.scanner import discover_mcp_configs

    return discover_mcp_configs()


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
        "policy_startup_validation": "Policy loads and passes startup validation",
        "listen_ports_available": "Proxy and dashboard listen ports are free",
        "python_environment": "Python version and optional dependencies",
        "mcp_config_discovery": "MCP config files discovered and scanned",
        "upstream_connectivity": "Upstream proxy.target reachable (HTTP HEAD)",
        "data_directory_disk_space": "Free space for Orchesis data directory",
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
            if check_id == "policy_startup_validation":
                return self._check_policy_startup_validation(policy_path)
            if check_id == "listen_ports_available":
                return self._check_listen_ports_available(policy_path)
            if check_id == "python_environment":
                return self._check_python_environment()
            if check_id == "mcp_config_discovery":
                return self._check_mcp_config_discovery()
            if check_id == "upstream_connectivity":
                return self._check_upstream_connectivity(policy_path)
            if check_id == "data_directory_disk_space":
                return self._check_data_directory_disk_space()
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

    def _check_policy_startup_validation(self, policy_path: str) -> dict[str, Any]:
        from orchesis.config import ConfigError, PolicyError, load_policy, validate_startup_policy

        p = Path(policy_path)
        if not p.exists():
            return {
                "status": "WARN",
                "message": f"{policy_path} — file not found; startup validation skipped",
                "warnings_count": 0,
            }
        try:
            policy = load_policy(p)
        except ConfigError as error:
            return {"status": "FAIL", "message": f"{policy_path} — {error}", "warnings_count": 0}
        except PolicyError as error:
            return {"status": "FAIL", "message": f"{policy_path} — {error}", "warnings_count": 0}
        except Exception as error:
            return {"status": "FAIL", "message": f"{policy_path} — policy load failed: {error}", "warnings_count": 0}

        proxy_cfg = policy.get("proxy") if isinstance(policy.get("proxy"), dict) else {}
        listen_raw = proxy_cfg.get("listen_port", proxy_cfg.get("port"))
        listen_port: int | None = None
        if isinstance(listen_raw, int | float):
            try:
                lp = int(listen_raw)
                if 1 <= lp <= 65535:
                    listen_port = lp
            except (TypeError, ValueError):
                listen_port = None

        critical, warnings = validate_startup_policy(policy, listen_port=listen_port)
        n_warn = len(warnings)
        if critical:
            joined = "; ".join(critical[:5])
            return {
                "status": "FAIL",
                "message": f"{policy_path} — parse OK; {n_warn} warning(s); critical: {joined}",
                "warnings_count": n_warn,
            }
        if n_warn:
            return {
                "status": "WARN",
                "message": f"{policy_path} — parse OK; {n_warn} warning(s)",
                "warnings_count": n_warn,
            }
        return {
            "status": "PASS",
            "message": f"{policy_path} — parse OK; 0 warning(s)",
            "warnings_count": 0,
        }

    def _check_listen_ports_available(self, policy_path: str) -> dict[str, Any]:
        proxy_port = 8080
        dashboard_port = 8081
        p = Path(policy_path)
        if p.exists():
            try:
                import yaml

                cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                if isinstance(cfg, dict):
                    pc = cfg.get("proxy")
                    if isinstance(pc, dict):
                        lp = pc.get("listen_port", pc.get("port"))
                        if isinstance(lp, int | float):
                            try:
                                proxy_port = int(lp)
                            except (TypeError, ValueError):
                                pass
                        elif isinstance(lp, str) and lp.strip().isdigit():
                            proxy_port = int(lp.strip())
            except Exception:
                pass

        host = "127.0.0.1"

        def _port_in_use(port: int) -> bool:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.settimeout(0.5)
                return probe.connect_ex((host, port)) == 0
            except OSError:
                return False
            finally:
                probe.close()

        parts: list[str] = []
        any_in_use = False
        for label, port in (("Proxy", proxy_port), ("Dashboard", dashboard_port)):
            if _port_in_use(port):
                parts.append(f"{label} port {port} in use (not free)")
                any_in_use = True
            else:
                parts.append(f"{label} port {port} available")
        status = "WARN" if any_in_use else "PASS"
        return {"status": status, "message": " — ".join(parts)}

    def _check_python_environment(self) -> dict[str, Any]:
        import importlib.util
        import sys
        from importlib.metadata import PackageNotFoundError, version

        if sys.version_info < (3, 10):
            return {
                "status": "FAIL",
                "message": f"Python {sys.version_info[0]}.{sys.version_info[1]} < 3.10 required",
            }

        chunks: list[str] = [
            f"Python {sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]} OK",
        ]
        optional = (
            ("yaml", "PyYAML"),
            ("fastapi", "fastapi"),
            ("uvicorn", "uvicorn"),
            ("httpx", "httpx"),
        )
        for import_name, dist_name in optional:
            spec = importlib.util.find_spec(import_name)
            if spec is None:
                chunks.append(f"{dist_name} not installed (optional)")
            else:
                try:
                    ver = version(dist_name)
                except PackageNotFoundError:
                    ver = "installed"
                chunks.append(f"{dist_name} {ver}")
        return {"status": "PASS", "message": "; ".join(chunks)}

    def _check_mcp_config_discovery(self) -> dict[str, Any]:
        from orchesis.scanner import McpConfigScanner

        paths = discover_mcp_config_paths()
        if not paths:
            return {"status": "PASS", "message": "found 0 MCP config files at: [] — 0 findings (0 critical, 0 high)"}

        scanner = McpConfigScanner()
        total = critical = high = 0
        for path in paths:
            try:
                report = scanner.scan(str(path))
            except Exception as error:
                return {"status": "WARN", "message": f"scan failed for {path}: {error}"}
            for item in report.findings:
                total += 1
                sev = str(item.severity).lower()
                if sev == "critical":
                    critical += 1
                elif sev == "high":
                    high += 1

        listed = ", ".join(str(x) for x in paths)
        return {
            "status": "PASS",
            "message": f"found {len(paths)} MCP config file(s) at: [{listed}] — {total} total findings ({critical} critical, {high} high)",
        }

    def _check_upstream_connectivity(self, policy_path: str) -> dict[str, Any]:
        import time
        import urllib.error
        import urllib.request

        p = Path(policy_path)
        if not p.exists():
            return {"status": "WARN", "message": f"{policy_path} missing — upstream check skipped"}

        try:
            import yaml

            cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception as error:
            return {"status": "WARN", "message": f"could not read policy: {error}"}

        if not isinstance(cfg, dict):
            return {"status": "WARN", "message": "policy not a mapping — upstream check skipped"}

        proxy_cfg = cfg.get("proxy")
        target: str | None = None
        if isinstance(proxy_cfg, dict):
            raw = proxy_cfg.get("target")
            if isinstance(raw, str) and raw.strip():
                target = raw.strip()

        if not target:
            return {"status": "PASS", "message": "no proxy.target in policy — upstream check skipped"}

        started = time.perf_counter()
        try:
            req = urllib.request.Request(target, method="HEAD")
            with urllib.request.urlopen(req, timeout=5) as resp:
                code = getattr(resp, "status", None) or resp.getcode()
            ms = (time.perf_counter() - started) * 1000
            return {
                "status": "PASS",
                "message": f"reachable — HTTP {int(code)}, {ms:.0f}ms latency",
            }
        except urllib.error.HTTPError as error:
            ms = (time.perf_counter() - started) * 1000
            return {
                "status": "PASS",
                "message": f"reachable — HTTP {error.code}, {ms:.0f}ms latency",
            }
        except Exception as error:
            return {"status": "WARN", "message": f"unreachable — {error}"}

    def _check_data_directory_disk_space(self) -> dict[str, Any]:
        import shutil

        data_dir = Path(".orchesis")
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        try:
            resolved = data_dir.resolve()
            anchor = resolved if resolved.exists() else Path.cwd().resolve()
            free_b = shutil.disk_usage(anchor).free
            free_mb = int(free_b // (1024 * 1024))
            if free_mb < 100:
                return {
                    "status": "WARN",
                    "message": f".orchesis — {free_mb}MB free (< 100MB)",
                }
            return {"status": "PASS", "message": f".orchesis — {free_mb}MB free"}
        except OSError as error:
            return {"status": "WARN", "message": f"could not read disk usage — {error}"}

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

    def _check_openclaw_compat(self, policy_path: str) -> dict[str, Any]:
        """Check if policy is compatible with OpenClaw agents."""
        import yaml

        p = Path(policy_path)
        if not p.exists():
            return {"status": "WARN", "message": "No policy file - OpenClaw compatibility not checked"}
        try:
            cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception as error:
            return {"status": "WARN", "message": f"Could not parse policy: {error}"}
        if not isinstance(cfg, dict):
            return {"status": "WARN", "message": "Policy format invalid for OpenClaw compatibility checks"}

        issues: list[str] = []
        warnings: list[str] = []

        threat_config = cfg.get("threat_intel", {})
        if isinstance(threat_config, dict):
            disabled = threat_config.get("disabled_threats", [])
            disabled_list = [str(item) for item in disabled] if isinstance(disabled, list) else []
            default_action = str(threat_config.get("default_action", "block")).strip().lower() or "block"
            if "ORCH-TA-002" not in disabled_list and default_action == "block":
                issues.append(
                    "ORCH-TA-002 is active with block action. This can cause false positives for OpenClaw tool calls. "
                    "Fix: add ORCH-TA-002 to threat_intel.disabled_threats or set threat_intel.default_action: warn."
                )

        loop_config = cfg.get("loop_detection", {})
        if isinstance(loop_config, dict):
            if loop_config.get("openclaw_memory_whitelist", True) is False:
                warnings.append(
                    "loop_detection.openclaw_memory_whitelist is disabled. This can trigger false loop warnings "
                    "for OpenClaw memory reads."
                )

        if issues:
            details = issues + warnings
            return {
                "status": "FAIL",
                "message": f"Found {len(issues)} OpenClaw compatibility issue(s)",
                "details": details,
            }
        if warnings:
            return {
                "status": "WARN",
                "message": "OpenClaw compatibility warnings found",
                "details": warnings,
            }
        return {"status": "PASS", "message": "Policy is OpenClaw-compatible"}

    def format_report(self, result: dict[str, Any]) -> str:
        lines = ["\norchesis verify\n" + "-" * 40]
        for check_id, check in result["checks"].items():
            status = check["status"]
            label = self.CHECKS.get(check_id, check_id.replace("_", " ").title())
            lines.append(f"[{status}] {label} — {check['message']}")
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


def check_openclaw_compatibility(orchesis_config_path: Path | None = None) -> CheckResult:
    """Validate OpenClaw-related compatibility flags in Orchesis policy."""
    import yaml

    candidates = []
    if orchesis_config_path is not None:
        candidates.append(orchesis_config_path)
    candidates.extend([Path("orchesis.yaml"), Path("policy.yaml")])
    policy_file = next((path for path in candidates if path.exists()), None)
    if policy_file is None:
        return CheckResult(
            name="openclaw_compatibility",
            severity=Severity.WARNING,
            message="Orchesis policy not found - cannot verify OpenClaw compatibility",
            fix="Create orchesis.yaml with threat_intel and loop_detection sections.",
        )

    try:
        cfg = yaml.safe_load(policy_file.read_text(encoding="utf-8")) or {}
    except Exception as error:
        return CheckResult(
            name="openclaw_compatibility",
            severity=Severity.WARNING,
            message=f"Could not parse policy for OpenClaw compatibility: {error}",
        )
    if not isinstance(cfg, dict):
        return CheckResult(
            name="openclaw_compatibility",
            severity=Severity.WARNING,
            message="Policy format invalid for OpenClaw compatibility checks",
        )

    issues: list[str] = []
    warnings: list[str] = []

    threat_config = cfg.get("threat_intel", {})
    if isinstance(threat_config, dict):
        disabled = threat_config.get("disabled_threats", [])
        disabled_list = [str(item) for item in disabled] if isinstance(disabled, list) else []
        default_action = str(threat_config.get("default_action", "block")).strip().lower() or "block"
        if "ORCH-TA-002" not in disabled_list and default_action == "block":
            issues.append(
                "ORCH-TA-002 is active with block action and may false-positive OpenClaw tool calls."
            )

    loop_config = cfg.get("loop_detection", {})
    if isinstance(loop_config, dict):
        if loop_config.get("openclaw_memory_whitelist", True) is False:
            warnings.append(
                "openclaw_memory_whitelist is disabled; memory read loops may be incorrectly flagged."
            )

    if issues:
        details = "; ".join(issues + warnings)
        return CheckResult(
            name="openclaw_compatibility",
            severity=Severity.CRITICAL,
            message=f"Found {len(issues)} OpenClaw compatibility issue(s)",
            detail=details,
            fix=(
                "Set threat_intel.disabled_threats to include ORCH-TA-002 or set "
                "threat_intel.default_action: warn."
            ),
        )
    if warnings:
        return CheckResult(
            name="openclaw_compatibility",
            severity=Severity.WARNING,
            message="OpenClaw compatibility warning(s) found",
            detail="; ".join(warnings),
            fix="Set loop_detection.openclaw_memory_whitelist: true.",
        )
    return CheckResult(
        name="openclaw_compatibility",
        severity=Severity.OK,
        message="Policy is OpenClaw-compatible",
    )


def run_all_checks(
    openclaw_config_path: Path | None = None,
    orchesis_config_path: Path | None = None,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8080,
) -> VerifyReport:
    report = VerifyReport()
    report.add(check_config_schema_injection(openclaw_config_path))
    report.add(check_proxy_connectivity(proxy_host=proxy_host, proxy_port=proxy_port))
    report.add(check_openclaw_proxy_routing(openclaw_config_path=openclaw_config_path))
    report.add(check_openclaw_compatibility(orchesis_config_path=orchesis_config_path))
    return report
