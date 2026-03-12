"""OpenClaw security auditor.

Standalone security auditing for OpenClaw config files and instances.
"""

from __future__ import annotations

import json
import os
import re
import stat
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http.client import HTTPConnection
from pathlib import Path
from typing import Any

import yaml


@dataclass
class OpenClawFinding:
    """Single security finding."""

    id: str
    severity: str
    category: str
    title: str
    description: str
    evidence: str
    fix: str
    references: list[str] = field(default_factory=list)


@dataclass
class OpenClawAuditResult:
    """Complete audit result."""

    findings: list[OpenClawFinding]
    score: int
    grade: str
    summary: dict[str, int]
    config_path: str
    timestamp: str


class OpenClawAuditor:
    """Security auditor for OpenClaw deployments."""

    _SEVERITY_PENALTY = {"critical": 25, "high": 10, "medium": 5, "low": 2}
    _SEVERITIES = ("critical", "high", "medium", "low")
    _CVE_BASE = ["CVE-2026-25253", "CVE-2026-26322", "CVE-2026-26319"]

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def audit_config(self, config_path: str) -> OpenClawAuditResult:
        """Audit an openclaw.json or openclaw.yaml config file."""

        findings: list[OpenClawFinding] = []
        config, err = self._load_config_file(config_path)
        if err is not None:
            findings.append(err)
            return self._build_result(findings, config_path)
        cfg = config if isinstance(config, dict) else {}

        self._check_default_api_keys(cfg, findings)
        self._check_hardcoded_secrets(cfg, findings)
        self._check_db_credentials(cfg, findings)
        self._check_env_gitignore(config_path, findings)
        self._check_world_readable(config_path, findings)
        self._check_exec_mode(cfg, findings)
        self._check_exec_allowlist(cfg, findings)
        self._check_exec_blocked_paths(cfg, findings)
        self._check_dev_mode(cfg, findings)
        self._check_workspace_scope(cfg, findings)
        self._check_file_limits(cfg, findings)
        self._check_browser_allowlist(cfg, findings)
        self._check_skill_version_pinning(cfg, findings)
        self._check_skill_allowlist(cfg, findings)

        return self._build_result(findings, config_path)

    def audit_gateway_config(self, gateway_path: str) -> OpenClawAuditResult:
        """Audit gateway.yaml configuration."""

        findings: list[OpenClawFinding] = []
        config, err = self._load_config_file(gateway_path)
        if err is not None:
            findings.append(err)
            return self._build_result(findings, gateway_path)
        cfg = config if isinstance(config, dict) else {}

        server = cfg.get("server") if isinstance(cfg.get("server"), dict) else {}
        host = str(server.get("host", "")).strip()
        if host == "0.0.0.0":
            findings.append(
                OpenClawFinding(
                    id="OC-001",
                    severity="critical",
                    category="exposure",
                    title="Gateway binds to public interface",
                    description="Gateway should not bind to all interfaces by default.",
                    evidence='server.host = "0.0.0.0"',
                    fix='Set host to "127.0.0.1" or place behind a reverse proxy.',
                    references=["CVE-2026-25253"],
                )
            )

        auth = cfg.get("auth") if isinstance(cfg.get("auth"), dict) else {}
        if not bool(auth.get("enabled", False)):
            findings.append(
                OpenClawFinding(
                    id="OC-002",
                    severity="critical",
                    category="auth",
                    title="Authentication disabled",
                    description="Gateway authentication is disabled or missing.",
                    evidence=f"auth.enabled = {auth.get('enabled', False)!r}",
                    fix="Set auth.enabled: true and configure API keys.",
                    references=["CVE-2026-26322"],
                )
            )

        self._check_default_api_keys(cfg, findings)
        self._check_hardcoded_secrets(cfg, findings)
        self._check_db_credentials(cfg, findings)
        self._check_env_gitignore(gateway_path, findings)
        self._check_world_readable(gateway_path, findings)

        health = cfg.get("health") if isinstance(cfg.get("health"), dict) else {}
        health_enabled = bool(health.get("enabled", True))
        if health_enabled and not bool(auth.get("enabled", False)):
            findings.append(
                OpenClawFinding(
                    id="OC-004",
                    severity="high",
                    category="exposure",
                    title="Health endpoint likely accessible without auth",
                    description="Health endpoint appears enabled while auth is disabled.",
                    evidence=f"health.enabled={health_enabled}, auth.enabled={auth.get('enabled', False)!r}",
                    fix="Require auth for health endpoint or expose it only internally.",
                    references=["CVE-2026-25253"],
                )
            )

        if not self._has_rate_limit(cfg):
            findings.append(
                OpenClawFinding(
                    id="OC-016",
                    severity="medium",
                    category="permissions",
                    title="No gateway rate limiting configured",
                    description="Gateway lacks explicit request throttling.",
                    evidence="rateLimit/rate_limit not configured",
                    fix="Configure rate limits per API key/IP.",
                    references=[],
                )
            )

        tls = cfg.get("tls") if isinstance(cfg.get("tls"), dict) else {}
        reverse_proxy = bool(cfg.get("reverse_proxy") or cfg.get("reverseProxy"))
        if not bool(tls.get("enabled", False)) and not reverse_proxy:
            findings.append(
                OpenClawFinding(
                    id="OC-017",
                    severity="high",
                    category="tls",
                    title="No TLS configured and no reverse proxy detected",
                    description="Traffic may be served over plaintext HTTP.",
                    evidence=f"tls.enabled={tls.get('enabled', False)!r}, reverse_proxy={reverse_proxy}",
                    fix="Enable TLS directly or terminate TLS at a trusted reverse proxy.",
                    references=["CVE-2026-26319"],
                )
            )

        cors = cfg.get("cors") if isinstance(cfg.get("cors"), dict) else {}
        allowed = cors.get("allowedOrigins")
        if isinstance(allowed, list) and "*" in [str(item) for item in allowed]:
            findings.append(
                OpenClawFinding(
                    id="OC-018",
                    severity="medium",
                    category="tls",
                    title="CORS allows all origins",
                    description="Wildcard CORS weakens browser-origin protections.",
                    evidence='cors.allowedOrigins contains "*"',
                    fix="Restrict CORS to trusted origin allowlist.",
                    references=[],
                )
            )

        return self._build_result(findings, gateway_path)

    def audit_instance(self, host: str, port: int = 18789) -> OpenClawAuditResult:
        """Audit a running OpenClaw instance (non-intrusive checks only)."""

        findings: list[OpenClawFinding] = []
        target = f"{host}:{int(port)}"
        try:
            conn = HTTPConnection(host, int(port), timeout=3.0)
            conn.request("GET", "/health")
            resp = conn.getresponse()
            body = resp.read(4096)
            server_header = str(resp.getheader("Server", ""))
            status = int(resp.status)
            evidence = f"GET /health -> {status}; Server={server_header or 'n/a'}; bytes={len(body)}"

            if status < 300:
                findings.append(
                    OpenClawFinding(
                        id="OC-002",
                        severity="critical",
                        category="auth",
                        title="Authentication appears disabled on running instance",
                        description="Health endpoint responded without authentication.",
                        evidence=evidence,
                        fix="Enable auth and require valid API key on sensitive endpoints.",
                        references=["CVE-2026-26322"],
                    )
                )
                if host not in ("127.0.0.1", "localhost", "::1"):
                    findings.append(
                        OpenClawFinding(
                            id="OC-004",
                            severity="high",
                            category="exposure",
                            title="Health endpoint exposed on reachable interface",
                            description="Publicly reachable health endpoint can leak operational metadata.",
                            evidence=evidence,
                            fix="Restrict health endpoint to internal network or protect with auth.",
                            references=["CVE-2026-25253"],
                        )
                    )
            elif status in (401, 403):
                pass
        except Exception:
            return self._build_result(findings, target)
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return self._build_result(findings, target)

    def generate_report(self, result: OpenClawAuditResult, format: str = "text") -> str:
        """Generate human-readable report. Formats: text, json, markdown."""

        fmt = str(format or "text").lower()
        if fmt == "json":
            return json.dumps(asdict(result), ensure_ascii=False, indent=2)
        if fmt == "markdown":
            return self._render_markdown(result)
        return self._render_text(result)

    def _load_config_file(self, config_path: str) -> tuple[dict[str, Any] | None, OpenClawFinding | None]:
        path = Path(config_path)
        if not path.exists():
            return None, OpenClawFinding(
                id="OC-900",
                severity="high",
                category="exposure",
                title="Configuration file not found",
                description="Provided configuration path does not exist.",
                evidence=str(path),
                fix="Provide a valid path to openclaw config file.",
                references=[],
            )
        try:
            text = path.read_text(encoding="utf-8")
        except Exception as exc:
            return None, OpenClawFinding(
                id="OC-901",
                severity="high",
                category="exposure",
                title="Configuration file unreadable",
                description="Could not read configuration file.",
                evidence=str(exc),
                fix="Ensure file exists and has readable permissions.",
                references=[],
            )

        if not text.strip():
            return {}, None
        try:
            if path.suffix.lower() in (".yaml", ".yml"):
                loaded = yaml.safe_load(text)
            else:
                loaded = json.loads(text)
        except Exception as exc:
            return None, OpenClawFinding(
                id="OC-902",
                severity="high",
                category="exposure",
                title="Malformed configuration",
                description="Configuration parsing failed.",
                evidence=str(exc)[:300],
                fix="Validate JSON/YAML syntax and retry.",
                references=[],
            )
        if loaded is None:
            return {}, None
        if not isinstance(loaded, dict):
            return {}, None
        return loaded, None

    def _build_result(self, findings: list[OpenClawFinding], path: str) -> OpenClawAuditResult:
        with self._lock:
            summary = {sev: 0 for sev in self._SEVERITIES}
            for finding in findings:
                sev = str(finding.severity).lower()
                if sev in summary:
                    summary[sev] += 1
            penalty = sum(self._SEVERITY_PENALTY.get(f.severity, 0) for f in findings)
            score = max(0, 100 - penalty)
            if score >= 90 and summary["critical"] == 0 and summary["high"] == 0 and summary["medium"] <= 1:
                grade = "A"
            elif score >= 75:
                grade = "B"
            elif score >= 60:
                grade = "C"
            elif score >= 40:
                grade = "D"
            else:
                grade = "F"
            return OpenClawAuditResult(
                findings=findings,
                score=int(score),
                grade=grade,
                summary=summary,
                config_path=str(path),
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

    def _flatten_strings(self, value: Any) -> list[str]:
        out: list[str] = []
        if isinstance(value, dict):
            for item in value.values():
                out.extend(self._flatten_strings(item))
        elif isinstance(value, list):
            for item in value:
                out.extend(self._flatten_strings(item))
        elif isinstance(value, str):
            out.append(value)
        return out

    def _check_default_api_keys(self, cfg: dict[str, Any], findings: list[OpenClawFinding]) -> None:
        joined = " | ".join(self._flatten_strings(cfg)).lower()
        if any(marker in joined for marker in ("change-me", "example", "sk-openclaw-example")):
            findings.append(
                OpenClawFinding(
                    id="OC-003",
                    severity="high",
                    category="auth",
                    title="Default/example API key detected",
                    description="Configuration appears to include default or placeholder credentials.",
                    evidence="Detected marker: example/change-me/sk-openclaw-example",
                    fix="Replace placeholder keys with strong unique secrets.",
                    references=self._CVE_BASE[:1],
                )
            )

    def _check_hardcoded_secrets(self, cfg: dict[str, Any], findings: list[OpenClawFinding]) -> None:
        patterns = (
            r"sk-proj-[A-Za-z0-9\-_]{8,}",
            r"sk-ant-[A-Za-z0-9\-_]{8,}",
            r"ghp_[A-Za-z0-9]{20,}",
            r"github_pat_[A-Za-z0-9_]{20,}",
        )
        for text in self._flatten_strings(cfg):
            for pattern in patterns:
                if re.search(pattern, text):
                    findings.append(
                        OpenClawFinding(
                            id="OC-005",
                            severity="critical",
                            category="secrets",
                            title="Hardcoded API key in config",
                            description="Sensitive API token appears directly in configuration.",
                            evidence=text[:120],
                            fix="Move keys to secure environment variables or secret manager.",
                            references=["CVE-2026-26322"],
                        )
                    )
                    return

    def _check_db_credentials(self, cfg: dict[str, Any], findings: list[OpenClawFinding]) -> None:
        pattern = re.compile(r"(postgres|mysql|mongodb|redis)://[^:@\s]+:[^@\s]+@", re.IGNORECASE)
        for text in self._flatten_strings(cfg):
            if pattern.search(text):
                findings.append(
                    OpenClawFinding(
                        id="OC-006",
                        severity="high",
                        category="secrets",
                        title="Database credentials in config",
                        description="Connection string appears to include inline credentials.",
                        evidence=text[:140],
                        fix="Store DB credentials in secret manager or env vars.",
                        references=[],
                    )
                )
                return

    def _check_env_gitignore(self, config_path: str, findings: list[OpenClawFinding]) -> None:
        parent = Path(config_path).resolve().parent
        gitignore = parent / ".gitignore"
        if not gitignore.exists():
            findings.append(
                OpenClawFinding(
                    id="OC-007",
                    severity="medium",
                    category="secrets",
                    title=".env not protected by .gitignore",
                    description="No .gitignore found next to config; .env may be committed.",
                    evidence=str(gitignore),
                    fix='Create .gitignore and add ".env" pattern.',
                    references=[],
                )
            )
            return
        try:
            text = gitignore.read_text(encoding="utf-8")
        except Exception:
            text = ""
        if ".env" not in text:
            findings.append(
                OpenClawFinding(
                    id="OC-007",
                    severity="medium",
                    category="secrets",
                    title=".env not protected by .gitignore",
                    description=".env was not found in .gitignore patterns.",
                    evidence=".gitignore missing .env",
                    fix='Add ".env" and related secret files to .gitignore.',
                    references=[],
                )
            )

    def _check_world_readable(self, config_path: str, findings: list[OpenClawFinding]) -> None:
        # Windows ACL semantics do not map cleanly to POSIX rwx bits.
        if os.name == "nt":
            return
        try:
            mode = stat.S_IMODE(os.stat(config_path).st_mode)
            if mode > 0o644:
                findings.append(
                    OpenClawFinding(
                        id="OC-008",
                        severity="high",
                        category="permissions",
                        title="Config file permissions are too broad",
                        description="Config appears world-readable/writable.",
                        evidence=f"mode={oct(mode)}",
                        fix="Restrict file mode to 0600 or 0640.",
                        references=[],
                    )
                )
        except Exception:
            return

    def _check_exec_mode(self, cfg: dict[str, Any], findings: list[OpenClawFinding]) -> None:
        exec_cfg = self._exec_cfg(cfg)
        mode = str(exec_cfg.get("mode", "sandboxed")).lower()
        if mode != "sandboxed":
            findings.append(
                OpenClawFinding(
                    id="OC-009",
                    severity="high",
                    category="exec",
                    title="Unrestricted exec mode",
                    description="Tool execution mode is not sandboxed.",
                    evidence=f"tools.exec.mode={mode!r}",
                    fix='Set tools.exec.mode to "sandboxed".',
                    references=["CVE-2026-26319"],
                )
            )

    def _check_exec_allowlist(self, cfg: dict[str, Any], findings: list[OpenClawFinding]) -> None:
        exec_cfg = self._exec_cfg(cfg)
        allowed = exec_cfg.get("allowedCommands")
        if not isinstance(allowed, list) or len(allowed) == 0:
            findings.append(
                OpenClawFinding(
                    id="OC-010",
                    severity="high",
                    category="exec",
                    title="No command allowlist configured",
                    description="Exec tool has no explicit allowed command list.",
                    evidence="tools.exec.allowedCommands missing/empty",
                    fix="Define a minimal allowedCommands list.",
                    references=[],
                )
            )

    def _check_exec_blocked_paths(self, cfg: dict[str, Any], findings: list[OpenClawFinding]) -> None:
        exec_cfg = self._exec_cfg(cfg)
        blocked = exec_cfg.get("blockedPaths")
        if not isinstance(blocked, list) or len(blocked) == 0:
            findings.append(
                OpenClawFinding(
                    id="OC-011",
                    severity="medium",
                    category="exec",
                    title="No blocked paths configured",
                    description="Exec file-path restrictions are missing.",
                    evidence="tools.exec.blockedPaths missing/empty",
                    fix="Block sensitive paths (/etc, /root, ~/.ssh, etc.).",
                    references=[],
                )
            )

    def _check_dev_mode(self, cfg: dict[str, Any], findings: list[OpenClawFinding]) -> None:
        mode = str(cfg.get("mode", "")).lower()
        env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
        node_env = str(env.get("NODE_ENV", "")).lower()
        if mode == "development" or node_env in ("", "development"):
            findings.append(
                OpenClawFinding(
                    id="OC-012",
                    severity="high",
                    category="exec",
                    title="Development mode configuration detected",
                    description="Development defaults are unsafe for internet-facing deployments.",
                    evidence=f"mode={mode!r}, NODE_ENV={node_env!r}",
                    fix='Set mode="production" and NODE_ENV="production".',
                    references=[],
                )
            )

    def _check_workspace_scope(self, cfg: dict[str, Any], findings: list[OpenClawFinding]) -> None:
        workspace = str(cfg.get("workspace", "")).strip().replace("\\", "/")
        broad = workspace in ("/", "", "C:", "C:/", "C:\\")
        if re.fullmatch(r"/home/[^/]+/?", workspace):
            broad = True
        if re.fullmatch(r"C:/Users/[^/]+/?", workspace):
            broad = True
        if broad:
            findings.append(
                OpenClawFinding(
                    id="OC-013",
                    severity="high",
                    category="permissions",
                    title="Workspace path is too broad",
                    description="Workspace should be restricted to a project-specific directory.",
                    evidence=f"workspace={workspace!r}",
                    fix="Limit workspace to dedicated app directory.",
                    references=[],
                )
            )

    def _check_file_limits(self, cfg: dict[str, Any], findings: list[OpenClawFinding]) -> None:
        exec_cfg = self._exec_cfg(cfg)
        has_limit = any(
            key in exec_cfg or key in cfg
            for key in ("maxFileSize", "max_file_size", "fileSizeLimitMb", "maxFileSizeMb")
        )
        if not has_limit:
            findings.append(
                OpenClawFinding(
                    id="OC-014",
                    severity="medium",
                    category="permissions",
                    title="No file size limits configured",
                    description="Large file operations can degrade availability.",
                    evidence="No max file size setting found",
                    fix="Set file size limits for file read/write operations.",
                    references=[],
                )
            )

    def _check_browser_allowlist(self, cfg: dict[str, Any], findings: list[OpenClawFinding]) -> None:
        text = " ".join(self._flatten_strings(cfg)).lower()
        browser_enabled = any(marker in text for marker in ("puppeteer", "playwright"))
        if not browser_enabled:
            return
        browser_cfg = cfg.get("browser") if isinstance(cfg.get("browser"), dict) else {}
        allowlist = browser_cfg.get("urlAllowlist") or browser_cfg.get("allowedUrls")
        if not isinstance(allowlist, list) or len(allowlist) == 0:
            findings.append(
                OpenClawFinding(
                    id="OC-015",
                    severity="high",
                    category="permissions",
                    title="Browser automation is unrestricted",
                    description="Browser automation tools are enabled without URL allowlist.",
                    evidence="Detected puppeteer/playwright usage without allowlist",
                    fix="Configure strict URL allowlist for browser automation.",
                    references=[],
                )
            )

    def _check_skill_version_pinning(self, cfg: dict[str, Any], findings: list[OpenClawFinding]) -> None:
        skills = cfg.get("skills")
        if not isinstance(skills, list):
            return
        for item in skills:
            if isinstance(item, str):
                val = item.strip()
                if val and "@" not in val:
                    findings.append(
                        OpenClawFinding(
                            id="OC-019",
                            severity="high",
                            category="supply_chain",
                            title="Skill is not pinned to version",
                            description="Unpinned skills may introduce breaking or malicious updates.",
                            evidence=val[:120],
                            fix="Pin skill version (e.g., skill-name@1.2.3).",
                            references=[],
                        )
                    )
                    return
            if isinstance(item, dict):
                if not item.get("version"):
                    findings.append(
                        OpenClawFinding(
                            id="OC-019",
                            severity="high",
                            category="supply_chain",
                            title="Skill is not pinned to version",
                            description="Skill entry does not include explicit version.",
                            evidence=str(item)[:120],
                            fix="Specify explicit skill version for each skill entry.",
                            references=[],
                        )
                    )
                    return

    def _check_skill_allowlist(self, cfg: dict[str, Any], findings: list[OpenClawFinding]) -> None:
        allowlist = cfg.get("skillAllowlist") or cfg.get("skill_allowlist")
        if not isinstance(allowlist, list) or len(allowlist) == 0:
            findings.append(
                OpenClawFinding(
                    id="OC-020",
                    severity="medium",
                    category="supply_chain",
                    title="No skill allowlist configured",
                    description="Any skill may be loaded when allowlist is absent.",
                    evidence="skillAllowlist missing/empty",
                    fix="Define explicit allowlist of approved skills.",
                    references=[],
                )
            )

    def _has_rate_limit(self, cfg: dict[str, Any]) -> bool:
        rl = cfg.get("rate_limit") if isinstance(cfg.get("rate_limit"), dict) else cfg.get("rateLimit")
        if isinstance(rl, dict) and len(rl) > 0:
            return True
        return False

    def _exec_cfg(self, cfg: dict[str, Any]) -> dict[str, Any]:
        tools = cfg.get("tools") if isinstance(cfg.get("tools"), dict) else {}
        return tools.get("exec") if isinstance(tools.get("exec"), dict) else {}

    def _render_text(self, result: OpenClawAuditResult) -> str:
        lines: list[str] = [
            "╔══════════════════════════════════════════════╗",
            "║  OpenClaw Security Audit Report              ║",
            f"║  Score: {result.score}/100 (Grade: {result.grade}){' ' * max(0, 17 - len(result.grade))}║",
            "╚══════════════════════════════════════════════╝",
            "",
            (
                "Summary: "
                f"{result.summary.get('critical', 0)} critical, "
                f"{result.summary.get('high', 0)} high, "
                f"{result.summary.get('medium', 0)} medium, "
                f"{result.summary.get('low', 0)} low"
            ),
            "",
        ]
        if not result.findings:
            lines.append("No findings detected.")
            return "\n".join(lines)
        for severity in ("critical", "high", "medium", "low"):
            bucket = [item for item in result.findings if item.severity == severity]
            if not bucket:
                continue
            lines.append(f"{severity.upper()} FINDINGS:")
            lines.append("")
            for finding in bucket:
                refs = ", ".join(finding.references) if finding.references else "n/a"
                lines.extend(
                    [
                        f"[{finding.id}] {finding.title}",
                        f"  Severity: {finding.severity.upper()}",
                        f"  Evidence: {finding.evidence}",
                        f"  Fix: {finding.fix}",
                        f"  Ref: {refs}",
                        "",
                    ]
                )
        lines.extend(
            [
                "RECOMMENDATIONS:",
                "  1. Enable authentication and restrict network exposure.",
                "  2. Remove hardcoded credentials from configuration files.",
                "  3. Enforce sandboxed execution and allowlists.",
            ]
        )
        return "\n".join(lines)

    def _render_markdown(self, result: OpenClawAuditResult) -> str:
        lines = [
            "# OpenClaw Security Audit Report",
            "",
            f"**Score:** {result.score}/100  ",
            f"**Grade:** {result.grade}  ",
            f"**Target:** `{result.config_path}`  ",
            f"**Timestamp:** `{result.timestamp}`",
            "",
            "## Summary",
            "",
            f"- Critical: {result.summary.get('critical', 0)}",
            f"- High: {result.summary.get('high', 0)}",
            f"- Medium: {result.summary.get('medium', 0)}",
            f"- Low: {result.summary.get('low', 0)}",
            "",
            "## Findings",
            "",
        ]
        if not result.findings:
            lines.append("- No findings.")
            return "\n".join(lines)
        for finding in result.findings:
            refs = ", ".join(finding.references) if finding.references else "n/a"
            lines.extend(
                [
                    f"### [{finding.id}] {finding.title}",
                    f"- Severity: `{finding.severity}`",
                    f"- Category: `{finding.category}`",
                    f"- Description: {finding.description}",
                    f"- Evidence: `{finding.evidence}`",
                    f"- Fix: {finding.fix}",
                    f"- References: {refs}",
                    "",
                ]
            )
        return "\n".join(lines)


def run_audit_cli(args: Any) -> None:
    """CLI entry point for: orchesis audit-openclaw."""

    auditor = OpenClawAuditor()
    if getattr(args, "config", None):
        result = auditor.audit_config(str(args.config))
    elif getattr(args, "gateway", None):
        result = auditor.audit_gateway_config(str(args.gateway))
    elif getattr(args, "host", None):
        result = auditor.audit_instance(str(args.host), int(getattr(args, "port", 18789)))
    else:
        result = OpenClawAuditResult(
            findings=[],
            score=100,
            grade="A",
            summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
            config_path="",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
    print(auditor.generate_report(result, format=str(getattr(args, "format", "text"))))
