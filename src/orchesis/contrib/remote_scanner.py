"""Remote scanner for skills and MCP assets."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, build_opener

from orchesis.contrib.ioc_database import IoCMatcher
from orchesis.contrib.secret_scanner import SecretScanner
from orchesis.scanner import (
    McpConfigScanner,
    ScanFinding,
    ScanReport,
    SkillScanner,
    _build_summary,
    _calc_risk_score,
    _now_iso,
)


class RemoteSkillScanner:
    """Scan remote skills from URLs and ecosystem identifiers."""

    def __init__(
        self,
        skill_scanner: SkillScanner | None = None,
        ioc_matcher: IoCMatcher | None = None,
        secret_scanner: SecretScanner | None = None,
        timeout: float = 10.0,
    ):
        self._skill_scanner = skill_scanner or SkillScanner()
        self._ioc_matcher = ioc_matcher or IoCMatcher(enable_opt_in_v1_1=True)
        self._secret_scanner = secret_scanner or SecretScanner()
        self._mcp_scanner = McpConfigScanner()
        self._timeout = timeout
        self._max_size = 1_000_000
        self._max_redirects = 3

    def scan_url(self, url: str) -> ScanReport:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only http/https URLs are supported")
        final_url, content = self._fetch_text(url)
        findings: list[ScanFinding] = []
        lower_url = final_url.lower()
        stripped = content.strip()

        if "skill.md" in lower_url or lower_url.endswith(".md"):
            findings.extend(self._scan_skill_text(content))
        elif lower_url.endswith("package.json") or ("\"name\"" in stripped and "\"version\"" in stripped):
            findings.extend(self._scan_package_json(content))
        elif "mcp" in lower_url or "\"mcpServers\"" in stripped:
            findings.extend(self._scan_mcp_json(content))
        else:
            findings.extend(self._scan_generic(content))

        score = _calc_risk_score(findings)
        return ScanReport(
            target=url,
            target_type="remote",
            findings=findings,
            risk_score=score,
            summary=_build_summary(findings),
            scanned_at=_now_iso(),
        )

    def scan_clawhub(self, skill_id: str) -> ScanReport:
        safe_id = skill_id.strip()
        if safe_id.startswith("clawhub:"):
            safe_id = safe_id.split(":", 1)[1]
        primary = f"https://clawhub.com/skills/{safe_id}/SKILL.md"
        try:
            return self.scan_url(primary)
        except Exception:
            fallback = f"https://raw.githubusercontent.com/{safe_id}/main/SKILL.md"
            return self.scan_url(fallback)

    def scan_github(self, github_url: str) -> ScanReport:
        parsed = urlparse(github_url)
        if "github.com" not in parsed.netloc.lower():
            return self.scan_url(github_url)
        segments = [item for item in parsed.path.split("/") if item]
        if len(segments) >= 5 and segments[2] == "blob":
            owner, repo, _blob, branch = segments[:4]
            rest = "/".join(segments[4:])
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{rest}"
            return self.scan_url(raw_url)
        return self.scan_url(github_url)

    def scan_npm_package(self, package_name: str) -> ScanReport:
        safe_name = package_name.strip()
        if safe_name.startswith("npm:"):
            safe_name = safe_name.split(":", 1)[1]
        url = f"https://registry.npmjs.org/{safe_name}"
        final_url, content = self._fetch_text(url)
        _ = final_url
        findings: list[ScanFinding] = []
        payload = json.loads(content)
        if not isinstance(payload, dict):
            raise ValueError("Invalid npm metadata")

        now_ts = time.time()
        created = (
            payload.get("time", {}).get("created")
            if isinstance(payload.get("time"), dict)
            else None
        )
        if isinstance(created, str):
            try:
                created_ts = self._parse_iso_to_epoch(created)
                age_days = max(0.0, (now_ts - created_ts) / 86400.0)
                if age_days < 7:
                    findings.append(
                        ScanFinding(
                            severity="medium",
                            category="new_package_risk",
                            description=f"Package age is {age_days:.1f} days (< 7 days)",
                            location="npm:time.created",
                            evidence=created,
                        )
                    )
            except Exception:
                pass

        lowered = safe_name.lower()
        if re.search(r"0|1|l|rn", lowered):
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="typosquat_risk",
                    description="Package name contains possible typosquat characters",
                    location="npm:name",
                    evidence=safe_name,
                )
            )

        latest = payload.get("dist-tags", {}).get("latest") if isinstance(payload.get("dist-tags"), dict) else None
        versions = payload.get("versions") if isinstance(payload.get("versions"), dict) else {}
        latest_meta = versions.get(latest) if isinstance(latest, str) and isinstance(versions, dict) else None
        if isinstance(latest_meta, dict):
            scripts = latest_meta.get("scripts")
            if isinstance(scripts, dict):
                for key in ("postinstall", "preinstall", "install"):
                    value = scripts.get(key)
                    if isinstance(value, str) and value.strip():
                        findings.append(
                            ScanFinding(
                                severity="high",
                                category="install_script_risk",
                                description=f"Package defines {key} script",
                                location=f"npm:versions.{latest}.scripts.{key}",
                                evidence=value,
                            )
                        )

        score = _calc_risk_score(findings)
        return ScanReport(
            target=f"npm:{safe_name}",
            target_type="remote_npm",
            findings=findings,
            risk_score=score,
            summary=_build_summary(findings),
            scanned_at=_now_iso(),
        )

    def batch_scan(self, targets: list[str]) -> list[ScanReport]:
        reports: list[ScanReport] = []
        for target in targets:
            safe = target.strip()
            if not safe:
                continue
            if safe.startswith("clawhub:"):
                reports.append(self.scan_clawhub(safe))
            elif safe.startswith("npm:"):
                reports.append(self.scan_npm_package(safe))
            elif "github.com" in safe:
                reports.append(self.scan_github(safe))
            else:
                reports.append(self.scan_url(safe))
        return reports

    def _scan_skill_text(self, content: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        for finding in self._secret_scanner.scan_text(content):
            findings.append(
                ScanFinding(
                    severity=str(finding.get("severity", "medium")),
                    category="secret_leak",
                    description=str(finding.get("description", "Secret-like value detected")),
                    location="remote:content",
                    evidence=str(finding.get("match", "")),
                )
            )
        for finding in self._ioc_matcher.scan_text(content):
            findings.append(
                ScanFinding(
                    severity=str(finding.get("severity", "medium")),
                    category="ioc_match",
                    description=str(finding.get("ioc_name", "IoC match detected")),
                    location="remote:content",
                    evidence=str(finding.get("match", "")),
                )
            )
        lowered = content.lower()
        if "subprocess.run" in lowered:
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="shell_exec",
                    description="Skill contains subprocess.run pattern",
                    location="remote:content",
                    evidence="subprocess.run",
                )
            )
        return findings

    def _scan_package_json(self, content: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        try:
            payload = json.loads(content)
        except Exception:
            return self._scan_generic(content)
        if not isinstance(payload, dict):
            return self._scan_generic(content)
        scripts = payload.get("scripts")
        if isinstance(scripts, dict):
            for key in ("postinstall", "preinstall", "install"):
                script = scripts.get(key)
                if isinstance(script, str) and script.strip():
                    findings.append(
                        ScanFinding(
                            severity="high",
                            category="dangerous_script",
                            description=f"package.json contains {key} script",
                            location=f"scripts.{key}",
                            evidence=script,
                        )
                    )
        return findings

    def _scan_mcp_json(self, content: str) -> list[ScanFinding]:
        tmp = Path(".orchesis") / "remote_scan_tmp_mcp.json"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(content, encoding="utf-8")
        try:
            report = self._mcp_scanner.scan(str(tmp))
            return report.findings
        finally:
            try:
                tmp.unlink()
            except Exception:
                pass

    def _scan_generic(self, content: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        for finding in self._secret_scanner.scan_text(content):
            findings.append(
                ScanFinding(
                    severity=str(finding.get("severity", "medium")),
                    category="secret_leak",
                    description=str(finding.get("description", "Secret-like value detected")),
                    location="remote:generic",
                    evidence=str(finding.get("match", "")),
                )
            )
        for finding in self._ioc_matcher.scan_text(content):
            findings.append(
                ScanFinding(
                    severity=str(finding.get("severity", "medium")),
                    category="ioc_match",
                    description=str(finding.get("ioc_name", "IoC match detected")),
                    location="remote:generic",
                    evidence=str(finding.get("match", "")),
                )
            )
        return findings

    def _fetch_text(self, url: str) -> tuple[str, str]:
        opener = build_opener()
        current = url
        for _ in range(self._max_redirects + 1):
            req = Request(current, headers={"User-Agent": "orchesis-remote-scanner/1.0"})
            try:
                with opener.open(req, timeout=self._timeout) as resp:
                    final_url = resp.geturl()
                    data = resp.read(self._max_size + 1)
                    if len(data) > self._max_size:
                        raise ValueError("Remote content too large (>1MB)")
                    return final_url, data.decode("utf-8", errors="replace")
            except HTTPError as error:
                if error.code in {301, 302, 307, 308}:
                    location = error.headers.get("Location")
                    if isinstance(location, str) and location.strip():
                        current = location.strip()
                        continue
                raise
            except URLError:
                raise
        raise ValueError("Too many redirects")

    @staticmethod
    def _parse_iso_to_epoch(value: str) -> float:
        import datetime

        normalized = value.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(normalized)
        return dt.timestamp()
