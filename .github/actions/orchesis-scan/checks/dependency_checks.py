from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import Finding

_VULNERABLE_PACKAGES: dict[str, dict[str, str]] = {
    "openclaw-mcp": {"max_vulnerable": "1.3.2", "cve": "CVE-2026-31011"},
    "legacy-mcp-bridge": {"max_vulnerable": "0.9.8", "cve": "CVE-2025-99421"},
    "mcp-shell-server": {"max_vulnerable": "2.1.0", "cve": "CVE-2026-12007"},
}

_VULNERABLE_IMAGES = {
    "ghcr.io/example/openclaw-mcp:0.8.0": "CVE-2026-31011",
    "docker.io/example/mcp-shell-server:2.0.0": "CVE-2026-12007",
}


def _line_number(source: str, token: str) -> int:
    idx = source.find(token)
    if idx < 0:
        return 1
    return source[:idx].count("\n") + 1


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", value)
    if not parts:
        return (0,)
    return tuple(int(item) for item in parts[:4])


def _is_vulnerable(version: str, max_vulnerable: str) -> bool:
    return _version_tuple(version) <= _version_tuple(max_vulnerable)


def _iter_servers(payload: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    raw = payload.get("mcpServers")
    if not isinstance(raw, dict):
        raw = payload.get("servers")
    if not isinstance(raw, dict):
        return []
    return [(name, cfg) for name, cfg in raw.items() if isinstance(name, str) and isinstance(cfg, dict)]


def _extract_name_version(spec: str) -> tuple[str, str]:
    if "@" not in spec:
        return spec.strip().lower(), ""
    if spec.startswith("@"):
        parts = spec.split("@")
        if len(parts) < 3:
            return spec.strip().lower(), ""
        return "@".join(parts[:2]).lower(), parts[2]
    name, version = spec.rsplit("@", 1)
    return name.strip().lower(), version.strip()


def run_dependency_checks(config_path: str) -> list[Finding]:
    path = Path(config_path)
    try:
        source = path.read_text(encoding="utf-8")
        payload = json.loads(source)
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(payload, dict):
        return []

    findings: list[Finding] = []
    for name, cfg in _iter_servers(payload):
        package = str(cfg.get("package", "")).strip()
        command = str(cfg.get("command", "")).strip()
        args = cfg.get("args")
        args_list = [str(item) for item in args] if isinstance(args, list) else []
        image = str(cfg.get("image", "")).strip()

        # 1: vulnerable package field
        if package:
            pkg_name, pkg_ver = _extract_name_version(package)
            vuln = _VULNERABLE_PACKAGES.get(pkg_name)
            if vuln and pkg_ver and _is_vulnerable(pkg_ver, vuln["max_vulnerable"]):
                findings.append(
                    Finding(
                        id="DEP_VULNERABLE_PACKAGE",
                        severity="critical",
                        title="Known vulnerable MCP package",
                        description=(
                            f"Server '{name}' uses {pkg_name}@{pkg_ver}, affected by {vuln['cve']} "
                            f"(<= {vuln['max_vulnerable']})."
                        ),
                        file=str(path),
                        line=_line_number(source, package),
                        remediation=f"Upgrade {pkg_name} above {vuln['max_vulnerable']}.",
                    )
                )

        # 2: vulnerable npx invocation
        for arg in [command, *args_list]:
            lowered = arg.lower()
            if "npx" not in lowered:
                continue
            for package_name, meta in _VULNERABLE_PACKAGES.items():
                if package_name not in lowered:
                    continue
                match = re.search(rf"{re.escape(package_name)}@([0-9][0-9a-zA-Z\.\-]*)", lowered)
                if match and _is_vulnerable(match.group(1), meta["max_vulnerable"]):
                    findings.append(
                        Finding(
                            id="DEP_VULNERABLE_NPX",
                            severity="high",
                            title="Vulnerable package version in npx command",
                            description=f"{package_name}@{match.group(1)} in command may be vulnerable ({meta['cve']}).",
                            file=str(path),
                            line=_line_number(source, arg),
                            remediation=f"Pin npx dependency to patched version above {meta['max_vulnerable']}.",
                        )
                    )

        # 3: known vulnerable image
        if image and image.lower() in _VULNERABLE_IMAGES:
            findings.append(
                Finding(
                    id="DEP_VULNERABLE_IMAGE",
                    severity="critical",
                    title="Known vulnerable container image",
                    description=f"Image '{image}' is listed as vulnerable ({_VULNERABLE_IMAGES[image.lower()]}).",
                    file=str(path),
                    line=_line_number(source, image),
                    remediation="Update to a patched image digest/tag.",
                )
            )

        # 4: high risk family without version pin
        for family in _VULNERABLE_PACKAGES:
            if family in command.lower() and "@" not in command:
                findings.append(
                    Finding(
                        id="DEP_UNPINNED_HIGH_RISK_FAMILY",
                        severity="high",
                        title="High-risk MCP family without version pin",
                        description=f"Server '{name}' references '{family}' without explicit version.",
                        file=str(path),
                        line=_line_number(source, command),
                        remediation="Pin exact patched version in command/package.",
                    )
                )

        # 5: latest tag on known vulnerable family
        combined = " ".join([package, command, *args_list, image]).lower()
        if "latest" in combined and any(name_key in combined for name_key in _VULNERABLE_PACKAGES):
            findings.append(
                Finding(
                    id="DEP_LATEST_TAG_ON_RISKY_SERVER",
                    severity="medium",
                    title="Latest tag used for risky MCP dependency",
                    description=f"Server '{name}' uses latest tag with known vulnerable dependency family.",
                    file=str(path),
                    line=_line_number(source, "latest"),
                    remediation="Pin to reviewed fixed version and monitor CVEs.",
                )
            )

    return findings
