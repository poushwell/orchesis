from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

ACTION_DIR = Path(__file__).resolve().parent
if str(ACTION_DIR) not in sys.path:
    sys.path.insert(0, str(ACTION_DIR))

from checks import (  # noqa: E402
    Finding,
    run_config_checks,
    run_dependency_checks,
    run_policy_checks,
    severity_meets_threshold,
)
from sarif_formatter import build_sarif  # noqa: E402

SEVERITIES = ("critical", "high", "medium", "low")
_COLOR = {
    "critical": "\033[31m",  # red
    "high": "\033[31m",
    "medium": "\033[33m",  # yellow
    "low": "\033[36m",  # cyan
    "reset": "\033[0m",
}
_AUTO_CONFIG_NAMES = {"openclaw.json", "claude_desktop_config.json", "mcp.json", ".cursor/mcp.json"}
_AUTO_POLICY_NAMES = {"policy.yaml", "orchesis.yaml"}


def _parse_bool(raw: str) -> bool:
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _normalize_severity(raw: str) -> str:
    sev = str(raw).strip().lower()
    return sev if sev in SEVERITIES else "critical"


def _split_paths(raw: str) -> list[Path]:
    if not raw.strip():
        return []
    parts = [item.strip() for item in raw.replace(";", ",").split(",") if item.strip()]
    return [Path(item) for item in parts]


def _discover_files(root: Path, names: set[str]) -> list[Path]:
    found: list[Path] = []
    for token in names:
        if "/" in token:
            candidate = root / token
            if candidate.exists():
                found.append(candidate)
            continue
        for path in root.rglob(token):
            if path.is_file():
                found.append(path)
    unique = sorted({path.resolve() for path in found})
    return [Path(path) for path in unique]


def autodetect_targets(root: Path, config_path: str, policy_path: str) -> tuple[list[Path], list[Path]]:
    config_targets = _split_paths(config_path)
    policy_targets = _split_paths(policy_path)
    if not config_targets:
        config_targets = _discover_files(root, set(_AUTO_CONFIG_NAMES))
    if not policy_targets:
        policy_targets = _discover_files(root, set(_AUTO_POLICY_NAMES))
    return config_targets, policy_targets


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except Exception:  # noqa: BLE001
        return str(path)


def run_scan(
    root: Path,
    config_targets: Iterable[Path],
    policy_targets: Iterable[Path],
) -> list[Finding]:
    findings: list[Finding] = []
    for config_path in config_targets:
        findings.extend(run_config_checks(str(config_path)))
        findings.extend(run_dependency_checks(str(config_path)))
    for policy_path in policy_targets:
        findings.extend(run_policy_checks(str(policy_path)))
    normalized: list[Finding] = []
    for item in findings:
        item.file = _relative(Path(item.file), root)
        normalized.append(item)
    return normalized


def format_text(findings: list[Finding], threshold: str) -> str:
    filtered = [f for f in findings if severity_meets_threshold(f.severity, threshold)]
    counts = Counter(f.severity for f in filtered)
    lines = [
        "Orchesis Security Scan",
        f"Threshold: {threshold}",
        (
            "Summary: "
            f"{len(filtered)} findings "
            f"(critical={counts.get('critical', 0)}, high={counts.get('high', 0)}, "
            f"medium={counts.get('medium', 0)}, low={counts.get('low', 0)})"
        ),
        "",
    ]
    if not filtered:
        lines.append("No findings above threshold.")
        return "\n".join(lines)

    for finding in filtered:
        sev = finding.severity.lower()
        color = _COLOR.get(sev, "")
        reset = _COLOR["reset"] if color else ""
        lines.append(
            (
                f"{color}[{sev.upper():8}]{reset} {finding.id} "
                f"{finding.file}:{finding.line} - {finding.title}\n"
                f"  {finding.description}\n"
                f"  Remediation: {finding.remediation}"
            )
        )
    return "\n".join(lines)


def _write_github_output(path: str | None, key: str, value: str) -> None:
    if not path:
        return
    with Path(path).open("a", encoding="utf-8") as fh:
        fh.write(f"{key}={value}\n")


def _write_step_summary(path: str | None, findings: list[Finding], threshold: str, report_path: str) -> None:
    if not path:
        return
    filtered = [f for f in findings if severity_meets_threshold(f.severity, threshold)]
    counts = Counter(f.severity for f in filtered)
    lines = [
        "## Orchesis Security Scan",
        "",
        f"- Threshold: `{threshold}`",
        f"- Findings above threshold: `{len(filtered)}`",
        f"- Critical: `{counts.get('critical', 0)}` | High: `{counts.get('high', 0)}` | Medium: `{counts.get('medium', 0)}` | Low: `{counts.get('low', 0)}`",
        f"- Report: `{report_path}`",
        "",
    ]
    if filtered:
        lines.append("### Top findings")
        for finding in filtered[:10]:
            lines.append(f"- **{finding.severity.upper()}** `{finding.id}` `{finding.file}:{finding.line}` - {finding.title}")
    else:
        lines.append("No findings above threshold.")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _report_filename(fmt: str) -> str:
    if fmt == "json":
        return "orchesis-report.json"
    if fmt == "sarif":
        return "orchesis-report.sarif"
    return "orchesis-report.txt"


def _write_report(fmt: str, findings: list[Finding], threshold: str) -> str:
    report_path = Path.cwd() / _report_filename(fmt)
    filtered = [item for item in findings if severity_meets_threshold(item.severity, threshold)]
    if fmt == "json":
        payload = {"findings": [item.to_dict() for item in filtered]}
        report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    elif fmt == "sarif":
        payload = build_sarif(filtered)
        report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    else:
        report_path.write_text(format_text(findings, threshold) + "\n", encoding="utf-8")
    return str(report_path)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Orchesis CI security checks")
    parser.add_argument("--config", default="", help="MCP config path (optional)")
    parser.add_argument("--policy", default="", help="Policy path (optional)")
    parser.add_argument("--severity", default="critical", help="critical|high|medium|low")
    parser.add_argument("--fail-on", default="critical", help="critical|high|medium|low")
    parser.add_argument("--format", default="text", choices=("text", "json", "sarif"))
    parser.add_argument("--fail-on-findings", default="true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    threshold = _normalize_severity(args.severity)
    fail_threshold = _normalize_severity(args.fail_on)
    fail_on_findings = _parse_bool(args.fail_on_findings)
    root = Path.cwd()

    config_targets, policy_targets = autodetect_targets(root, args.config, args.policy)
    findings = run_scan(root, config_targets, policy_targets)
    report_path = _write_report(args.format, findings, threshold)

    if args.format == "text":
        sys.stdout.write(format_text(findings, threshold) + "\n")
    elif args.format == "json":
        sys.stdout.write(json.dumps({"findings": [item.to_dict() for item in findings]}, ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(json.dumps({"report": report_path, "findings": len(findings)}) + "\n")

    filtered = [item for item in findings if severity_meets_threshold(item.severity, threshold)]
    critical_count = sum(1 for item in filtered if item.severity.lower() == "critical")

    output_path = os.getenv("GITHUB_OUTPUT")
    _write_github_output(output_path, "findings-count", str(len(filtered)))
    _write_github_output(output_path, "critical-count", str(critical_count))
    _write_github_output(output_path, "report-path", report_path)

    _write_step_summary(os.getenv("GITHUB_STEP_SUMMARY"), findings, threshold, report_path)

    fail_candidates = [item for item in findings if severity_meets_threshold(item.severity, fail_threshold)]
    if fail_on_findings and fail_candidates:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
