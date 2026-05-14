#!/usr/bin/env python3
"""Pre-commit hook entrypoint for MCP config scanning."""

from __future__ import annotations

import sys
from pathlib import Path

from orchesis.scanner import McpConfigScanner


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _meets_threshold(severity: str, threshold: str) -> bool:
    left = SEVERITY_ORDER.get(str(severity).lower(), 0)
    right = SEVERITY_ORDER.get(threshold, 0)
    return left >= right


def _scan_file(scanner: McpConfigScanner, file_path: Path) -> int:
    report = scanner.scan(str(file_path))
    findings = list(report.findings)
    if not findings:
        print(f"[orchesis] {file_path}: no findings")
        return 0

    print(f"[orchesis] {file_path}: {len(findings)} finding(s), risk_score={report.risk_score}")
    for finding in findings:
        print(
            f"  - [{finding.severity.upper()}] {finding.description} "
            f"({finding.location})"
        )
    return sum(1 for item in findings if _meets_threshold(item.severity, "high"))


def main() -> int:
    files = [Path(arg) for arg in sys.argv[1:] if arg.strip()]
    if not files:
        print("[orchesis] no files passed to hook")
        return 0

    scanner = McpConfigScanner()
    blocking_findings = 0
    for file_path in files:
        if not file_path.exists():
            print(f"[orchesis] skip missing file: {file_path}")
            continue
        blocking_findings += _scan_file(scanner, file_path)

    if blocking_findings > 0:
        print(f"[orchesis] FAILED: {blocking_findings} high/critical finding(s) detected")
        return 1

    print("[orchesis] PASSED: no high/critical findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
