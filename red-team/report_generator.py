"""Generate markdown and JSON red-team reports."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from config import AttackReport, AttackResult, RESULTS_ROOT, write_json


def generate_reports(reports: list[AttackReport]) -> tuple[Path, Path]:
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)

    counts = Counter(item.result for item in reports)
    blocked = counts.get(AttackResult.PASS, 0)
    bypasses = counts.get(AttackResult.FAIL, 0)
    partial = counts.get(AttackResult.PARTIAL, 0)
    errors = counts.get(AttackResult.ERROR, 0)
    total = len(reports)

    md_lines = [
        f"# Orchesis Red Team Report v1 - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}",
        "",
        "## Summary",
        "",
        f"{blocked}/{total} attacks blocked, {bypasses} bypasses found, {errors} errors, {partial} partial findings.",
        "",
        "## Attack Matrix",
        "",
        "| Attack | Category | Result | Severity | Description |",
        "|--------|----------|--------|----------|-------------|",
    ]
    for item in sorted(reports, key=lambda x: (x.category, x.name)):
        md_lines.append(
            f"| {item.name} | {item.category} | {item.result.value} | {item.severity} | {item.description} |"
        )

    fail_items = [item for item in reports if item.result == AttackResult.FAIL]
    if fail_items:
        md_lines.extend(["", "## Bypass Details", ""])
        for item in fail_items:
            md_lines.extend(
                [
                    f"### {item.name}",
                    "",
                    f"- **Category:** {item.category}",
                    f"- **Severity:** {item.severity}",
                    f"- **Vectors tested:** {item.vectors_tested}",
                    f"- **Vectors bypassed:** {item.vectors_bypassed}",
                    f"- **Details:** {item.details or 'n/a'}",
                    f"- **Fix suggestion:** {item.fix_suggestion or 'n/a'}",
                    "",
                ]
            )

    md_path = RESULTS_ROOT / "report.md"
    md_path.write_text("\n".join(md_lines).strip() + "\n", encoding="utf-8")

    json_payload = {
        "summary": {
            "total": total,
            "pass": blocked,
            "fail": bypasses,
            "partial": partial,
            "error": errors,
        },
        "attacks": [item.to_dict() for item in reports],
    }
    json_path = RESULTS_ROOT / "report.json"
    write_json(json_path, json_payload)
    return md_path, json_path
