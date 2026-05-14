from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from checks.models import Finding

_LEVEL_MAP = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_RANK_MAP = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "2.0"}


def build_sarif(findings: list[Finding], tool_name: str = "Orchesis Security Scan") -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        if finding.id not in rules:
            rules[finding.id] = {
                "id": finding.id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "help": {"text": finding.remediation},
                "properties": {
                    "precision": "high",
                    "problem.severity": finding.severity.lower(),
                    "security-severity": _RANK_MAP.get(finding.severity.lower(), "5.0"),
                },
            }

        results.append(
            {
                "ruleId": finding.id,
                "level": _LEVEL_MAP.get(finding.severity.lower(), "warning"),
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file},
                            "region": {"startLine": max(1, int(finding.line))},
                        }
                    }
                ],
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": tool_name, "rules": list(rules.values())}},
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }
