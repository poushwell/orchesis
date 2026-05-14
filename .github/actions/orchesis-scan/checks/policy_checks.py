from __future__ import annotations

import re
from pathlib import Path

from .models import Finding


def _line_number(source: str, token: str) -> int:
    idx = source.lower().find(token.lower())
    if idx < 0:
        return 1
    return source[:idx].count("\n") + 1


def _finding(
    fid: str,
    severity: str,
    title: str,
    description: str,
    file_path: str,
    line: int,
    remediation: str,
) -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        title=title,
        description=description,
        file=file_path,
        line=max(1, int(line)),
        remediation=remediation,
    )


def run_policy_checks(policy_path: str) -> list[Finding]:
    path = Path(policy_path)
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        return [
            _finding(
                "POL_READ_ERROR",
                "high",
                "Policy file cannot be read",
                str(error),
                str(path),
                1,
                "Ensure file exists and permissions are correct.",
            )
        ]

    text = source.lower()
    findings: list[Finding] = []

    # 1
    if "default_action:" not in text:
        findings.append(
            _finding(
                "POL_DEFAULT_ACTION_MISSING",
                "high",
                "default_action is missing",
                "Policy does not specify default allow/deny behavior.",
                str(path),
                1,
                "Set default_action: deny for secure baseline.",
            )
        )
    elif re.search(r"default_action:\s*allow\b", text):
        findings.append(
            _finding(
                "POL_DEFAULT_ACTION_ALLOW",
                "high",
                "default_action is allow",
                "Allow-by-default policy increases blast radius.",
                str(path),
                _line_number(source, "default_action"),
                "Switch to default_action: deny and allow specific capabilities.",
            )
        )

    # 2
    if "budgets:" not in text:
        findings.append(
            _finding(
                "POL_BUDGETS_MISSING",
                "high",
                "Budget limits are missing",
                "No budgets section found.",
                str(path),
                1,
                "Add budgets.daily and per_tool limits.",
            )
        )
    elif "daily:" not in text:
        findings.append(
            _finding(
                "POL_DAILY_BUDGET_MISSING",
                "medium",
                "Daily budget is missing",
                "budgets section exists but daily limit not configured.",
                str(path),
                _line_number(source, "budgets:"),
                "Set budgets.daily to a finite value.",
            )
        )

    # 3
    if "loop_detection:" not in text:
        findings.append(
            _finding(
                "POL_LOOP_DETECTION_MISSING",
                "high",
                "Loop detection is missing",
                "Policy has no loop_detection section.",
                str(path),
                1,
                "Enable loop_detection with block_threshold.",
            )
        )
    elif re.search(r"loop_detection:\s*(?:\n[ \t]+.*)*\n[ \t]*enabled:\s*false", text):
        findings.append(
            _finding(
                "POL_LOOP_DETECTION_DISABLED",
                "medium",
                "Loop detection disabled",
                "loop_detection.enabled is false.",
                str(path),
                _line_number(source, "loop_detection"),
                "Set loop_detection.enabled: true.",
            )
        )

    # 4
    if "secret_scanning:" not in text and "secrets:" not in text:
        findings.append(
            _finding(
                "POL_SECRET_SCANNING_MISSING",
                "high",
                "Secret scanning is missing",
                "No secret_scanning/secrets section found.",
                str(path),
                1,
                "Enable outbound and response secret scanning.",
            )
        )
    elif "scan_outbound: false" in text and "scan_response: false" in text:
        findings.append(
            _finding(
                "POL_SECRET_SCANNING_DISABLED",
                "high",
                "Secret scanning disabled",
                "Both outbound and response secret scanning are disabled.",
                str(path),
                _line_number(source, "scan_outbound"),
                "Enable at least one scanning mode.",
            )
        )

    # 5
    if "tool_access:" not in text and "capabilities:" not in text:
        findings.append(
            _finding(
                "POL_TOOL_ACCESS_MISSING",
                "medium",
                "Tool access controls missing",
                "No tool_access/capabilities constraints defined.",
                str(path),
                1,
                "Define explicit allow/deny tool rules.",
            )
        )

    # 6
    if "deny" not in text and "denied_" not in text:
        findings.append(
            _finding(
                "POL_NO_DENY_RULES",
                "high",
                "No deny rules detected",
                "Policy lacks deny constraints for risky actions.",
                str(path),
                1,
                "Add deny lists for paths, commands, and tools.",
            )
        )

    # 7
    if "rate_limits:" not in text and "max_requests_per_minute" not in text:
        findings.append(
            _finding(
                "POL_RATE_LIMITS_MISSING",
                "medium",
                "Rate limiting is missing",
                "No request rate limits found.",
                str(path),
                1,
                "Add rate limits to prevent abuse spikes.",
            )
        )

    # 8
    if re.search(r"allowed_paths:\s*\[(.*?)\]", text) and any(token in text for token in ("allowed_paths: [\"/\"]", "allowed_paths: ['/']", "allowed_paths: [/*]")):
        findings.append(
            _finding(
                "POL_ALLOWED_PATHS_TOO_BROAD",
                "high",
                "Overly broad allowed_paths",
                "allowed_paths includes filesystem root.",
                str(path),
                _line_number(source, "allowed_paths"),
                "Limit file access to strict project directories.",
            )
        )

    # 9
    if "kill_switch:" not in text:
        findings.append(
            _finding(
                "POL_KILL_SWITCH_MISSING",
                "low",
                "Kill switch not configured",
                "Policy lacks emergency kill_switch controls.",
                str(path),
                1,
                "Add kill_switch section with resume token and triggers.",
            )
        )

    # 10
    if "audit" not in text and "telemetry" not in text and "logging" not in text:
        findings.append(
            _finding(
                "POL_AUDIT_MISSING",
                "low",
                "Audit/telemetry settings missing",
                "Policy has no explicit audit/telemetry configuration.",
                str(path),
                1,
                "Enable structured logging and audit retention.",
            )
        )

    return findings
