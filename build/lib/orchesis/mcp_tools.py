"""Tool definitions and handlers for Orchesis MCP server."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}


def build_tool_registry(policy_path: str | None = None) -> dict[str, dict[str, Any]]:
    """Build MCP tool registry with Orchesis capabilities."""
    return {
        "orchesis_scan_config": {
            "description": (
                "Analyze MCP configuration JSON for security issues. "
                "Returns score, grade, findings, and remediation hints."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "config_json": {"type": "string", "description": "MCP config JSON string"},
                },
                "required": ["config_json"],
            },
            "handler": _handle_scan_config,
        },
        "orchesis_check_policy": {
            "description": (
                "Validate if a tool call would be allowed by current Orchesis policy."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_name": {"type": "string", "description": "Tool name to evaluate"},
                    "params": {
                        "type": "object",
                        "description": "Tool call params",
                        "additionalProperties": True,
                    },
                },
                "required": ["tool_name"],
            },
            "handler": _make_check_policy_handler(policy_path),
        },
        "orchesis_cost_report": {
            "description": (
                "Get current cost report with totals and tool-level breakdown."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "day": {"type": "string", "description": "Optional YYYY-MM-DD"},
                    "format": {
                        "type": "string",
                        "enum": ["json", "markdown", "console"],
                        "description": "Output format (default: markdown)",
                    },
                },
            },
            "handler": _handle_cost_report,
        },
        "orchesis_cost_status": {
            "description": (
                "Get budget status: spent, remaining, per-tool limits and threshold status."
            ),
            "inputSchema": {"type": "object", "properties": {}},
            "handler": _make_cost_status_handler(policy_path),
        },
        "orchesis_scan_skill": {
            "description": (
                "Scan skill/plugin code for malicious patterns: shell execution, "
                "exfiltration, credential access and obfuscation."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Skill source code text"},
                    "filename": {"type": "string", "description": "Optional filename"},
                },
                "required": ["code"],
            },
            "handler": _handle_scan_skill,
        },
        "orchesis_loop_stats": {
            "description": (
                "Get loop detection stats: warned, blocked, and estimated money saved."
            ),
            "inputSchema": {"type": "object", "properties": {}},
            "handler": _handle_loop_stats,
        },
    }


def _get_policy(policy_path: str | None) -> dict[str, Any]:
    from orchesis.config import load_policy

    if isinstance(policy_path, str) and policy_path.strip():
        path = Path(policy_path).expanduser()
        if path.exists():
            return load_policy(path)
        return {}
    default_path = Path("policy.yaml")
    if default_path.exists():
        return load_policy(default_path)
    return {}


def _get_servers(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    candidate = (
        config.get("mcpServers")
        or config.get("servers")
        or config.get("mcp-servers")
        or config.get("mcptools")
        or {}
    )
    if isinstance(candidate, list):
        mapped: dict[str, dict[str, Any]] = {}
        for idx, item in enumerate(candidate):
            if isinstance(item, dict):
                name = item.get("name") if isinstance(item.get("name"), str) and item.get("name") else f"server_{idx + 1}"
                mapped[name] = item
        return mapped
    if isinstance(candidate, dict):
        return {k: v for k, v in candidate.items() if isinstance(k, str) and isinstance(v, dict)}
    return {}


def _append_finding(
    findings: list[dict[str, Any]],
    score: int,
    *,
    severity: str,
    title: str,
    description: str,
    remediation: str,
) -> int:
    findings.append(
        {
            "severity": severity,
            "title": title,
            "description": description,
            "remediation": remediation,
        }
    )
    return max(0, score - _SEVERITY_WEIGHT.get(severity, 0))


def _handle_scan_config(params: dict[str, Any]) -> dict[str, Any]:
    raw = params.get("config_json", "")
    if not isinstance(raw, str):
        return {"score": 0, "grade": "F", "error": "config_json must be a string", "findings": []}
    try:
        config = json.loads(raw)
    except json.JSONDecodeError as error:
        return {"score": 0, "grade": "F", "error": f"Invalid JSON: {error}", "findings": []}
    if not isinstance(config, dict):
        return {"score": 0, "grade": "F", "error": "Top-level JSON must be an object", "findings": []}

    findings: list[dict[str, Any]] = []
    score = 100
    servers = _get_servers(config)

    if not servers:
        return {
            "score": 100,
            "grade": "A",
            "servers_scanned": 0,
            "findings": [
                {
                    "severity": "INFO",
                    "title": "No servers found",
                    "description": "Configuration does not contain MCP servers.",
                    "remediation": "Add MCP server definitions to scan.",
                }
            ],
        }

    config_text = json.dumps(config, ensure_ascii=False)
    secret_patterns = [
        (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI key"),
        (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "GitHub token"),
        (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
        (re.compile(r"xox[bsp]-[A-Za-z0-9-]+"), "Slack token"),
        (re.compile(r"glpat-[A-Za-z0-9_-]{20,}"), "GitLab token"),
        (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "Private key"),
    ]
    for regex, label in secret_patterns:
        if regex.search(config_text):
            score = _append_finding(
                findings,
                score,
                severity="CRITICAL",
                title=f"Hardcoded {label} found",
                description=f"Detected {label} in configuration payload.",
                remediation="Move secrets out of config and use environment-based injection.",
            )

    if len(servers) > 10:
        score = _append_finding(
            findings,
            score,
            severity="MEDIUM",
            title=f"High server count ({len(servers)})",
            description="Large MCP server set increases attack surface.",
            remediation="Remove unused MCP servers.",
        )

    for name, server in servers.items():
        transport = str(server.get("transport") or server.get("type") or "stdio").lower()
        url = str(server.get("url") or server.get("baseUrl") or "")
        if transport in {"sse", "http", "streamable-http"} and url.startswith("http://"):
            if "localhost" not in url and "127.0.0.1" not in url:
                score = _append_finding(
                    findings,
                    score,
                    severity="CRITICAL",
                    title=f'Server "{name}" uses unencrypted remote HTTP',
                    description=f"Remote MCP traffic is plaintext: {url}",
                    remediation="Use HTTPS for remote endpoints.",
                )

        command = str(server.get("command") or "").lower()
        if command in {"bash", "sh", "cmd", "powershell", "pwsh", "zsh"}:
            score = _append_finding(
                findings,
                score,
                severity="HIGH",
                title=f'Server "{name}" runs via shell interpreter',
                description=f'Command "{command}" is high risk.',
                remediation="Use direct executable instead of shell interpreter.",
            )

        args = server.get("args", [])
        args_list = args if isinstance(args, list) else []
        args_text = " ".join(str(item) for item in args_list)
        if re.search(r"[;&|`$()]", args_text):
            score = _append_finding(
                findings,
                score,
                severity="CRITICAL",
                title=f'Server "{name}" has shell metacharacters in args',
                description=f"Args include shell operators: {args_text[:120]}",
                remediation="Pass explicit safe args without shell operators.",
            )

        if command in {"npx", "uvx", "pipx"}:
            has_pin = False
            for arg in args_list:
                text = str(arg)
                if "@" in text or "==" in text:
                    has_pin = True
                    break
            if not has_pin:
                score = _append_finding(
                    findings,
                    score,
                    severity="MEDIUM",
                    title=f'Server "{name}" has no version pinning',
                    description=f"Command {command} runs without pinned package version.",
                    remediation="Pin package version (`pkg@x.y.z` or `pkg==x.y.z`).",
                )

        if not server.get("allowedTools") and not server.get("disabledTools") and not server.get("tools"):
            score = _append_finding(
                findings,
                score,
                severity="MEDIUM",
                title=f'Server "{name}" has no tool restrictions',
                description="No allowlist/denylist for exposed tools.",
                remediation="Add explicit allowedTools list.",
            )

        if server.get("allowedDirectories") == ["/"] or "/" in args_list:
            score = _append_finding(
                findings,
                score,
                severity="HIGH",
                title=f'Server "{name}" has root filesystem access',
                description='Configuration appears to expose "/" to server.',
                remediation="Restrict to minimal required subdirectories.",
            )

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    findings_sorted = sorted(findings, key=lambda item: severity_rank.get(str(item.get("severity")), 0), reverse=True)
    return {"score": score, "grade": grade, "servers_scanned": len(servers), "findings": findings_sorted}


def _make_check_policy_handler(policy_path: str | None):
    def handler(params: dict[str, Any]) -> dict[str, Any]:
        from orchesis.engine import evaluate

        tool_name = params.get("tool_name")
        call_params = params.get("params", {})
        if not isinstance(tool_name, str) or not tool_name.strip():
            return {"action": "error", "reason": "tool_name is required"}
        safe_params = call_params if isinstance(call_params, dict) else {}
        policy = _get_policy(policy_path)
        decision = evaluate({"tool": tool_name, "params": safe_params}, policy)
        return {
            "tool": tool_name,
            "action": "allow" if decision.allowed else "deny",
            "reason": decision.reasons[0] if decision.reasons else "allowed",
            "warnings": [item for item in decision.reasons if isinstance(item, str) and item.startswith("warning:")],
            "all_reasons": list(decision.reasons),
        }

    return handler


def _handle_cost_report(params: dict[str, Any]) -> str:
    from orchesis.cost_reporter import CostReporter
    from orchesis.engine import get_cost_tracker, get_loop_detector_stats

    class _LoopStatsAdapter:
        def get_stats(self) -> dict[str, Any]:
            return get_loop_detector_stats()

    tracker = get_cost_tracker()
    reporter = CostReporter(tracker, loop_detector=_LoopStatsAdapter())
    day = params.get("day")
    day_value = day if isinstance(day, str) and day.strip() else None
    output_format = params.get("format", "markdown")
    fmt = output_format if isinstance(output_format, str) else "markdown"
    summary = reporter.daily_summary(day=day_value)
    if fmt == "json":
        return json.dumps(summary, ensure_ascii=False, indent=2, default=str)
    if fmt == "console":
        return reporter.format_console(summary)
    return reporter.format_markdown(summary)


def _make_cost_status_handler(policy_path: str | None):
    def handler(_params: dict[str, Any]) -> dict[str, Any]:
        from orchesis.engine import get_cost_tracker

        tracker = get_cost_tracker()
        policy = _get_policy(policy_path)
        budgets = policy.get("budgets") if isinstance(policy.get("budgets"), dict) else {}
        if not budgets:
            return {
                "message": "No budgets configured in policy",
                "daily_spent": round(tracker.get_daily_total(), 4),
            }
        return tracker.check_budget(budgets)

    return handler


def _handle_scan_skill(params: dict[str, Any]) -> dict[str, Any]:
    code = params.get("code", "")
    filename = params.get("filename", "unknown")
    if not isinstance(code, str):
        return {"score": 0, "filename": filename, "lines_scanned": 0, "findings": [], "verdict": "DANGEROUS"}
    if not isinstance(filename, str):
        filename = "unknown"

    findings: list[dict[str, Any]] = []
    score = 100

    checks: list[tuple[str, str, str, str]] = [
        (
            r"eval\s*\(|Function\s*\(|exec\s*\(|compile\s*\(",
            "CRITICAL",
            "Dynamic code execution",
            "Code contains dynamic execution primitives.",
        ),
        (
            r"child_process|subprocess|os\.system|os\.popen|spawn\(",
            "CRITICAL",
            "Shell/process execution",
            "Code can execute external commands.",
        ),
        (
            r"fetch\s*\(|requests\.(?:get|post)|http\.request|https\.request|urllib",
            "HIGH",
            "Network request capability",
            "Code performs network requests, check destinations and payloads.",
        ),
        (
            r"process\.env|os\.environ|\.env|API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL",
            "HIGH",
            "Credential access pattern",
            "Code references sensitive environment values.",
        ),
        (
            r"base64|atob\s*\(|btoa\s*\(|rot13|unicode_escape",
            "MEDIUM",
            "Obfuscation pattern",
            "Encoding/obfuscation indicators found.",
        ),
        (
            r"pastebin\.com|webhook\.site|requestbin|pipedream|ngrok\.io",
            "CRITICAL",
            "Suspicious external service",
            "Potential exfiltration endpoint reference found.",
        ),
    ]
    for pattern, severity, title, description in checks:
        matches = re.findall(pattern, code, flags=re.IGNORECASE)
        if matches:
            score = _append_finding(
                findings,
                score,
                severity=severity,
                title=title,
                description=f"{description} Occurrences: {len(matches)}",
                remediation="Review this code path before enabling the skill.",
            )

    lines = code.splitlines()
    long_lines = [line for line in lines if len(line) > 500]
    if long_lines:
        score = _append_finding(
            findings,
            score,
            severity="MEDIUM",
            title="Minified/obfuscated code detected",
            description=f"{len(long_lines)} very long line(s) detected.",
            remediation="Prefer readable source; audit minified blobs manually.",
        )

    verdict = "SAFE" if score >= 80 else "SUSPICIOUS" if score >= 40 else "DANGEROUS"
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return {
        "score": score,
        "filename": filename,
        "lines_scanned": len(lines),
        "findings": sorted(findings, key=lambda item: severity_rank.get(str(item.get("severity")), 0), reverse=True),
        "verdict": verdict,
    }


def _handle_loop_stats(_params: dict[str, Any]) -> dict[str, Any]:
    from orchesis.engine import get_loop_detector_stats

    try:
        stats = get_loop_detector_stats()
        if not isinstance(stats, dict) or not stats:
            return {"error": "Loop detection not enabled"}
        return stats
    except Exception as error:  # noqa: BLE001
        return {"error": str(error)}

