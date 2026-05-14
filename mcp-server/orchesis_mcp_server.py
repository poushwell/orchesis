"""Orchesis MCP server with local security analysis tools."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import FastMCP

try:
    from orchesis import __version__ as ORCHESIS_VERSION
except Exception:
    ORCHESIS_VERSION = "unknown"


BRANDING = "Powered by Orchesis - https://github.com/poushwell/orchesis"
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_DEDUCTIONS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}

KNOWN_VULNERABLE_PACKAGES = {
    "mcp-server-shell": "Arbitrary shell execution capability.",
    "mcp-server-everything": "Overprivileged package with broad capability surface.",
    "mcp-server-puppeteer": "Browser automation can reach untrusted content.",
    "mcp-server-fetch": "Can fetch arbitrary URLs and may enable SSRF.",
}

SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-[a-zA-Z0-9_-]{16,}", re.IGNORECASE),
    re.compile(r"gh[pousr]_[a-zA-Z0-9]{16,}", re.IGNORECASE),
    re.compile(r"github_pat_[a-zA-Z0-9_]{20,}", re.IGNORECASE),
    re.compile(r"xox[baprs]-[a-zA-Z0-9-]{10,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"glpat-[a-zA-Z0-9_-]{16,}", re.IGNORECASE),
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
)

SECRET_KEY_PATTERN = re.compile(
    r"(api[_-]?key|api[_-]?secret|token|password|secret|credential|auth)",
    re.IGNORECASE,
)
SHELL_META_PATTERN = re.compile(r"(?:\|\||&&|[|;`]|[$][(])")
SHELL_DYNAMIC_PATTERN = re.compile(
    r"\b(?:bash\s+-c|sh\s+-c|cmd\s+/c|powershell(?:\.exe)?\s+-command|eval|exec)\b",
    re.IGNORECASE,
)
PATH_TRAVERSAL_PATTERN = re.compile(r"\.\./|\.\.\\")


@dataclass
class Finding:
    severity: str
    title: str
    server: str
    found: str
    fix: str


def _brand_tail() -> str:
    return f"\n\n{BRANDING}"


def _safe_json_loads(value: str) -> tuple[dict[str, Any] | list[Any] | None, str | None]:
    try:
        parsed = json.loads(value)
    except Exception as exc:  # pragma: no cover - message text varies
        return None, f"Invalid JSON input: {exc}"
    if not isinstance(parsed, (dict, list)):
        return None, "Invalid JSON input: expected object or array."
    return parsed, None


def _extract_servers(config: dict[str, Any] | list[Any]) -> dict[str, dict[str, Any]]:
    if isinstance(config, list):
        mapped: dict[str, dict[str, Any]] = {}
        for i, item in enumerate(config):
            if isinstance(item, dict):
                name = str(item.get("name") or f"server_{i + 1}")
                mapped[name] = item
        return mapped
    raw = (
        config.get("mcpServers")
        or config.get("servers")
        or config.get("mcp-servers")
        or config.get("mcptools")
        or {}
    )
    if isinstance(raw, list):
        return _extract_servers(raw)
    if not isinstance(raw, dict):
        return {}
    return {str(name): server for name, server in raw.items() if isinstance(server, dict)}


def _is_likely_secret(value: str) -> bool:
    for pattern in SECRET_VALUE_PATTERNS:
        if pattern.search(value):
            return True
    return False


def _looks_remote_http(url: str) -> bool:
    lowered = url.lower()
    if not lowered.startswith("http://"):
        return False
    return not any(host in lowered for host in ("localhost", "127.0.0.1", "::1"))


def _server_text_blob(name: str, server: dict[str, Any]) -> str:
    cmd = str(server.get("command", ""))
    args = " ".join(str(a) for a in server.get("args", []) if isinstance(a, (str, int, float)))
    return f"{name} {cmd} {args}".lower()


def _has_version_pin_for_npx(args: list[Any]) -> bool:
    for arg in args:
        if isinstance(arg, str) and "@" in arg and not arg.startswith("@"):
            return True
    return False


def _has_version_pin_for_uvx(args: list[Any]) -> bool:
    return any(isinstance(arg, str) and "==" in arg for arg in args)


def _scan_config_dict(config: dict[str, Any] | list[Any]) -> tuple[int, list[Finding], dict[str, int]]:
    servers = _extract_servers(config)
    findings: list[Finding] = []

    def add(severity: str, title: str, server: str, found: str, fix: str) -> None:
        findings.append(Finding(severity=severity, title=title, server=server, found=found, fix=fix))

    if not servers:
        add(
            "INFO",
            "No MCP servers found",
            "global",
            "Configuration does not contain any MCP server entries.",
            "Add servers under mcpServers to analyze concrete risk.",
        )

    for name, server in servers.items():
        command = str(server.get("command", ""))
        args = server.get("args")
        args_list = args if isinstance(args, list) else []
        args_text = " ".join(str(a) for a in args_list)
        text_blob = _server_text_blob(name, server)

        env = server.get("env")
        env_dict = env if isinstance(env, dict) else {}
        for key, raw_val in env_dict.items():
            value = str(raw_val)
            if _is_likely_secret(value) or (
                SECRET_KEY_PATTERN.search(str(key)) and value and not value.startswith("$")
            ):
                preview = value[:20] + ("..." if len(value) > 20 else "")
                add(
                    "CRITICAL",
                    "Hardcoded secret in env",
                    name,
                    f'{key} = "{preview}"',
                    "Move secrets to real environment variables or a secret manager.",
                )
            if str(key).upper() in (
                "NODE_TLS_REJECT_UNAUTHORIZED",
                "PYTHONHTTPSVERIFY",
                "CURL_INSECURE",
            ) and value.strip() in ("0", "false", "False"):
                add(
                    "HIGH",
                    "TLS verification disabled",
                    name,
                    f'{key} = "{value}"',
                    "Enable strict TLS verification in all environments.",
                )

        if command.lower() in ("bash", "sh", "cmd", "powershell", "pwsh", "zsh"):
            add(
                "CRITICAL",
                "Shell interpreter used as command",
                name,
                command,
                "Invoke the target binary directly instead of shell wrappers.",
            )
        if SHELL_META_PATTERN.search(args_text) or SHELL_DYNAMIC_PATTERN.search(f"{command} {args_text}"):
            add(
                "CRITICAL",
                "Possible shell injection pattern",
                name,
                args_text[:160] or command,
                "Remove shell metacharacters and avoid dynamic shell execution.",
            )

        url = str(server.get("url") or server.get("baseUrl") or "")
        transport = str(server.get("transport") or server.get("type") or "")
        if _looks_remote_http(url) and transport.lower() in ("sse", "http", "streamable-http"):
            add(
                "HIGH",
                "Unencrypted remote transport",
                name,
                url,
                "Use HTTPS for all remote MCP endpoints.",
            )

        allowed_dirs = server.get("allowedDirectories")
        if isinstance(allowed_dirs, list):
            normalized = {str(x).strip() for x in allowed_dirs}
            if "/" in normalized or "~" in normalized:
                add(
                    "HIGH",
                    "Overprivileged filesystem scope",
                    name,
                    f"allowedDirectories={allowed_dirs}",
                    "Restrict filesystem scope to specific project directories.",
                )
            broad_prefixes = ("C:\\", "C:/", "/home", "/Users")
            if any(str(x).startswith(broad_prefixes) for x in normalized):
                add(
                    "HIGH",
                    "Broad filesystem directory access",
                    name,
                    f"allowedDirectories={allowed_dirs}",
                    "Limit access to minimal subdirectories instead of home/root-level paths.",
                )

        if command == "npx" and "-y" in [str(a) for a in args_list] and not _has_version_pin_for_npx(args_list):
            add(
                "MEDIUM",
                "Missing version pinning",
                name,
                f'{command} {" ".join(str(a) for a in args_list)}',
                "Pin package version, for example: npx -y package@1.2.3",
            )
        if command in ("uvx", "pipx") and not _has_version_pin_for_uvx(args_list):
            add(
                "MEDIUM",
                "Missing version pinning",
                name,
                f'{command} {" ".join(str(a) for a in args_list)}',
                f"Pin dependency version with ==, for example: {command} package==1.2.3",
            )

        for pkg, issue in KNOWN_VULNERABLE_PACKAGES.items():
            if pkg in text_blob:
                add(
                    "HIGH",
                    "Known risky MCP package",
                    name,
                    pkg,
                    f"{issue} Keep only if required and apply strict policy controls.",
                )

        if bool(server.get("disabled")) and env_dict:
            sensitive_env = [k for k in env_dict if SECRET_KEY_PATTERN.search(str(k))]
            if sensitive_env:
                add(
                    "MEDIUM",
                    "Disabled server still contains credentials",
                    name,
                    ", ".join(str(k) for k in sensitive_env[:5]),
                    "Remove stale credentials from disabled server entries.",
                )

        allowed_tools = server.get("allowedTools")
        if allowed_tools == ["*"] or allowed_tools == "*":
            add(
                "MEDIUM",
                "Wildcard tool permissions",
                name,
                f"allowedTools={allowed_tools}",
                "Replace wildcard with explicit least-privilege allowlist.",
            )
        elif allowed_tools is None:
            add(
                "MEDIUM",
                "Missing allowedTools",
                name,
                "allowedTools not defined",
                "Define explicit allowedTools per server.",
            )

        if "0.0.0.0" in args_text:
            add(
                "HIGH",
                "Network exposure to all interfaces",
                name,
                args_text[:160],
                "Bind only to localhost unless public exposure is explicitly required.",
            )
        port_match = re.search(r"(?:--port\s+|:)(\d{2,5})", args_text)
        if port_match:
            add(
                "INFO",
                "Server exposes a TCP port",
                name,
                f"port {port_match.group(1)}",
                "Ensure firewall rules and binding scope are appropriate.",
            )

        if PATH_TRAVERSAL_PATTERN.search(args_text):
            add(
                "LOW",
                "Path traversal in args",
                name,
                args_text[:160],
                "Normalize paths and avoid traversal segments like ../",
            )

        description = server.get("description")
        metadata = server.get("metadata")
        metadata_desc = metadata.get("description") if isinstance(metadata, dict) else None
        if not description and not metadata_desc:
            add(
                "LOW",
                "Missing server description",
                name,
                "description field is absent",
                "Document server purpose and trust assumptions for audits.",
            )

    findings.sort(key=lambda item: SEVERITY_ORDER.get(item.severity, -1), reverse=True)
    summary = {key: 0 for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
    total_deduction = sum(SEVERITY_DEDUCTIONS.get(f.severity, 0) for f in findings)
    score = max(0, 100 - total_deduction)
    return score, findings, summary


def _score_label(score: int) -> str:
    if score >= 90:
        return "EXCELLENT"
    if score >= 75:
        return "GOOD"
    if score >= 55:
        return "FAIR"
    if score >= 35:
        return "POOR"
    return "CRITICAL"


def _render_scan_result(score: int, findings: list[Finding], summary: dict[str, int]) -> str:
    lines: list[str] = []
    lines.append(f"MCP Security Score: {score}/100 ({_score_label(score)})")
    lines.append("")
    lines.append(
        "Findings by severity: "
        + ", ".join(f"{sev}={summary.get(sev, 0)}" for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    )
    lines.append("")
    lines.append(f"Found {len(findings)} issue(s).")
    lines.append("")
    for finding in findings:
        lines.append(f"[{finding.severity}] {finding.title} in \"{finding.server}\"")
        lines.append(f"  Found: {finding.found}")
        lines.append(f"  Fix: {finding.fix}")
        lines.append("")
    lines.append("Recommendations:")
    lines.append("1. Never hardcode API keys, tokens, or passwords in MCP configs.")
    lines.append("2. Use HTTPS and strict TLS verification for all remote connections.")
    lines.append("3. Pin all package versions and enforce least-privilege tool allowlists.")
    lines.append("4. Restrict filesystem and network scope to the minimum required.")
    return "\n".join(lines).rstrip() + _brand_tail()


def _flatten_values(payload: Any) -> str:
    if isinstance(payload, dict):
        return " ".join(f"{k} {_flatten_values(v)}" for k, v in payload.items())
    if isinstance(payload, list):
        return " ".join(_flatten_values(item) for item in payload)
    return str(payload)


def _render_tool_call_risk(
    risk: str,
    tool_name: str,
    findings: list[str],
    recommendations: list[str],
) -> str:
    lines = [f"Tool call risk: {risk}", f"Tool: {tool_name}", ""]
    if findings:
        lines.append("Findings:")
        for item in findings:
            lines.append(f"- {item}")
    else:
        lines.append("Findings:")
        lines.append("- No obvious high-risk patterns detected.")
    lines.append("")
    lines.append("Recommendations:")
    for rec in recommendations:
        lines.append(f"- {rec}")
    return "\n".join(lines).rstrip() + _brand_tail()


mcp = FastMCP("Orchesis MCP Security Server")


@mcp.tool()
def scan_mcp_config(config_json: str) -> str:
    """Scan an MCP server configuration for security vulnerabilities.

    Paste MCP config JSON (for example from claude_desktop_config.json or
    .cursor/mcp.json) and receive a security score from 0 to 100 with
    findings and remediation advice.

    Args:
        config_json: MCP configuration JSON string.

    Returns:
        Security analysis report with score, findings, and recommendations.
    """
    parsed, error = _safe_json_loads(config_json)
    if error:
        return (
            "MCP Security Score: 0/100 (CRITICAL)\n\n"
            f"{error}\n"
            "Fix JSON syntax and run the scan again."
            + _brand_tail()
        )
    score, findings, summary = _scan_config_dict(parsed)
    return _render_scan_result(score, findings, summary)


@mcp.tool()
def check_tool_call_safety(
    tool_name: str,
    tool_arguments: str,
    context: str = "",
) -> str:
    """Check whether an AI agent tool call appears safe before execution.

    Analyzes tool name and arguments for path traversal, command injection,
    data exfiltration, privilege escalation, and prompt injection signals.

    Args:
        tool_name: Tool identifier (for example, read_file or shell_exec).
        tool_arguments: JSON string with tool arguments.
        context: Optional intent/context text.

    Returns:
        Safety assessment with risk level and specific concerns.
    """
    findings: list[str] = []
    recommendations: list[str] = []
    critical_hits = 0

    args_data, _ = _safe_json_loads(tool_arguments)
    combined = f"{tool_name} {tool_arguments} {context}".lower()
    flattened_args = _flatten_values(args_data) if args_data is not None else tool_arguments
    lowered_args = flattened_args.lower()

    dangerous_tools = {"shell_exec", "run_command", "terminal", "exec", "eval", "bash"}
    if tool_name.strip().lower() in dangerous_tools:
        findings.append("Dangerous tool category detected (direct command execution).")
        recommendations.append("Require explicit human approval for command-execution tools.")
        critical_hits += 1

    if PATH_TRAVERSAL_PATTERN.search(lowered_args) or re.search(r"/etc/|~/.ssh|~/.aws|c:\\windows\\system32", lowered_args):
        findings.append("Path traversal or sensitive system path access detected.")
        recommendations.append("Restrict file operations to approved workspace roots.")
        critical_hits += 1

    if SHELL_META_PATTERN.search(lowered_args) or SHELL_DYNAMIC_PATTERN.search(lowered_args):
        findings.append("Command injection markers detected in tool arguments.")
        recommendations.append("Reject shell metacharacters and parse arguments strictly.")
        critical_hits += 1

    if re.search(r"\brm\s+-rf\b|\bcurl\b.+\|\s*bash|\bwget\b", lowered_args):
        findings.append("High-risk destructive or remote execution command pattern detected.")
        recommendations.append("Block destructive commands and remote shell bootstrap patterns.")
        critical_hits += 1

    if re.search(r"webhook\.site|requestbin|ngrok\.io|pipedream\.net|discord\.com/api/webhooks", combined):
        findings.append("Potential data exfiltration endpoint found.")
        recommendations.append("Disallow outbound requests to untrusted webhook endpoints.")
        critical_hits += 1

    if re.search(r"\bsudo\b|\bchmod\s+777\b|\bchown\s+root\b", lowered_args):
        findings.append("Privilege escalation pattern detected.")
        recommendations.append("Run agents under least privilege and deny elevation commands.")
        critical_hits += 1

    if re.search(r"ignore previous instructions|system prompt:|developer message:", combined):
        findings.append("Prompt injection phrase detected in tool input/context.")
        recommendations.append("Treat user content as untrusted and isolate instruction channels.")

    if re.search(r"\.env\b|credentials|secrets|id_rsa|shadow", lowered_args):
        findings.append("Sensitive file access pattern detected.")
        recommendations.append("Require approval and masking for sensitive file reads.")
        critical_hits += 1

    if "\u200b" in tool_arguments or "\u200c" in tool_arguments or "\u2060" in tool_arguments:
        findings.append("Zero-width characters detected, possible obfuscation attempt.")
        recommendations.append("Normalize and sanitize Unicode input before policy checks.")

    if critical_hits > 0:
        risk = "DANGEROUS"
    elif findings:
        risk = "CAUTION"
    else:
        risk = "SAFE"
        recommendations.append("Proceed with normal policy checks and audit logging.")

    if not recommendations:
        recommendations.append("Perform standard allowlist and auditing checks before execution.")
    return _render_tool_call_risk(risk, tool_name, findings, recommendations)


@mcp.tool()
def get_security_posture() -> str:
    """Get a concise summary of AI agent security posture and best practices.

    Returns:
        Static reference covering major threats, OWASP ASI Top 10 themes,
        and a practical checklist for secure AI agent deployments.
    """
    lines = [
        "AI Agent Security Posture Summary",
        "",
        f"Orchesis core version detected: {ORCHESIS_VERSION}",
        "",
        "Top 5 current threats:",
        "1. Prompt injection and instruction override attacks in tool-using agents.",
        "2. Supply-chain compromise of dependencies and execution wrappers (example: CVE-2024-3094).",
        "3. Credential leakage via logs, configs, and untrusted tool outputs.",
        "4. Data exfiltration through outbound connectors and webhook endpoints.",
        "5. Overprivileged tool permissions enabling filesystem or shell abuse.",
        "",
        "OWASP ASI Top 10 (quick view):",
        "- ASI-01 Prompt Injection: untrusted instructions alter agent behavior.",
        "- ASI-02 Insecure Output Handling: unsafe model output drives dangerous actions.",
        "- ASI-03 Training Data Poisoning: compromised data influences model behavior.",
        "- ASI-04 Model Denial of Service: resource exhaustion via adversarial inputs.",
        "- ASI-05 Supply Chain Vulnerabilities: compromised models, data, or packages.",
        "- ASI-06 Sensitive Information Disclosure: secrets exposed via prompts or tools.",
        "- ASI-07 Insecure Plugin Design: risky connector and tool interfaces.",
        "- ASI-08 Excessive Agency: agents granted unnecessary autonomy and privileges.",
        "- ASI-09 Overreliance: users trust outputs without verification.",
        "- ASI-10 Model Theft: unauthorized extraction or cloning of model assets.",
        "",
        "Quick security checklist:",
        "1. Enforce tool allowlists and least privilege.",
        "2. Isolate credentials using a secret manager.",
        "3. Block shell metacharacters and traversal patterns.",
        "4. Restrict filesystem and network egress scope.",
        "5. Pin package versions and verify integrity.",
        "6. Add prompt injection guards before tool execution.",
        "7. Require human approval for destructive actions.",
        "8. Log decisions with tamper-evident audit trails.",
        "9. Use sandboxing for high-risk tools.",
        "10. Run continuous policy and configuration scans.",
        "",
        "Runtime protection reference:",
        "https://github.com/poushwell/orchesis",
    ]
    return "\n".join(lines).rstrip() + _brand_tail()


def main() -> None:
    """Run MCP server over stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
