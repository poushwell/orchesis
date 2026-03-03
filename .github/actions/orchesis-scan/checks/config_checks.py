from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .models import Finding

_SHELL_INJECTION_RE = re.compile(r"(;|\|\||&&|`|\$\(|\b(?:rm|curl|wget|powershell)\b)", re.IGNORECASE)
_SECRET_KEY_RE = re.compile(r"(token|secret|api[_-]?key|password)", re.IGNORECASE)
_SECRET_VALUE_RE = re.compile(r"(sk-[A-Za-z0-9]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})")
_TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\")
_PERMISSIVE_PATH_RE = re.compile(r"(^/$|^\*$|^~/?$|^[A-Za-z]:\\$)")


def _line_number(source: str, token: str) -> int:
    idx = source.find(token)
    if idx < 0:
        return 1
    return source[:idx].count("\n") + 1


def _iter_servers(payload: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    raw = payload.get("mcpServers")
    if not isinstance(raw, dict):
        raw = payload.get("servers")
    if not isinstance(raw, dict):
        return []
    out: list[tuple[str, dict[str, Any]]] = []
    for name, cfg in raw.items():
        if isinstance(name, str) and isinstance(cfg, dict):
            out.append((name, cfg))
    return out


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


def run_config_checks(config_path: str) -> list[Finding]:
    path = Path(config_path)
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        return [
            _finding(
                "CFG_READ_ERROR",
                "high",
                "Config file cannot be read",
                str(error),
                str(path),
                1,
                "Ensure file exists and the workflow has read permissions.",
            )
        ]

    try:
        payload = json.loads(source)
    except Exception as error:  # noqa: BLE001
        return [
            _finding(
                "CFG_MALFORMED_JSON",
                "high",
                "Malformed MCP config JSON",
                f"JSON parse failed: {error}",
                str(path),
                1,
                "Fix syntax errors in JSON configuration.",
            )
        ]

    if not isinstance(payload, dict):
        return [
            _finding(
                "CFG_ROOT_NOT_OBJECT",
                "high",
                "Invalid config root type",
                "Top-level JSON must be an object.",
                str(path),
                1,
                "Use object root with mcpServers mapping.",
            )
        ]

    findings: list[Finding] = []
    servers = _iter_servers(payload)
    if not servers:
        return findings

    for name, server in servers:
        prefix = f"mcpServers.{name}"
        command = str(server.get("command", "")).strip()
        args = server.get("args")
        args_list = [str(item) for item in args] if isinstance(args, list) else []
        args_joined = " ".join(args_list)
        url = str(server.get("url", "")).strip()
        env = server.get("env")
        roots = server.get("allowed_paths") or server.get("roots") or []
        tools = server.get("tools", [])
        auth = server.get("auth") or server.get("token") or server.get("apiKey")
        package = str(server.get("package", "")).strip()
        image = str(server.get("image", "")).strip()

        # 1
        if command and _SHELL_INJECTION_RE.search(command):
            findings.append(
                _finding(
                    "CFG_COMMAND_INJECTION",
                    "critical",
                    "Possible command injection in server command",
                    f"{prefix}.command contains shell control operators.",
                    str(path),
                    _line_number(source, command),
                    "Use fixed executable path and remove shell operators.",
                )
            )

        # 2
        if args_list and _SHELL_INJECTION_RE.search(args_joined):
            findings.append(
                _finding(
                    "CFG_ARGS_INJECTION",
                    "high",
                    "Possible command injection in args",
                    f"{prefix}.args contains shell control patterns.",
                    str(path),
                    _line_number(source, args_list[0]),
                    "Sanitize args and avoid shell interpolation.",
                )
            )

        # 3
        traversal_arg = next((item for item in args_list if _TRAVERSAL_RE.search(item)), "")
        if traversal_arg:
            findings.append(
                _finding(
                    "CFG_PATH_TRAVERSAL",
                    "high",
                    "Path traversal risk in args",
                    f"{prefix}.args includes traversal token: {traversal_arg}",
                    str(path),
                    _line_number(source, traversal_arg),
                    "Validate and normalize paths before passing args.",
                )
            )

        # 4
        if any(flag in args_list for flag in ("--allow-all", "--unsafe", "--dangerously-skip-permissions")):
            findings.append(
                _finding(
                    "CFG_DANGEROUS_FLAGS",
                    "critical",
                    "Dangerous permissive flags enabled",
                    f"{prefix}.args includes unsafe execution flags.",
                    str(path),
                    _line_number(source, "--allow-all"),
                    "Remove permissive flags and enable strict permission checks.",
                )
            )

        # 5
        if isinstance(env, dict):
            for key, value in env.items():
                if not isinstance(key, str):
                    continue
                value_str = str(value)
                if _SECRET_KEY_RE.search(key) and value_str and value_str != "${ENV_VAR}":
                    findings.append(
                        _finding(
                            "CFG_ENV_SECRET_EXPOSED",
                            "critical",
                            "Secret value exposed in env section",
                            f"{prefix}.env.{key} appears to store plaintext secret.",
                            str(path),
                            _line_number(source, key),
                            "Use GitHub secrets and environment substitution.",
                        )
                    )
                elif _SECRET_VALUE_RE.search(value_str):
                    findings.append(
                        _finding(
                            "CFG_ENV_SECRET_PATTERN",
                            "high",
                            "Sensitive token-like value in env",
                            f"{prefix}.env.{key} matches known token pattern.",
                            str(path),
                            _line_number(source, value_str),
                            "Rotate leaked credentials and inject at runtime.",
                        )
                    )

        # 6
        if url.startswith("http://"):
            host = (urlparse(url).hostname or "").lower()
            sev = "medium" if host in {"127.0.0.1", "localhost"} else "high"
            findings.append(
                _finding(
                    "CFG_INSECURE_HTTP",
                    sev,
                    "Insecure MCP transport over HTTP",
                    f"{prefix}.url uses http:// instead of https://",
                    str(path),
                    _line_number(source, url),
                    "Use https:// endpoints with TLS.",
                )
            )

        # 7
        if "0.0.0.0" in url or str(server.get("bind", "")).startswith("0.0.0.0"):
            findings.append(
                _finding(
                    "CFG_BIND_ALL_INTERFACES",
                    "critical",
                    "Server bound to all interfaces",
                    f"{prefix} appears publicly reachable via 0.0.0.0.",
                    str(path),
                    _line_number(source, "0.0.0.0"),
                    "Bind to localhost or private network interface only.",
                )
            )

        # 8
        if not args_list:
            findings.append(
                _finding(
                    "CFG_MISSING_ARGS_VALIDATION",
                    "medium",
                    "Server args are not explicitly defined",
                    f"{prefix} does not specify args constraints.",
                    str(path),
                    _line_number(source, name),
                    "Define strict validated args for server command.",
                )
            )

        # 9
        if command and not Path(command).is_absolute() and "/" not in command and "\\" not in command:
            findings.append(
                _finding(
                    "CFG_RELATIVE_COMMAND",
                    "medium",
                    "Relative command path used",
                    f"{prefix}.command resolves from PATH and may be hijacked.",
                    str(path),
                    _line_number(source, command),
                    "Use absolute command path or pinned runtime executable.",
                )
            )

        # 10
        if any("curl" in item.lower() and "bash" in item.lower() for item in args_list):
            findings.append(
                _finding(
                    "CFG_REMOTE_SCRIPT_EXEC",
                    "critical",
                    "Remote script execution pattern found",
                    f"{prefix}.args includes curl|bash style execution.",
                    str(path),
                    _line_number(source, "curl"),
                    "Vendor scripts and verify checksums before execution.",
                )
            )

        # 11
        if isinstance(roots, list) and any(isinstance(root, str) and _PERMISSIVE_PATH_RE.search(root.strip()) for root in roots):
            findings.append(
                _finding(
                    "CFG_OVERLY_PERMISSIVE_PATHS",
                    "high",
                    "Overly permissive filesystem roots",
                    f"{prefix} includes root/wildcard path access.",
                    str(path),
                    _line_number(source, "/"),
                    "Restrict allowed paths to least privilege directories.",
                )
            )

        # 12
        if isinstance(tools, list) and any(str(tool).strip() == "*" for tool in tools):
            findings.append(
                _finding(
                    "CFG_WILDCARD_TOOLS",
                    "high",
                    "Wildcard tool permission granted",
                    f"{prefix}.tools contains wildcard access.",
                    str(path),
                    _line_number(source, "*"),
                    "Enumerate explicit allowed tools.",
                )
            )

        # 13
        if package and ("@latest" in package or package.endswith(":latest")):
            findings.append(
                _finding(
                    "CFG_UNPINNED_PACKAGE",
                    "medium",
                    "Unpinned package version",
                    f"{prefix}.package is not pinned to exact version.",
                    str(path),
                    _line_number(source, package),
                    "Pin exact version to reduce supply-chain risk.",
                )
            )

        # 14
        if image and image.endswith(":latest"):
            findings.append(
                _finding(
                    "CFG_UNPINNED_IMAGE",
                    "medium",
                    "Unpinned container image tag",
                    f"{prefix}.image uses :latest tag.",
                    str(path),
                    _line_number(source, image),
                    "Pin immutable image digest or fixed version tag.",
                )
            )

        # 15
        if url.startswith("https://") and not auth:
            findings.append(
                _finding(
                    "CFG_REMOTE_NO_AUTH",
                    "high",
                    "Remote MCP endpoint without auth",
                    f"{prefix} targets remote endpoint but no token/auth configured.",
                    str(path),
                    _line_number(source, url),
                    "Add token/apiKey and enforce authenticated transport.",
                )
            )

    return findings
