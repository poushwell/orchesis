"""Plugin wrapper for secret scanner."""

from __future__ import annotations

from typing import Any

from orchesis.contrib.secret_scanner import SecretScanner
from orchesis.plugins import PluginInfo

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_at_least(value: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(value.lower(), 0) >= SEVERITY_ORDER.get(threshold.lower(), 0)


class SecretScannerPlugin:
    """Orchesis policy plugin: block tool calls containing secrets."""

    def __init__(
        self,
        check_params: bool = True,
        check_responses: bool = True,
        severity_threshold: str = "high",
        ignore_patterns: list[str] | None = None,
    ) -> None:
        self._check_params = check_params
        self._check_responses = check_responses
        self._severity_threshold = severity_threshold
        self._scanner = SecretScanner(ignore_patterns=ignore_patterns)

    def evaluate(
        self,
        rule: dict[str, Any],
        request: dict[str, Any],
        **kwargs: Any,  # noqa: ANN401
    ) -> tuple[list[str], list[str]]:
        _ = kwargs
        check_params = bool(rule.get("check_params", self._check_params))
        threshold = str(rule.get("severity_threshold", self._severity_threshold))
        ignore = rule.get("ignore_patterns")
        scanner = (
            SecretScanner(ignore_patterns=ignore)
            if isinstance(ignore, list)
            else self._scanner
        )
        reasons: list[str] = []
        checked = ["secret_scanner"]
        if not check_params:
            return reasons, checked

        tool_name = request.get("tool")
        safe_tool = str(tool_name) if isinstance(tool_name, str) else "__unknown__"
        params = request.get("params")
        safe_params = params if isinstance(params, dict) else {}
        findings = scanner.scan_tool_call(safe_tool, safe_params)
        blocking = [item for item in findings if _severity_at_least(str(item["severity"]), threshold)]
        if blocking:
            labels = ", ".join(
                f"{item['pattern']}@{item.get('path', 'params')}" for item in blocking[:3]
            )
            reasons.append(f"secret_scanner: secret-like content detected ({labels})")
        return reasons, checked

    def scan_response(self, tool_name: str, response: str) -> list[dict[str, Any]]:
        if not self._check_responses:
            return []
        findings = self._scanner.scan_text(response)
        for finding in findings:
            finding["tool"] = tool_name
        return findings


PLUGIN_INFO = PluginInfo(
    name="secret_scanner",
    rule_type="secret_scanner",
    version="1.0",
    description="Block tool calls containing secrets",
    handler=SecretScannerPlugin(),
)
