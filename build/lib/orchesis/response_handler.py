"""Response processing: secret scanning, token/cost extraction, metadata."""

from __future__ import annotations

import re
from typing import Any

from orchesis.cost_tracker import CostTracker
from orchesis.request_parser import ParsedResponse

SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "OpenAI API key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36,}"), "GitHub PAT"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"xox[bsp]-[a-zA-Z0-9-]+"), "Slack token"),
    (re.compile(r"glpat-[a-zA-Z0-9_-]{20,}"), "GitLab token"),
    (re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----"), "Private key"),
    (re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"), "JWT token"),
]


class ResponseProcessor:
    """Process parsed LLM response payload with security/cost checks."""

    def __init__(
        self,
        cost_tracker: CostTracker | None = None,
        secret_patterns: list[tuple[re.Pattern[str], str]] | None = None,
        scan_secrets: bool = True,
    ) -> None:
        self._tracker = cost_tracker
        self._patterns = list(secret_patterns) if isinstance(secret_patterns, list) else SECRET_PATTERNS
        self._scan_secrets = bool(scan_secrets)
        self._secrets_found: list[dict[str, Any]] = []

    def process(self, parsed: ParsedResponse, task_id: str | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "allowed": True,
            "reason": "",
            "secrets_found": [],
            "cost": 0.0,
            "tokens": {"input": int(parsed.input_tokens), "output": int(parsed.output_tokens)},
            "tool_calls": [{"name": tc.name, "params": tc.params} for tc in parsed.tool_calls],
        }

        if self._scan_secrets and isinstance(parsed.content_text, str) and parsed.content_text:
            secrets = self._scan_for_secrets(parsed.content_text)
            if secrets:
                result["allowed"] = False
                result["reason"] = (
                    f"Response contains {len(secrets)} potential secret(s): "
                    + ", ".join(item["type"] for item in secrets)
                )
                result["secrets_found"] = secrets
                self._secrets_found = secrets
            else:
                self._secrets_found = []

        if self._tracker is not None and isinstance(parsed.model, str) and parsed.model:
            entry = self._tracker.record_call(
                tool_name=f"llm:{parsed.model}",
                task_id=task_id,
                model=parsed.model,
                tokens_input=int(parsed.input_tokens),
                tokens_output=int(parsed.output_tokens),
            )
            result["cost"] = float(entry.cost_usd)

        return result

    def _scan_for_secrets(self, text: str) -> list[dict[str, str]]:
        found: list[dict[str, str]] = []
        for pattern, secret_type in self._patterns:
            matches = pattern.findall(text)
            for match in matches:
                safe_preview = f"{match[:8]}..." if len(match) > 8 else match
                found.append({"type": secret_type, "match_preview": safe_preview})
        return found

    @property
    def secrets_found(self) -> list[dict[str, Any]]:
        return list(self._secrets_found)

