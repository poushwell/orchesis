"""Automatic redaction helpers for audit and telemetry logs."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from orchesis.contrib.pii_detector import PiiDetector
from orchesis.contrib.secret_scanner import SecretScanner


class AuditRedactor:
    """Auto-redact PII and secrets from audit log events."""

    def __init__(
        self,
        redact_secrets: bool = True,
        redact_pii: bool = True,
        secret_scanner: SecretScanner | None = None,
        pii_detector: PiiDetector | None = None,
        preserve_fields: list[str] | None = None,
    ):
        self._secret_scanner = secret_scanner or SecretScanner()
        self._pii_detector = pii_detector or PiiDetector() if redact_pii else None
        self._redact_secrets = redact_secrets
        self._redact_pii = redact_pii
        self._preserve_fields = set(preserve_fields or [])

    def redact_event(self, event: dict[str, Any]) -> dict[str, Any]:
        redacted = deepcopy(event)
        return self.redact_dict(redacted)

    def redact_string(self, text: str) -> str:
        output = text
        if self._redact_secrets:
            findings = self._secret_scanner.scan_text(output)
            output = SecretScanner.redact(output, findings)
        if self._redact_pii and self._pii_detector is not None:
            output = self._pii_detector.redact_text(output)
        return output

    def redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        def _walk(value: Any, path: str = "") -> Any:
            if isinstance(value, str):
                root = path.split(".", 1)[0] if path else ""
                if root in self._preserve_fields:
                    return value
                return self.redact_string(value)
            if isinstance(value, dict):
                return {
                    key: _walk(item, f"{path}.{key}" if path else str(key))
                    for key, item in value.items()
                }
            if isinstance(value, list):
                return [_walk(item, path) for item in value]
            return value

        return _walk(data)
