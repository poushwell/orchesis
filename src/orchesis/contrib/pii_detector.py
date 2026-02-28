"""Plugin: Block requests containing PII patterns."""

from __future__ import annotations

import re
from typing import Any

from orchesis.plugins import PluginInfo


class PIIDetectorHandler:
    """Checks params for email, phone, SSN, and credit card patterns."""

    PII_PATTERNS = {
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
    }

    def _extract_field(self, request: dict[str, Any], field_path: str) -> Any:
        current: Any = request
        for segment in field_path.split("."):
            if not isinstance(current, dict):
                return None
            current = current.get(segment)
        return current

    def _collect_strings(self, value: Any, prefix: str = "") -> list[tuple[str, str]]:
        if isinstance(value, str):
            return [(prefix or "value", value)]
        if isinstance(value, dict):
            collected: list[tuple[str, str]] = []
            for key, item in value.items():
                child_prefix = f"{prefix}.{key}" if prefix else str(key)
                collected.extend(self._collect_strings(item, child_prefix))
            return collected
        if isinstance(value, list):
            collected: list[tuple[str, str]] = []
            for index, item in enumerate(value):
                child_prefix = f"{prefix}[{index}]"
                collected.extend(self._collect_strings(item, child_prefix))
            return collected
        return []

    def evaluate(self, rule, request, **kwargs):  # noqa: ANN001, ANN003
        _ = kwargs
        checked = ["pii_detector"]
        reasons: list[str] = []
        fields = rule.get("check_fields")
        strings: list[tuple[str, str]] = []
        if isinstance(fields, list) and fields:
            for field in fields:
                if not isinstance(field, str):
                    continue
                strings.extend(self._collect_strings(self._extract_field(request, field), field))
        else:
            strings = self._collect_strings(request.get("params"), "params")
        for field_name, value in strings:
            for pii_type, pattern in self.PII_PATTERNS.items():
                if re.search(pattern, value):
                    reasons.append(f"pii_detector: {pii_type} found in {field_name}")
        return reasons, checked


PLUGIN_INFO = PluginInfo(
    name="pii_detector",
    rule_type="pii_detector",
    version="1.0",
    description="Block requests containing PII patterns",
    handler=PIIDetectorHandler(),
)
