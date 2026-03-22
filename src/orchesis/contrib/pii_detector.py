"""PII detector and backward-compatible plugin handler."""

from __future__ import annotations

import re
import unicodedata
from copy import deepcopy
from typing import Any

from orchesis.fast_scanner import FastPIIDetector
from orchesis.input_guard import sanitize_text
from orchesis.plugins import PluginInfo

BIDI_CONTROLS = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u200f", "\u200e"}

PII_PATTERNS: dict[str, tuple[re.Pattern[str], str, str]] = {
    "email": (
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "medium",
        "Email address",
    ),
    "phone_us": (
        re.compile(r"(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"),
        "medium",
        "US phone number",
    ),
    "phone_intl": (
        re.compile(r"\+\d{1,3}[-.\s]?\d{4,14}"),
        "medium",
        "International phone number",
    ),
    "ssn": (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "critical", "US Social Security Number"),
    "passport_us": (re.compile(r"\b[A-Z]\d{8}\b"), "high", "Possible US passport number"),
    "credit_card_visa": (
        re.compile(r"\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
        "critical",
        "Visa credit card number",
    ),
    "credit_card_mc": (
        re.compile(r"\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
        "critical",
        "Mastercard credit card number",
    ),
    "credit_card_amex": (
        re.compile(r"\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b"),
        "critical",
        "Amex credit card number",
    ),
    "iban": (
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?\d{0,16})\b"),
        "high",
        "IBAN number",
    ),
    "swift_bic": (
        re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b"),
        "medium",
        "SWIFT/BIC code",
    ),
    "icd10_code": (re.compile(r"\b[A-Z]\d{2}(\.\d{1,4})?\b"), "low", "Possible ICD-10 code"),
    "npi_number": (re.compile(r"\b\d{10}\b"), "medium", "Possible NPI number"),
    "ipv4_address": (
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
        "low",
        "IPv4 address",
    ),
    "mac_address": (
        re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
        "low",
        "MAC address",
    ),
    "date_of_birth": (
        re.compile(r"(?i)\b(?:dob|date.of.birth|born)\s*[=:]\s*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}"),
        "high",
        "Date of birth",
    ),
    "drivers_license": (
        re.compile(r"(?i)(?:driver'?s?\s*license|DL)\s*[#:]\s*[A-Z0-9]{5,15}"),
        "high",
        "Driver's license number",
    ),
}

CLASSIFICATION_LEVELS = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
}

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_CRITICAL_PATTERNS = {"ssn", "credit_card_visa", "credit_card_mc", "credit_card_amex"}


def preprocess_for_pii(text: str) -> list[str]:
    if not isinstance(text, str):
        try:
            text = str(text, "utf-8", errors="replace")  # type: ignore[arg-type]
        except Exception:
            text = repr(text)
    if not text:
        return [text]
    try:
        text = text.replace("\x00", "")
    except Exception:
        pass
    try:
        text = text.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    except Exception:
        pass

    versions: list[str] = [text]
    cleaned = text
    try:
        cleaned = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", text)
        if cleaned != text:
            versions.append(cleaned)
    except Exception:
        cleaned = text
    try:
        normalized = unicodedata.normalize("NFKC", cleaned)
        if normalized != cleaned:
            versions.append(normalized)
    except Exception:
        pass
    deduped: list[str] = []
    seen: set[str] = set()
    for item in versions:
        try:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        except Exception:
            continue
    return deduped or [text]


def _sanitize_detect_input(text: Any) -> str:
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    if not isinstance(text, str):
        text = str(text)
    text = text.encode("utf-16", errors="surrogatepass").decode("utf-16", errors="replace")
    text = text.replace("\ufffd", "")
    text = text.replace("\x00", "")
    # Remove BIDI override and other formatting characters.
    text = "".join(
        c for c in text if unicodedata.category(c) != "Cf" or c in (" ", "\t", "\n")
    )
    # Remove replacement chars from broken UTF-8 and null bytes after normalization.
    text = text.replace("\ufffd", "")
    text = text.replace("\x00", "")
    if len(text) > 100000:
        text = text[:100000]
    return text


class PiiDetector:
    """Detect PII and sensitive data in text and structured data."""

    def __init__(
        self,
        patterns: dict[str, tuple[re.Pattern[str], str, str]] | None = None,
        custom_patterns: dict[str, tuple[re.Pattern[str], str, str]] | None = None,
        ignore_patterns: list[str] | None = None,
        severity_threshold: str = "medium",
        use_fast_matching: bool = True,
    ):
        self._patterns = dict(patterns or PII_PATTERNS)
        if custom_patterns:
            self._patterns.update(custom_patterns)
        self._ignored = set(ignore_patterns or [])
        self._threshold = _SEVERITY_RANK.get(severity_threshold, _SEVERITY_RANK["medium"])
        self._use_fast_matching = bool(use_fast_matching)
        self._fast_detector = FastPIIDetector(self._patterns)

    def _scan_text_sequential(self, text: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for pattern_name, (compiled, severity, description) in self._patterns.items():
            if pattern_name in self._ignored:
                continue
            if _SEVERITY_RANK.get(severity, 0) < self._threshold:
                continue
            for match in compiled.finditer(text):
                raw = match.group(0)
                findings.append(
                    {
                        "pattern": pattern_name,
                        "severity": severity,
                        "description": description,
                        "match": self._mask(raw, pattern_name),
                        "position": match.start(),
                    }
                )
        return findings

    def detect(self, text: Any) -> list[dict[str, Any]]:
        """Compatibility detect entrypoint hardened for fuzzed inputs."""
        text = _sanitize_detect_input(text)
        if not isinstance(text, str):
            return []
        try:
            text = text.encode("utf-8", errors="replace").decode("utf-8")
        except Exception:
            return []
        text = "".join(ch for ch in text if ch not in BIDI_CONTROLS)
        if not text.strip():
            return []
        try:
            return self.scan_text(text)
        except (re.error, UnicodeDecodeError, OverflowError):
            return []

    def scan_text(self, text: Any) -> list[dict[str, Any]]:
        text = _sanitize_detect_input(text)
        if not isinstance(text, str):
            return []
        try:
            text = text.encode("utf-8", errors="replace").decode("utf-8")
        except Exception:
            return []
        text = "".join(ch for ch in text if ch not in BIDI_CONTROLS)
        text = sanitize_text(text)
        if text is None:
            return []
        all_findings: list[dict[str, Any]] = []
        try:
            versions = preprocess_for_pii(text)
        except Exception:
            return []
        for version in versions:
            try:
                if self._use_fast_matching:
                    all_findings.extend(
                        self._fast_detector.scan(
                            version,
                            threshold_rank=self._threshold,
                            ignored_patterns=self._ignored,
                            mask_fn=self._mask,
                            severity_rank=_SEVERITY_RANK,
                        )
                    )
                else:
                    all_findings.extend(self._scan_text_sequential(version))
            except Exception:
                # Defensive path for malformed Unicode / fuzzed inputs.
                try:
                    all_findings.extend(self._scan_text_sequential(version))
                except Exception:
                    continue
        deduped: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int]] = set()
        for finding in sorted(all_findings, key=lambda item: int(item.get("position", 0))):
            signature = (
                str(finding.get("pattern", "")),
                str(finding.get("match", "")),
                int(finding.get("position", 0)),
            )
            if signature in seen:
                continue
            seen.add(signature)
            deduped.append(finding)
        return deduped

    def scan_dict(self, data: dict[str, Any], path: str = "") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for item_path, value in self._iter_strings(data, path):
            for finding in self.scan_text(value):
                enriched = dict(finding)
                enriched["path"] = item_path
                findings.append(enriched)
        return findings

    def classify_data(self, text: Any) -> str:
        findings = self.scan_text(text)
        if any(item["severity"] == "critical" for item in findings):
            return "restricted"
        if any(item["severity"] == "high" for item in findings):
            return "confidential"
        if any(item["severity"] == "medium" for item in findings):
            return "internal"
        return "public"

    def redact_text(self, text: Any) -> str:
        text = _sanitize_detect_input(text)
        if not isinstance(text, str):
            return ""
        matches: list[tuple[int, int, str]] = []
        for pattern_name, (compiled, severity, _) in self._patterns.items():
            if pattern_name in self._ignored:
                continue
            if _SEVERITY_RANK.get(severity, 0) < self._threshold:
                continue
            for match in compiled.finditer(text):
                matches.append((match.start(), match.end(), pattern_name))

        if not matches:
            return text

        matches.sort(key=lambda item: (item[0], -(item[1] - item[0])))
        merged: list[tuple[int, int, str]] = []
        cursor = -1
        for start, end, pattern_name in matches:
            if start < cursor:
                continue
            merged.append((start, end, pattern_name))
            cursor = end

        chunks: list[str] = []
        position = 0
        for start, end, pattern_name in merged:
            chunks.append(text[position:start])
            chunks.append(f"[REDACTED-{pattern_name}]")
            position = end
        chunks.append(text[position:])
        return "".join(chunks)

    def scan_tool_call(self, tool_name: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        findings = self.scan_dict(params, path="params")
        for finding in findings:
            finding["tool"] = tool_name
        return findings

    def _iter_strings(self, value: Any, path: str) -> list[tuple[str, str]]:
        if isinstance(value, str):
            return [(path or "$", value)]
        if isinstance(value, dict):
            out: list[tuple[str, str]] = []
            for key, item in value.items():
                child = f"{path}.{key}" if path else str(key)
                out.extend(self._iter_strings(item, child))
            return out
        if isinstance(value, list):
            out = []
            for index, item in enumerate(value):
                child = f"{path}[{index}]"
                out.extend(self._iter_strings(item, child))
            return out
        return []

    def _mask(self, raw: str, pattern_name: str) -> str:
        if pattern_name in _CRITICAL_PATTERNS:
            suffix = raw[-4:] if len(raw) >= 4 else raw
            return f"***{suffix}"
        if "@" in raw:
            local, _, domain = raw.partition("@")
            local_masked = (local[:2] + "***") if local else "***"
            return f"{local_masked}@{domain}"
        if len(raw) <= 4:
            return "***"
        return f"{raw[:2]}***{raw[-2:]}"


class PIIDetectorHandler:
    """Backward-compatible rule handler for plugin registry integration."""

    def evaluate(self, rule, request, **kwargs):  # noqa: ANN001, ANN003
        _ = kwargs
        detector = PiiDetector(
            ignore_patterns=rule.get("ignore_patterns")
            if isinstance(rule.get("ignore_patterns"), list)
            else None,
            severity_threshold=rule.get("severity_threshold", "medium"),
        )
        params = request.get("params")
        findings = detector.scan_tool_call(
            request.get("tool") if isinstance(request.get("tool"), str) else "__unknown__",
            params if isinstance(params, dict) else {},
        )
        reasons = [f"pii_detector: {item['pattern']} found in {item.get('path', 'params')}" for item in findings]
        return reasons, ["pii_detector"]


class PiiDetectorPlugin:
    """Orchesis policy plugin for blocking and redacting PII."""

    def __init__(self, config: dict[str, Any] | None = None):
        cfg = config or {}
        self.check_params = bool(cfg.get("check_params", True))
        self.check_responses = bool(cfg.get("check_responses", True))
        self.block_on_pii = bool(cfg.get("block_on_pii", True))
        self.redact_in_logs = bool(cfg.get("redact_in_logs", True))
        self.allowed_pii_tools = {
            item for item in cfg.get("allowed_pii_tools", []) if isinstance(item, str)
        }
        self.detector = PiiDetector(
            ignore_patterns=cfg.get("ignore_patterns")
            if isinstance(cfg.get("ignore_patterns"), list)
            else None,
            severity_threshold=cfg.get("severity_threshold", "medium"),
        )

    def evaluate(
        self,
        tool_name: str,
        params: dict[str, Any],
        agent_id: str,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        _ = (agent_id, context)
        findings = self.detector.scan_tool_call(tool_name, params) if self.check_params else []
        classification = self.detector.classify_data(json_dump_safe(params))
        if findings and self.block_on_pii and tool_name not in self.allowed_pii_tools:
            first = findings[0]
            reason = f"PII detected: {first['pattern']} in {first.get('path', 'params')}"
            return {
                "allowed": False,
                "reasons": [reason],
                "pii_findings": findings,
                "classification": classification,
            }
        return {
            "allowed": True,
            "reasons": [],
            "pii_findings": findings,
            "classification": classification,
        }

    def scan_response(self, tool_name: str, response: str) -> list[dict[str, Any]]:
        _ = tool_name
        if not self.check_responses:
            return []
        return self.detector.scan_text(response)

    def redact_for_audit(self, event: dict[str, Any]) -> dict[str, Any]:
        if not self.redact_in_logs:
            return deepcopy(event)
        redacted = deepcopy(event)
        return _redact_structure(redacted, self.detector)


def _redact_structure(value: Any, detector: PiiDetector) -> Any:
    if isinstance(value, str):
        return detector.redact_text(value)
    if isinstance(value, dict):
        return {key: _redact_structure(item, detector) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_structure(item, detector) for item in value]
    return value


def json_dump_safe(value: Any) -> str:
    try:
        import json

        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except Exception:
        return str(value)


PLUGIN_INFO = PluginInfo(
    name="pii_detector",
    rule_type="pii_detector",
    version="2.0",
    description="Detect and block tool calls containing sensitive PII",
    handler=PIIDetectorHandler(),
)
