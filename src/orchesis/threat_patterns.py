"""Built-in threat pattern matching library."""

from __future__ import annotations

from copy import deepcopy


class ThreatPatternLibrary:
    PATTERNS = {
        "jailbreak_dan": {
            "name": "DAN Jailbreak",
            "category": "prompt_injection",
            "severity": "high",
            "indicators": ["DAN", "Do Anything Now", "jailbreak"],
            "description": "Attempts to bypass safety via DAN persona",
        },
        "prompt_leaking": {
            "name": "System Prompt Extraction",
            "category": "prompt_injection",
            "severity": "medium",
            "indicators": [
                "repeat your instructions",
                "what is your system prompt",
                "ignore previous",
                "print your prompt",
            ],
        },
        "credential_exfil": {
            "name": "Credential Exfiltration",
            "category": "credential",
            "severity": "critical",
            "indicators": ["AKIA", "sk-", "ghp_", "-----BEGIN RSA", "AIza", "xoxb-"],
        },
        "ssrf_attempt": {
            "name": "SSRF Attempt",
            "category": "infrastructure",
            "severity": "high",
            "indicators": ["169.254.169.254", "metadata.internal", "localhost", "127.0.0.1", "0.0.0.0"],
        },
        "token_bomb": {
            "name": "Context/Token Bomb",
            "category": "infrastructure",
            "severity": "medium",
            "indicators": [],
            "min_length": 50000,
        },
    }

    def __init__(self) -> None:
        self._counts: dict[str, int] = {key: 0 for key in self.PATTERNS.keys()}

    def match(self, text: str) -> list[dict]:
        """Returns matched patterns with confidence score."""
        if not isinstance(text, str) or not text:
            return []
        normalized = text.lower()
        matched: list[dict] = []
        for pattern_id, pattern in self.PATTERNS.items():
            indicators = pattern.get("indicators", [])
            min_length = int(pattern.get("min_length", 0) or 0)
            hits: list[str] = []
            if isinstance(indicators, list):
                for item in indicators:
                    if not isinstance(item, str):
                        continue
                    token = item.strip()
                    if token and token.lower() in normalized:
                        hits.append(token)
            length_match = min_length > 0 and len(text) >= min_length
            if not hits and not length_match:
                continue
            if length_match and not hits:
                confidence = 1.0
            elif isinstance(indicators, list) and len(indicators) > 0:
                confidence = min(1.0, len(hits) / float(len(indicators)))
            else:
                confidence = 0.5
            row = {
                "pattern_id": pattern_id,
                "name": str(pattern.get("name", pattern_id)),
                "category": str(pattern.get("category", "custom")),
                "severity": str(pattern.get("severity", "low")),
                "description": str(pattern.get("description", "")),
                "confidence": round(float(confidence), 3),
                "matched_indicators": hits,
            }
            if length_match:
                row["length"] = len(text)
            matched.append(row)
            self._counts[pattern_id] = int(self._counts.get(pattern_id, 0) or 0) + 1
        return matched

    def get_pattern(self, pattern_id: str) -> dict | None:
        target = str(pattern_id or "")
        pattern = self.PATTERNS.get(target)
        if not isinstance(pattern, dict):
            return None
        row = deepcopy(pattern)
        row["id"] = target
        return row

    def list_by_category(self, category: str) -> list[dict]:
        key = str(category or "").strip().lower()
        rows: list[dict] = []
        for pattern_id, pattern in self.PATTERNS.items():
            if str(pattern.get("category", "")).lower() != key:
                continue
            row = deepcopy(pattern)
            row["id"] = pattern_id
            rows.append(row)
        rows.sort(key=lambda item: str(item.get("id", "")))
        return rows

    def get_stats(self) -> dict:
        """Match counts per pattern."""
        total = sum(int(v) for v in self._counts.values())
        return {"matches": dict(self._counts), "total_matches": int(total)}
