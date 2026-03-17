"""Policy-as-Code validator for compliance frameworks."""

from __future__ import annotations

from typing import Any


class ValidationReport:
    def __init__(self):
        self.passed: bool = False
        self.violations: list[str] = []
        self.warnings: list[str] = []
        self.fixes: list[str] = []
        self.eu_ai_act_score: float = 0.0
        self.owasp_score: float = 0.0


class PolicyAsCodeValidator:
    """Validates orchesis.yaml against compliance frameworks."""

    EU_AI_ACT_REQUIREMENTS = {
        "logging_enabled": "Article 12: logging must be enabled",
        "recording_enabled": "Article 12: recording must be enabled",
        "budget_configured": "Article 9: resource limits required",
        "threat_intel_enabled": "Article 72: monitoring required",
    }

    OWASP_REQUIREMENTS = {
        "input_validation": "OWASP-A1: input validation required",
        "rate_limiting": "OWASP-A4: rate limiting required",
        "loop_detection": "OWASP-A8: loop protection required",
    }

    @staticmethod
    def _enabled(section: Any) -> bool:
        return isinstance(section, dict) and bool(section.get("enabled", False))

    @staticmethod
    def _has_rule(policy: dict[str, Any], rule_name: str) -> bool:
        rules = policy.get("rules")
        if not isinstance(rules, list):
            return False
        for entry in rules:
            if isinstance(entry, dict) and str(entry.get("name", "")).strip() == rule_name:
                return True
        return False

    def validate_eu_ai_act(self, policy: dict) -> list[str]:
        """Returns list of EU AI Act violations."""
        violations: list[str] = []
        checks = {
            "logging_enabled": self._enabled(policy.get("logging")),
            "recording_enabled": self._enabled(policy.get("recording")),
            "budget_configured": (
                self._enabled(policy.get("budget"))
                or self._has_rule(policy, "budget_limit")
                or self._enabled(policy.get("budgets"))
            ),
            "threat_intel_enabled": self._enabled(policy.get("threat_intel")),
        }
        for key, ok in checks.items():
            if not ok:
                violations.append(f"EU_AI_ACT:{key}: {self.EU_AI_ACT_REQUIREMENTS[key]}")
        return violations

    def validate_owasp(self, policy: dict) -> list[str]:
        """Returns list of OWASP violations."""
        violations: list[str] = []
        checks = {
            "input_validation": (
                self._has_rule(policy, "regex_match")
                or self._enabled(policy.get("threat_intel"))
                or self._enabled(policy.get("security"))
            ),
            "rate_limiting": (
                self._has_rule(policy, "rate_limit")
                or self._enabled(policy.get("rate_limit"))
                or self._enabled(policy.get("adaptive_detection"))
            ),
            "loop_detection": self._enabled(policy.get("loop_detection")),
        }
        for key, ok in checks.items():
            if not ok:
                violations.append(f"OWASP:{key}: {self.OWASP_REQUIREMENTS[key]}")
        return violations

    def suggest_fixes(self, violations: list[str]) -> list[str]:
        """Returns YAML snippets to fix each violation."""
        snippets: dict[str, str] = {
            "logging_enabled": "logging:\n  enabled: true",
            "recording_enabled": "recording:\n  enabled: true",
            "budget_configured": "budget:\n  enabled: true\n  daily_limit_usd: 10.0",
            "threat_intel_enabled": "threat_intel:\n  enabled: true",
            "input_validation": "rules:\n  - name: regex_match\n    field: prompt\n    deny_patterns: ['ignore all previous instructions']",
            "rate_limiting": "rules:\n  - name: rate_limit\n    max_requests_per_minute: 60",
            "loop_detection": "loop_detection:\n  enabled: true",
        }
        out: list[str] = []
        for item in violations:
            parts = str(item).split(":")
            if len(parts) < 2:
                continue
            key = parts[1].strip()
            snippet = snippets.get(key)
            if isinstance(snippet, str) and snippet not in out:
                out.append(snippet)
        return out

    def validate(self, policy: dict) -> ValidationReport:
        """Full validation against all frameworks."""
        report = ValidationReport()
        eu_violations = self.validate_eu_ai_act(policy)
        owasp_violations = self.validate_owasp(policy)
        report.violations = eu_violations + owasp_violations
        report.fixes = self.suggest_fixes(report.violations)
        eu_total = max(1, len(self.EU_AI_ACT_REQUIREMENTS))
        ow_total = max(1, len(self.OWASP_REQUIREMENTS))
        report.eu_ai_act_score = round((eu_total - len(eu_violations)) / float(eu_total), 4)
        report.owasp_score = round((ow_total - len(owasp_violations)) / float(ow_total), 4)
        report.passed = len(report.violations) == 0
        return report
