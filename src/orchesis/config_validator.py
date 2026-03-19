"""Comprehensive policy configuration validator."""

from __future__ import annotations

from typing import Any


class ConfigValidator:
    """Validates orchesis.yaml for all subsystem requirements."""

    REQUIRED_SECTIONS = ["proxy"]

    RECOMMENDED_SECTIONS = [
        "security",
        "semantic_cache",
        "recording",
        "loop_detection",
        "budgets",
        "threat_intel",
    ]

    NEW_MODULE_SECTIONS = [
        "uci_compression",
        "context_budget",
        "apoptosis",
        "injection_protocol",
        "thompson_sampling",
        "hgt_protocol",
        "quorum_sensing",
    ]

    def validate(self, policy: dict[str, Any]) -> dict[str, Any]:
        errors: list[str] = []
        warnings: list[str] = []
        info: list[str] = []

        for section in self.REQUIRED_SECTIONS:
            if section not in policy:
                errors.append(f"Missing required section: {section}")

        for section in self.RECOMMENDED_SECTIONS:
            if section not in policy:
                warnings.append(f"Missing recommended section: {section}")

        for section in self.NEW_MODULE_SECTIONS:
            if section not in policy:
                info.append(f"Optional new module not configured: {section}")

        proxy = policy.get("proxy", {})
        if isinstance(proxy, dict) and "port" in proxy and not isinstance(proxy["port"], int):
            errors.append("proxy.port must be integer")

        budgets = policy.get("budgets", {})
        if isinstance(budgets, dict) and "daily" in budgets and not isinstance(
            budgets["daily"], (int, float)
        ):
            errors.append("budgets.daily must be numeric")

        score = max(0.0, 1.0 - len(errors) * 0.3 - len(warnings) * 0.05)

        return {
            "valid": len(errors) == 0,
            "score": round(score, 2),
            "errors": errors,
            "warnings": warnings,
            "info": info,
            "grade": "A" if score > 0.9 else "B" if score > 0.7 else "C",
        }

    def suggest_additions(self, policy: dict[str, Any]) -> list[str]:
        suggestions: list[str] = []
        if "semantic_cache" not in policy:
            suggestions.append("Add semantic_cache: {enabled: true} for 20-40% token savings")
        if "uci_compression" not in policy:
            suggestions.append("Add uci_compression: {enabled: true} for NLCE Layer 2")
        if "context_budget" not in policy:
            suggestions.append("Add context_budget: {enabled: true, l0_threshold: 0.8}")
        return suggestions
