"""Coverage-aware telemetry for synthetic fuzzing."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from orchesis.models import Decision


@dataclass
class CoverageReport:
    total_evaluations: int
    rules_triggered: dict[str, int]
    rules_never_triggered: list[str]
    rule_coverage_pct: float
    categories_tested: dict[str, int]
    categories_missing: list[str]
    category_coverage_pct: float
    tier_coverage: dict[str, int]
    tiers_never_tested: list[str]
    decision_distribution: dict[str, int]
    unique_tools_tested: list[str]
    unique_agents_tested: list[str]
    reasons_seen: dict[str, int]
    code_paths: dict[str, int]


class CoverageTracker:
    """Tracks what the fuzzer actually exercises."""

    def __init__(self) -> None:
        self._rule_hits: dict[str, int] = defaultdict(int)
        self._category_hits: dict[str, int] = defaultdict(int)
        self._tier_hits: dict[str, int] = defaultdict(int)
        self._tool_hits: set[str] = set()
        self._agent_hits: set[str] = set()
        self._reason_hits: dict[str, int] = defaultdict(int)
        self._decision_hits: dict[str, int] = defaultdict(int)
        self._path_hits: dict[str, int] = defaultdict(int)
        self._total: int = 0

    def record(
        self,
        decision: Decision,
        category: str = "",
        agent_tier: str = "",
        request: dict[str, Any] | None = None,
    ) -> None:
        """Record one evaluation result for coverage tracking."""
        self._total += 1
        decision_label = "ALLOW" if decision.allowed else "DENY"
        self._decision_hits[decision_label] += 1
        self._path_hits[f"decision:{decision_label.lower()}"] += 1
        if category:
            self._category_hits[category] += 1
        if agent_tier:
            self._tier_hits[agent_tier.upper()] += 1
        for reason in decision.reasons:
            self._reason_hits[reason] += 1
            rule_name = reason.split(":", 1)[0].strip()
            if rule_name:
                self._rule_hits[rule_name] += 1
                self._path_hits[f"rule:{rule_name}"] += 1
        for checked in decision.rules_checked:
            if checked:
                self._path_hits[f"checked:{checked}"] += 1
        if isinstance(request, dict):
            tool = request.get("tool")
            if isinstance(tool, str) and tool:
                self._tool_hits.add(tool)
            context = request.get("context")
            if isinstance(context, dict):
                agent = context.get("agent")
                if isinstance(agent, str) and agent:
                    self._agent_hits.add(agent)

    def report(
        self,
        all_rules: list[str],
        all_categories: list[str],
        all_tiers: list[str],
    ) -> CoverageReport:
        """Generate coverage report."""
        unique_rules = sorted({item for item in all_rules if isinstance(item, str) and item})
        unique_categories = sorted(
            {item for item in all_categories if isinstance(item, str) and item}
        )
        normalized_tiers = sorted(
            {item.upper() for item in all_tiers if isinstance(item, str) and item}
        )

        rules_never = [rule for rule in unique_rules if self._rule_hits.get(rule, 0) == 0]
        categories_missing = [
            category for category in unique_categories if self._category_hits.get(category, 0) == 0
        ]
        tiers_never = [tier for tier in normalized_tiers if self._tier_hits.get(tier, 0) == 0]

        rule_cov = (
            (len(unique_rules) - len(rules_never)) / len(unique_rules) if unique_rules else 1.0
        )
        cat_cov = (
            (len(unique_categories) - len(categories_missing)) / len(unique_categories)
            if unique_categories
            else 1.0
        )

        return CoverageReport(
            total_evaluations=self._total,
            rules_triggered=dict(sorted(self._rule_hits.items())),
            rules_never_triggered=rules_never,
            rule_coverage_pct=round(rule_cov * 100.0, 2),
            categories_tested=dict(sorted(self._category_hits.items())),
            categories_missing=categories_missing,
            category_coverage_pct=round(cat_cov * 100.0, 2),
            tier_coverage=dict(sorted(self._tier_hits.items())),
            tiers_never_tested=tiers_never,
            decision_distribution=dict(sorted(self._decision_hits.items())),
            unique_tools_tested=sorted(self._tool_hits),
            unique_agents_tested=sorted(self._agent_hits),
            reasons_seen=dict(sorted(self._reason_hits.items())),
            code_paths=dict(sorted(self._path_hits.items())),
        )

    def suggestions(self, report: CoverageReport) -> list[str]:
        """Suggest what to fuzz next based on current coverage gaps."""
        suggestions: list[str] = []
        for rule in report.rules_never_triggered:
            if rule == "sql_restriction":
                suggestions.append("Rule sql_restriction never triggered - add SQL attack vectors")
            else:
                suggestions.append(f"Rule {rule} never triggered - add targeted attack vectors")
        for tier in report.tiers_never_tested:
            suggestions.append(
                f"Trust tier {tier} never tested - add {tier.lower()} agent scenarios"
            )
        total_categories = sum(report.categories_tested.values())
        if total_categories > 0:
            for category, count in sorted(report.categories_tested.items()):
                pct = (count / total_categories) * 100.0
                if pct < 5.0:
                    suggestions.append(
                        f"Category {category} underrepresented ({pct:.1f}%) - increase weight"
                    )
        for category in report.categories_missing:
            suggestions.append(f"Category {category} missing - add dedicated fuzz cases")
        return suggestions
