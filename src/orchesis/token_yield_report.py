"""Token Yield report generator."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any


class TokenYieldReportGenerator:
    """Generates detailed Token Yield reports for sharing."""

    @staticmethod
    def _to_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _to_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def generate(self, session_data: list[dict], period: str = "24h") -> dict:
        rows = [item for item in session_data if isinstance(item, dict)]
        total_tokens = 0
        semantic_tokens = 0
        total_saved = 0
        cache_hits = 0
        collapses = 0
        total_cost = 0.0
        by_model: dict[str, dict[str, Any]] = {}
        by_agent: dict[str, dict[str, Any]] = {}

        for row in rows:
            prompt = max(0, self._to_int(row.get("prompt_tokens", 0)))
            completion = max(0, self._to_int(row.get("completion_tokens", 0)))
            tokens = prompt + completion
            ratio = max(0.0, min(1.0, self._to_float(row.get("unique_content_ratio", 1.0), 1.0)))
            semantic = int(round(tokens * ratio))
            waste_saved = max(0, tokens - semantic)
            cache_hit = bool(row.get("cache_hit", False))
            cache_saved = tokens if cache_hit else 0
            saved = waste_saved + cache_saved
            if cache_hit:
                cache_hits += 1
            if bool(row.get("context_collapse", False)):
                collapses += 1
            total_tokens += tokens
            semantic_tokens += semantic
            total_saved += saved
            total_cost += self._to_float(row.get("cost", 0.0), 0.0)

            model = str(row.get("model", "unknown") or "unknown")
            model_bucket = by_model.setdefault(
                model,
                {"requests": 0, "tokens": 0, "saved": 0, "cost": 0.0, "yield": 0.0, "_semantic": 0},
            )
            model_bucket["requests"] += 1
            model_bucket["tokens"] += tokens
            model_bucket["saved"] += saved
            model_bucket["cost"] += self._to_float(row.get("cost", 0.0), 0.0)
            model_bucket["_semantic"] += semantic

            agent = str(row.get("agent_id", "unknown") or "unknown")
            agent_bucket = by_agent.setdefault(
                agent,
                {"requests": 0, "tokens": 0, "saved": 0, "cost": 0.0, "yield": 0.0, "_semantic": 0},
            )
            agent_bucket["requests"] += 1
            agent_bucket["tokens"] += tokens
            agent_bucket["saved"] += saved
            agent_bucket["cost"] += self._to_float(row.get("cost", 0.0), 0.0)
            agent_bucket["_semantic"] += semantic

        avg_yield = (semantic_tokens / float(total_tokens)) if total_tokens > 0 else 0.0
        cache_hit_rate = (cache_hits / float(len(rows))) if rows else 0.0
        est_savings_usd = (total_saved / 1000.0) * 0.002

        for bucket in by_model.values():
            tokens = int(bucket.get("tokens", 0))
            semantic = int(bucket.pop("_semantic", 0))
            bucket["yield"] = round((semantic / float(tokens)) if tokens > 0 else 0.0, 6)
            bucket["cost"] = round(float(bucket.get("cost", 0.0)), 8)
        for bucket in by_agent.values():
            tokens = int(bucket.get("tokens", 0))
            semantic = int(bucket.pop("_semantic", 0))
            bucket["yield"] = round((semantic / float(tokens)) if tokens > 0 else 0.0, 6)
            bucket["cost"] = round(float(bucket.get("cost", 0.0)), 8)

        recommendations: list[str] = []
        if avg_yield < 0.6:
            recommendations.append("Enable stronger context pruning to remove stale prompt history.")
        if cache_hit_rate < 0.2:
            recommendations.append("Increase semantic cache coverage to reduce repeat token spend.")
        if collapses > 0:
            recommendations.append("Investigate sessions with context collapse and enforce tighter context budgets.")
        if not recommendations:
            recommendations.append("Token Yield is healthy; continue monitoring for drift and periodic regressions.")

        executive_summary = (
            f"Token Yield averaged {avg_yield * 100:.1f}% over the {period} window across {len(rows)} requests. "
            f"The system used {total_tokens} tokens and saved an estimated {total_saved} tokens through deduplication and cache effects. "
            f"Observed context collapses: {collapses}; estimated savings: ${est_savings_usd:.2f}."
        )

        return {
            "report_id": f"tyr-{uuid.uuid4().hex[:12]}",
            "period": str(period),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "executive_summary": executive_summary,
            "metrics": {
                "avg_token_yield": round(avg_yield, 6),
                "total_tokens_used": int(total_tokens),
                "total_tokens_saved": int(total_saved),
                "context_collapses": int(collapses),
                "cache_hit_rate": round(cache_hit_rate, 6),
                "estimated_savings_usd": round(est_savings_usd, 6),
            },
            "by_model": by_model,
            "by_agent": by_agent,
            "recommendations": recommendations,
            "methodology": (
                "Token Yield = semantic_tokens / total_tokens. "
                "semantic_tokens are approximated as total_tokens * unique_content_ratio. "
                "Token savings include non-semantic token waste plus full prompt+completion savings on cache hits."
            ),
        }

    def export_text(self, report: dict) -> str:
        """Formatted text report."""
        metrics = report.get("metrics", {}) if isinstance(report, dict) else {}
        lines = [
            "TOKEN YIELD REPORT",
            "==================",
            f"Report ID: {report.get('report_id', '-')}",
            f"Period: {report.get('period', '-')}",
            f"Generated at: {report.get('generated_at', '-')}",
            "",
            "Executive Summary:",
            str(report.get("executive_summary", "")),
            "",
            "Metrics:",
            f"  Avg Token Yield: {float(metrics.get('avg_token_yield', 0.0)) * 100:.2f}%",
            f"  Total Tokens Used: {int(metrics.get('total_tokens_used', 0))}",
            f"  Total Tokens Saved: {int(metrics.get('total_tokens_saved', 0))}",
            f"  Context Collapses: {int(metrics.get('context_collapses', 0))}",
            f"  Cache Hit Rate: {float(metrics.get('cache_hit_rate', 0.0)) * 100:.2f}%",
            f"  Estimated Savings USD: ${float(metrics.get('estimated_savings_usd', 0.0)):.2f}",
            "",
            "Recommendations:",
        ]
        for rec in report.get("recommendations", []):
            lines.append(f"  - {rec}")
        lines.extend(["", "Methodology:", str(report.get("methodology", ""))])
        return "\n".join(lines)

    def export_markdown(self, report: dict) -> str:
        """Markdown report for sharing."""
        metrics = report.get("metrics", {}) if isinstance(report, dict) else {}
        lines = [
            "# Token Yield Report",
            "",
            f"- **Report ID:** `{report.get('report_id', '-')}`",
            f"- **Period:** `{report.get('period', '-')}`",
            f"- **Generated At:** `{report.get('generated_at', '-')}`",
            "",
            "## Executive Summary",
            str(report.get("executive_summary", "")),
            "",
            "## Metrics",
            f"- **Avg Token Yield:** {float(metrics.get('avg_token_yield', 0.0)) * 100:.2f}%",
            f"- **Total Tokens Used:** {int(metrics.get('total_tokens_used', 0))}",
            f"- **Total Tokens Saved:** {int(metrics.get('total_tokens_saved', 0))}",
            f"- **Context Collapses:** {int(metrics.get('context_collapses', 0))}",
            f"- **Cache Hit Rate:** {float(metrics.get('cache_hit_rate', 0.0)) * 100:.2f}%",
            f"- **Estimated Savings USD:** ${float(metrics.get('estimated_savings_usd', 0.0)):.2f}",
            "",
            "## Recommendations",
        ]
        for rec in report.get("recommendations", []):
            lines.append(f"- {rec}")
        lines.extend(["", "## Methodology", str(report.get("methodology", ""))])
        return "\n".join(lines)

    def get_benchmark_comparison(self, report: dict) -> dict:
        """Compare to NLCE baseline results."""
        baseline_yield = 0.65
        baseline_cache_rate = 0.20
        metrics = report.get("metrics", {}) if isinstance(report, dict) else {}
        current_yield = float(metrics.get("avg_token_yield", 0.0))
        current_cache = float(metrics.get("cache_hit_rate", 0.0))
        return {
            "baseline": {"avg_token_yield": baseline_yield, "cache_hit_rate": baseline_cache_rate},
            "current": {"avg_token_yield": current_yield, "cache_hit_rate": current_cache},
            "delta": {
                "avg_token_yield": round(current_yield - baseline_yield, 6),
                "cache_hit_rate": round(current_cache - baseline_cache_rate, 6),
            },
            "status": "above_baseline" if current_yield >= baseline_yield else "below_baseline",
        }

