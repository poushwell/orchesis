"""Cost of Freedom - quantify cost of NOT using Orchesis.

Marketing-facing calculator: "What does it cost to run agents without governance?"
Key metrics: wasted tokens, missed blocks, compliance risk, retry costs.
"""

from __future__ import annotations


class CostOfFreedomCalculator:
    BENCHMARKS = {
        "redundancy_rate": 0.2273,  # 22.73% average redundancy
        "retry_reduction": 3.52,  # 3.52x fewer retries
        "block_rate_unmanaged": 0.12,  # 12% attacks unblocked without Orchesis
        "block_rate_managed": 0.83,  # 83% with Orchesis
        "overhead_pct": 0.008,  # 0.8% proxy overhead
    }

    def __init__(self, config: dict | None = None):
        _ = config
        self.benchmarks = dict(self.BENCHMARKS)

    def calculate(self, inputs: dict) -> dict:
        daily_requests = int(inputs.get("daily_requests", 1000))
        avg_tokens = int(inputs.get("avg_tokens_per_request", 2000))
        cost_per_ktok = float(inputs.get("cost_per_ktok", 0.005))

        # Wasted tokens from redundancy
        daily_tokens = daily_requests * avg_tokens
        wasted_tokens = daily_tokens * self.benchmarks["redundancy_rate"]
        wasted_cost_daily = (wasted_tokens / 1000) * cost_per_ktok

        # Retry cost
        retry_multiplier = self.benchmarks["retry_reduction"]
        retry_savings_daily = wasted_cost_daily * (1 - 1 / retry_multiplier)

        # Security risk cost (unblocked attacks)
        unblocked = daily_requests * (
            self.benchmarks["block_rate_managed"] - self.benchmarks["block_rate_unblocked"]
            if "block_rate_unblocked" in self.benchmarks
            else self.benchmarks["block_rate_managed"] - self.benchmarks["block_rate_unmanaged"]
        )

        total_daily_savings = wasted_cost_daily + retry_savings_daily
        overhead_cost_daily = (daily_tokens / 1000) * cost_per_ktok * self.benchmarks["overhead_pct"]

        return {
            "daily_requests": daily_requests,
            "daily_tokens": daily_tokens,
            "wasted_tokens_daily": round(wasted_tokens),
            "wasted_cost_daily": round(wasted_cost_daily, 4),
            "retry_savings_daily": round(retry_savings_daily, 4),
            "total_daily_savings": round(total_daily_savings, 4),
            "total_monthly_savings": round(total_daily_savings * 30, 2),
            "attacks_missed_daily": round(unblocked),
            "overhead_cost_daily": round(overhead_cost_daily, 6),
            "roi": round(total_daily_savings / max(0.001, overhead_cost_daily), 1),
        }

    def get_summary_text(self, result: dict) -> str:
        return (
            f"Without Orchesis you waste ${result['wasted_cost_daily']:.2f}/day "
            f"({result['wasted_tokens_daily']:,} tokens). "
            f"ROI: {result['roi']}x."
        )
