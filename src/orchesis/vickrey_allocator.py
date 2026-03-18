"""Vickrey auction allocator for fleet context budget."""

from __future__ import annotations

from datetime import datetime, timezone
import threading
import uuid
from typing import Any


class VickreyBudgetAllocator:
    """Revealed preference auction for fleet context budget.

    Vickrey (second-price) auction — agents bid for context budget.
    Incentive-compatible: truthful bidding is dominant strategy.
    NLCE Layer 2 — fleet budget coordination.
    """

    _PRIORITY_WEIGHT = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        self.total_budget_tokens = int(cfg.get("total_budget", 100000))
        self._bids: dict[str, dict[str, Any]] = {}
        self._allocations: dict[str, int] = {}
        self._prices: dict[str, int] = {}
        self._auctions_run = 0
        self._utilization_history: list[float] = []
        self._lock = threading.Lock()

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def submit_bid(self, agent_id: str, bid_tokens: int, task_priority: str) -> dict:
        """Agent submits bid for context tokens."""
        aid = str(agent_id or "").strip()
        tokens = max(0, int(bid_tokens))
        priority = str(task_priority or "medium").strip().lower()
        if priority not in self._PRIORITY_WEIGHT:
            priority = "medium"
        bid = {
            "bid_id": f"bid-{uuid.uuid4().hex[:12]}",
            "agent_id": aid,
            "bid_tokens": tokens,
            "task_priority": priority,
            "submitted_at": self._now_iso(),
        }
        with self._lock:
            self._bids[aid] = bid
        return dict(bid)

    def run_auction(self) -> dict:
        """Run Vickrey auction. Returns allocations."""
        with self._lock:
            bids = list(self._bids.values())
            # highest bid first, then highest priority
            bids.sort(
                key=lambda row: (
                    int(row.get("bid_tokens", 0)),
                    self._PRIORITY_WEIGHT.get(str(row.get("task_priority", "medium")), 2),
                ),
                reverse=True,
            )
            remaining = int(self.total_budget_tokens)
            allocations: dict[str, int] = {}
            prices: dict[str, int] = {}
            for idx, row in enumerate(bids):
                agent_id = str(row.get("agent_id", ""))
                bid_tokens = max(0, int(row.get("bid_tokens", 0)))
                if remaining <= 0 or bid_tokens <= 0:
                    allocations[agent_id] = 0
                    prices[agent_id] = 0
                    continue
                allocated = min(remaining, bid_tokens)
                allocations[agent_id] = allocated
                next_bid = bids[idx + 1]["bid_tokens"] if idx + 1 < len(bids) else 0
                prices[agent_id] = min(allocated, max(0, int(next_bid)))
                remaining -= allocated

            self._allocations = allocations
            self._prices = prices
            self._auctions_run += 1
            utilization = (
                (self.total_budget_tokens - remaining) / float(self.total_budget_tokens)
                if self.total_budget_tokens > 0
                else 0.0
            )
            self._utilization_history.append(float(utilization))
            if len(self._utilization_history) > 1000:
                self._utilization_history = self._utilization_history[-1000:]
            return {
                "allocations": dict(allocations),
                "prices": dict(prices),
                "total_allocated": int(self.total_budget_tokens - remaining),
                "unallocated": int(remaining),
            }

    def get_allocation(self, agent_id: str) -> int:
        """Get current token allocation for agent."""
        with self._lock:
            return int(self._allocations.get(str(agent_id or ""), 0))

    def get_auction_stats(self) -> dict:
        with self._lock:
            avg_utilization = (
                sum(self._utilization_history) / len(self._utilization_history)
                if self._utilization_history
                else 0.0
            )
            return {
                "auctions_run": int(self._auctions_run),
                "total_budget": int(self.total_budget_tokens),
                "avg_utilization": round(float(avg_utilization), 6),
                "active_bidders": int(len(self._bids)),
            }

