from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from lib.scenario_utils import get_proxy_stats, start_stack, stop_stack
from lib.traffic_generator import TrafficGenerator


def run(*, quick: bool = False) -> dict[str, Any]:
    concurrent = 30 if quick else 100
    stack = start_stack(
        upstream_behavior="normal",
        strict=True,
        low_budget=True,
        enable_spend_rate=True,
    )
    try:
        tg = TrafficGenerator(stack["proxy_url"], num_threads=concurrent)
        with ThreadPoolExecutor(max_workers=concurrent) as pool:
            out = list(pool.map(lambda _: tg.send_normal_chat(agent_id="budget-race"), range(concurrent)))
        stats = get_proxy_stats(stack["proxy_url"])
    finally:
        stop_stack(stack)

    allowed = sum(1 for i in out if int(i.get("status", 0)) == 200)
    blocked = sum(1 for i in out if int(i.get("status", 0)) == 429)
    spend = float(stats.get("cost_today", 0.0))
    passed = spend <= 0.11 and blocked > 0
    return {
        "id": "s07",
        "name": "Budget Race",
        "passed": passed,
        "key_metric": f"spend=${spend:.4f}, blocked={blocked}",
        "details": {
            "concurrent_requests": concurrent,
            "allowed_200": allowed,
            "blocked_429": blocked,
            "proxy_cost_today": round(spend, 6),
            "budget_limit": 0.10,
        },
    }


if __name__ == "__main__":
    print(run(quick=True))
