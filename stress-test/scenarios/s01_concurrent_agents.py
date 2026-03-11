from __future__ import annotations

from typing import Any

from lib.metrics_collector import MetricsCollector
from lib.scenario_utils import get_proxy_stats, start_stack, stop_stack
from lib.traffic_generator import TrafficGenerator


def _pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return float(s[int((len(s) - 1) * q)])


def run(*, quick: bool = False) -> dict[str, Any]:
    agents = 10 if quick else 50
    per_agent = 5 if quick else 20
    stack = start_stack(upstream_behavior="normal", strict=True)
    collector = MetricsCollector(interval_seconds=1.0)
    collector.start()
    try:
        tg = TrafficGenerator(stack["proxy_url"], num_threads=agents)
        out = tg.run_concurrent(num_agents=agents, requests_per_agent=per_agent)
        stats = get_proxy_stats(stack["proxy_url"])
        metrics = collector.stop()
    finally:
        stop_stack(stack)

    lats = [float(i.get("latency_ms", 0.0)) for i in out]
    ok_like = sum(1 for i in out if int(i.get("status", 0)) in (200, 403, 429))
    errors = sum(1 for i in out if int(i.get("status", 0)) >= 500 or int(i.get("status", 0)) == 599)
    total = len(out)
    distinct_agents = len({str(i.get("agent_id", "")) for i in out if str(i.get("agent_id", ""))})
    p95 = _pct(lats, 0.95)
    avg = (sum(lats) / len(lats)) if lats else 0.0
    passed = (
        total == (agents * per_agent)
        and errors == 0
        and ok_like == total
        and avg < 250.0
        and distinct_agents >= max(5, agents // 2)
    )
    return {
        "id": "s01",
        "name": "50 Concurrent Agents",
        "passed": passed,
        "key_metric": f"avg latency {avg:.2f}ms, p95 {p95:.2f}ms",
        "latencies_ms": lats[:1000],
        "details": {
            "total_requests": total,
            "errors": errors,
            "expected_total": agents * per_agent,
            "distinct_agents_seen": distinct_agents,
            "proxy_stats_keys": ",".join(sorted(stats.keys())[:8]),
            "rss_growth_mb": metrics["rss_mb"]["growth"],
        },
    }


if __name__ == "__main__":
    print(run(quick=True))
