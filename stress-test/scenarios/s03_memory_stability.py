from __future__ import annotations

from typing import Any

from lib.metrics_collector import MetricsCollector
from lib.scenario_utils import get_proxy_stats, start_stack, stop_stack
from lib.traffic_generator import TrafficGenerator


def run(*, quick: bool = False) -> dict[str, Any]:
    duration = 180 if quick else 1800
    rps = 2 if quick else 5
    stack = start_stack(upstream_behavior="normal", strict=True)
    collector = MetricsCollector(interval_seconds=5.0 if not quick else 1.0)
    collector.start()
    try:
        tg = TrafficGenerator(stack["proxy_url"], num_threads=16)
        out = tg.run_sustained(rps=rps, duration_seconds=duration, mix={"normal": 0.95, "heartbeat": 0.05})
        proxy_stats = get_proxy_stats(stack["proxy_url"])
        metrics = collector.stop()
    finally:
        stop_stack(stack)

    rss = metrics["rss_mb"]
    growth = float(rss["growth"])
    start = max(0.001, float(rss["start"]))
    end = float(rss["end"])
    stable_ratio = end / start
    entries = proxy_stats.get("cache_entries", proxy_stats.get("semantic_cache_entries", "n/a"))
    passed = growth < (30.0 if quick else 50.0) and stable_ratio < 2.0
    return {
        "id": "s03",
        "name": "Memory 30min",
        "passed": passed,
        "key_metric": f"rss growth {growth:.2f}MB",
        "details": {
            "requests": len(out),
            "rss_start_mb": rss["start"],
            "rss_end_mb": rss["end"],
            "rss_peak_mb": rss["peak"],
            "rss_growth_mb": growth,
            "final_to_initial_ratio": round(stable_ratio, 3),
            "semantic_cache_entries": entries,
        },
    }


if __name__ == "__main__":
    print(run(quick=True))
