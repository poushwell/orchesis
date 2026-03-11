from __future__ import annotations

import time
from typing import Any

from lib.metrics_collector import MetricsCollector
from lib.scenario_utils import start_stack, stop_stack
from lib.traffic_generator import TrafficGenerator


def _pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return float(s[int((len(s) - 1) * q)])


def run(*, quick: bool = False) -> dict[str, Any]:
    duration = 60 if quick else 600
    target_rps = 4 if quick else 17
    stack = start_stack(upstream_behavior="normal", strict=True)
    collector = MetricsCollector(interval_seconds=1.0)
    collector.start()
    started = time.monotonic()
    try:
        tg = TrafficGenerator(stack["proxy_url"], num_threads=32 if quick else 64)
        out = tg.run_sustained(rps=target_rps, duration_seconds=duration, mix={"normal": 1.0})
        metrics = collector.stop()
    finally:
        stop_stack(stack)

    elapsed = max(0.001, time.monotonic() - started)
    lats = [float(i.get("latency_ms", 0.0)) for i in out]
    p50 = _pct(lats, 0.50)
    p95 = _pct(lats, 0.95)
    p99 = _pct(lats, 0.99)
    errors = sum(1 for i in out if int(i.get("status", 0)) >= 500 or int(i.get("status", 0)) == 599)
    reqs = len(out)
    throughput = reqs / elapsed
    passed = (
        errors == 0
        and p95 < (250.0 if quick else 120.0)
        and p99 < (400.0 if quick else 250.0)
        and reqs >= int(duration * target_rps * 0.9)
    )
    return {
        "id": "s02",
        "name": "1000 req/min 10min",
        "passed": passed,
        "key_metric": f"p95 {p95:.2f}ms, p99 {p99:.2f}ms, err {errors}",
        "latencies_ms": lats[:2000],
        "details": {
            "requests": reqs,
            "duration_seconds": round(elapsed, 3),
            "throughput_rps": round(throughput, 3),
            "p50_ms": round(p50, 3),
            "p95_ms": round(p95, 3),
            "p99_ms": round(p99, 3),
            "errors": errors,
            "rss_growth_mb": metrics["rss_mb"]["growth"],
        },
    }


if __name__ == "__main__":
    print(run(quick=True))
