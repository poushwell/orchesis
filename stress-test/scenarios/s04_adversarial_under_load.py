from __future__ import annotations

from typing import Any

from lib.metrics_collector import MetricsCollector
from lib.scenario_utils import start_stack, stop_stack
from lib.traffic_generator import ATTACKS, TrafficGenerator


def run(*, quick: bool = False) -> dict[str, Any]:
    duration = 12 if quick else 120
    rps = 8 if quick else 50
    stack = start_stack(upstream_behavior="normal", strict=True)
    collector = MetricsCollector(interval_seconds=1.0)
    collector.start()
    try:
        tg = TrafficGenerator(stack["proxy_url"], num_threads=64 if not quick else 24)
        out = tg.run_sustained(
            rps=rps,
            duration_seconds=duration,
            mix={"normal": 0.7, "attack": 0.2, "heartbeat": 0.1},
        )
        metrics = collector.stop()
    finally:
        stop_stack(stack)

    attacks = [i for i in out if i.get("request_type") == "attack"]
    normals = [i for i in out if i.get("request_type") == "normal"]
    blocked_or_warned = 0
    for item in attacks:
        status = int(item.get("status", 0))
        hdr = item.get("headers", {})
        if status in (403, 429) or ("X-Orchesis-Threat-Detected" in hdr):
            blocked_or_warned += 1
    false_positives = sum(1 for i in normals if int(i.get("status", 0)) >= 400)
    attack_coverage = (blocked_or_warned / len(attacks)) if attacks else 0.0
    passed = attack_coverage >= 0.40 and false_positives == 0
    return {
        "id": "s04",
        "name": "Adversarial Under Load",
        "passed": passed,
        "key_metric": f"attack handling {attack_coverage*100:.1f}% / false positives {false_positives}",
        "details": {
            "total_requests": len(out),
            "attack_requests": len(attacks),
            "normal_requests": len(normals),
            "attack_patterns": ",".join(sorted(ATTACKS.keys())),
            "blocked_or_warned": blocked_or_warned,
            "false_positives": false_positives,
            "rss_growth_mb": metrics["rss_mb"]["growth"],
        },
    }


if __name__ == "__main__":
    print(run(quick=True))
