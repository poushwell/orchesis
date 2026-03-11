from __future__ import annotations

from typing import Any

from lib.metrics_collector import MetricsCollector
from lib.scenario_utils import start_stack, stop_stack
from lib.traffic_generator import TrafficGenerator


def _status_split(items: list[dict[str, Any]]) -> dict[str, int]:
    out = {"ok": 0, "proxy_5xx": 0, "other": 0}
    for item in items:
        status = int(item.get("status", 0))
        if 200 <= status < 300:
            out["ok"] += 1
        elif 500 <= status < 600:
            out["proxy_5xx"] += 1
        else:
            out["other"] += 1
    return out


def run(*, quick: bool = False) -> dict[str, Any]:
    phase = 6 if quick else 60
    stack = start_stack(upstream_behavior="normal", strict=True)
    collector = MetricsCollector(interval_seconds=1.0)
    collector.start()
    try:
        tg = TrafficGenerator(stack["proxy_url"], num_threads=24 if quick else 64)
        upstream = stack["upstream"]

        upstream.set_behavior("normal")
        p1 = tg.run_sustained(rps=5 if quick else 20, duration_seconds=phase, mix={"normal": 1.0})

        upstream.set_behavior("errors")
        p2 = tg.run_sustained(rps=5 if quick else 20, duration_seconds=phase, mix={"normal": 1.0})

        upstream.set_behavior("normal")
        p3 = tg.run_sustained(rps=5 if quick else 20, duration_seconds=phase, mix={"normal": 1.0})

        upstream.set_behavior("normal")
        p4 = tg.run_sustained(rps=5 if quick else 20, duration_seconds=phase, mix={"normal": 1.0})
        metrics = collector.stop()
    finally:
        stop_stack(stack)

    s1, s2, s3, s4 = _status_split(p1), _status_split(p2), _status_split(p3), _status_split(p4)
    recovery_total = len(p3) + len(p4)
    recovery_ok = s3["ok"] + s4["ok"]
    recovery_rate = (recovery_ok / recovery_total) if recovery_total else 0.0
    passed = recovery_rate >= 0.90
    return {
        "id": "s05",
        "name": "Cascade Failure",
        "passed": passed,
        "key_metric": (
            f"phase2 5xx={s2['proxy_5xx']}/{len(p2)}; "
            f"recovery_rate={recovery_rate*100:.1f}% ({recovery_ok}/{recovery_total})"
        ),
        "details": {
            "phase1": s1,
            "phase2": s2,
            "phase3": s3,
            "phase4": s4,
            "recovery_ok": recovery_ok,
            "recovery_total": recovery_total,
            "recovery_rate": round(recovery_rate, 4),
            "rss_growth_mb": metrics["rss_mb"]["growth"],
        },
    }


if __name__ == "__main__":
    print(run(quick=True))
