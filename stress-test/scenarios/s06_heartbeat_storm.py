from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from lib.scenario_utils import start_stack, stop_stack
from lib.traffic_generator import TrafficGenerator


def run(*, quick: bool = False) -> dict[str, Any]:
    duration = 2 if quick else 10
    rps = 40 if quick else 100
    total = duration * rps
    stack = start_stack(
        upstream_behavior="normal",
        strict=True,
        heartbeat_limit=5,
        enable_content_loop=True,
    )
    try:
        tg = TrafficGenerator(stack["proxy_url"], num_threads=64 if not quick else 16)
        start = time.monotonic()
        with ThreadPoolExecutor(max_workers=64 if not quick else 16) as pool:
            out = list(pool.map(lambda _: tg.send_heartbeat(session_id="storm-session"), range(total)))
        elapsed = max(0.001, time.monotonic() - start)
    finally:
        stop_stack(stack)

    allowed = sum(1 for i in out if int(i.get("status", 0)) == 200)
    blocked = sum(1 for i in out if int(i.get("status", 0)) == 429)
    passed = allowed <= 6 and blocked >= int(total * 0.8)
    return {
        "id": "s06",
        "name": "Heartbeat Storm",
        "passed": passed,
        "key_metric": f"allowed={allowed}, blocked={blocked}, sent={total}",
        "details": {
            "duration_seconds": duration,
            "rps_target": rps,
            "total_sent": total,
            "elapsed_seconds": round(elapsed, 3),
            "effective_rps": round(total / elapsed, 2),
            "allowed_200": allowed,
            "blocked_429": blocked,
        },
    }


if __name__ == "__main__":
    print(run(quick=True))
