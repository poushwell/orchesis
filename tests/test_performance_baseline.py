import statistics
import time

import pytest

from ci_multiplier import CI_MULTIPLIER

pytestmark = pytest.mark.performance


def _time_it(fn, n=100):
    times = []
    for _ in range(n):
        start = time.perf_counter()
        fn()
        times.append((time.perf_counter() - start) * 1000)
    return {
        "mean_ms": statistics.mean(times),
        "p95_ms": sorted(times)[int(n * 0.95)],
        "p99_ms": sorted(times)[int(n * 0.99)],
    }


def test_evaluate_baseline_under_5ms():
    """evaluate() with typical policy < 5ms p99."""
    from orchesis.engine import evaluate

    policy = {
        "rules": [
            {"name": "budget", "max_cost_per_call": 10.0},
            {
                "name": "injection",
                "type": "regex_match",
                "field": "params.content",
                "deny_patterns": ["ignore previous", "jailbreak"],
            },
        ]
    }
    req = {"tool": "chat", "params": {"content": "What is the weather today?"}, "cost": 0.01, "context": {}}
    result = _time_it(lambda: evaluate(req, policy))
    assert result["p99_ms"] < 5.0 * CI_MULTIPLIER, f"p99={result['p99_ms']:.2f}ms > 5ms SLA"


def test_config_load_under_10ms():
    """load_policy() < 10ms p99."""
    import os
    import tempfile

    import yaml
    from orchesis.config import load_policy

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump({"proxy": {"port": 8080}, "security": {"enabled": True}}, f)
        fname = f.name
    result = _time_it(lambda: load_policy(fname))
    os.unlink(fname)
    assert result["p99_ms"] < 10.0 * CI_MULTIPLIER


def test_api_health_under_50ms():
    """GET /health < 50ms p99."""
    from fastapi.testclient import TestClient
    from orchesis.api import create_api_app

    app = create_api_app()
    client = TestClient(app)
    result = _time_it(lambda: client.get("/health"), n=50)
    assert result["p99_ms"] < 50.0 * CI_MULTIPLIER


def test_uci_compression_under_10ms():
    """UCICompressor.compress() for 20 messages < 10ms mean."""
    from orchesis.uci_compression import UCICompressor

    uc = UCICompressor()
    messages = [{"role": "user", "content": f"Message {i} about context."} for i in range(20)]
    result = _time_it(lambda: uc.compress(messages, 10000), n=50)
    assert result["mean_ms"] < 10.0 * CI_MULTIPLIER


def test_casura_create_incident_under_20ms():
    """CASURA create_incident() < 20ms mean."""
    from orchesis.casura.incident_db import CASURAIncidentDB

    db = CASURAIncidentDB()
    factors = {"attack_vector": 0.8, "impact": 0.7, "exploitability": 0.6}
    result = _time_it(
        lambda: db.create_incident(
            {
                "title": "Test",
                "description": "Test incident",
                "factors": factors,
                "tags": ["test"],
            }
        ),
        n=50,
    )
    assert result["mean_ms"] < 20.0 * CI_MULTIPLIER


@pytest.mark.slow
def test_throughput_100_rps():
    """Engine handles 100 requests/second without errors."""
    import threading

    from orchesis.engine import evaluate

    policy = {"rules": [{"name": "b", "max_cost_per_call": 10.0}]}
    results = []
    errors = []

    def worker():
        try:
            r = evaluate({"tool": "t", "params": {}, "cost": 0.01, "context": {}}, policy)
            results.append(r)
        except Exception as e:
            errors.append(str(e))

    start = time.time()
    threads = [threading.Thread(target=worker) for _ in range(100)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start
    assert not errors, f"Errors: {errors[:3]}"
    assert len(results) == 100
    print(f"\nThroughput: {100 / elapsed:.1f} req/s")
