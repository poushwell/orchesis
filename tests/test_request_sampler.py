from __future__ import annotations

from orchesis.request_sampler import RequestSampler


def test_full_rate_records_all() -> None:
    sampler = RequestSampler({"rate": 1.0, "strategy": "random", "always_record_blocks": False, "seed": 7})
    rows = [sampler.should_record({"decision": "ALLOW"}) for _ in range(100)]
    assert all(rows)


def test_zero_rate_records_none() -> None:
    sampler = RequestSampler({"rate": 0.0, "strategy": "random", "always_record_blocks": False, "seed": 7})
    rows = [sampler.should_record({"decision": "ALLOW"}) for _ in range(100)]
    assert not any(rows)


def test_always_record_blocks() -> None:
    sampler = RequestSampler({"rate": 0.0, "strategy": "random", "always_record_blocks": True, "seed": 7})
    assert sampler.should_record({"decision": "DENY"}) is True
    assert sampler.should_record({"decision": "ALLOW"}) is False


def test_reservoir_sampling_uniform() -> None:
    sampler = RequestSampler({"rate": 0.2, "strategy": "reservoir", "always_record_blocks": False, "seed": 11})
    for _ in range(1000):
        sampler.should_record({"decision": "ALLOW"})
    stats = sampler.get_stats()
    assert 0.15 <= float(stats["effective_rate"]) <= 0.25


def test_adaptive_rate_increases_on_anomaly() -> None:
    sampler = RequestSampler({"rate": 0.1, "strategy": "adaptive", "always_record_blocks": False})
    base = sampler.rate
    sampler.adjust_rate(0.95)
    assert sampler.rate > base


def test_stats_tracked() -> None:
    sampler = RequestSampler({"rate": 0.5, "strategy": "random", "always_record_blocks": False, "seed": 13})
    for _ in range(20):
        sampler.should_record({"decision": "ALLOW"})
    stats = sampler.get_stats()
    assert int(stats["sampled"]) + int(stats["skipped"]) == 20
    assert stats["strategy"] == "random"


def test_effective_rate_computed() -> None:
    sampler = RequestSampler({"rate": 0.3, "strategy": "random", "always_record_blocks": False, "seed": 3})
    for _ in range(200):
        sampler.should_record({"decision": "ALLOW"})
    stats = sampler.get_stats()
    total = int(stats["sampled"]) + int(stats["skipped"])
    expected = (int(stats["sampled"]) / total) if total else 0.0
    assert abs(float(stats["effective_rate"]) - expected) < 1e-6
