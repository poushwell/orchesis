from __future__ import annotations

from orchesis.shannon_hartley import ShannonHartleyCalculator


def test_entropy_computed() -> None:
    calc = ShannonHartleyCalculator()
    entropy = calc.compute_entropy([0.5, 0.5])
    assert round(entropy, 4) == 1.0


def test_channel_capacity_formula() -> None:
    calc = ShannonHartleyCalculator()
    out = calc.compute_channel_capacity(context_entropy=2.0, response_entropy=10.0, noise=0.1)
    assert out["capacity"] > 0.0


def test_snr_positive() -> None:
    calc = ShannonHartleyCalculator()
    out = calc.compute_channel_capacity(context_entropy=1.5, response_entropy=1.0, noise=0.1)
    assert out["snr"] > 0.0


def test_c_eff_bounded_by_response() -> None:
    calc = ShannonHartleyCalculator()
    out = calc.compute_channel_capacity(context_entropy=5.0, response_entropy=1.0, noise=0.1)
    assert out["c_eff"] <= 1.0


def test_utilization_0_to_1() -> None:
    calc = ShannonHartleyCalculator()
    out = calc.compute_channel_capacity(context_entropy=2.5, response_entropy=2.0, noise=0.1)
    assert 0.0 <= out["utilization"] <= 1.0


def test_conditional_mutual_info() -> None:
    calc = ShannonHartleyCalculator()
    info = calc.compute_conditional_mutual_info([1, 2, 3, 4], [3, 4, 5, 6])
    assert info > 0.0


def test_record_measurement() -> None:
    calc = ShannonHartleyCalculator()
    cap = calc.compute_channel_capacity(context_entropy=2.0, response_entropy=1.4, noise=0.1)
    calc.record_measurement("s-1", cap)
    stats = calc.get_stats()
    assert stats["measurements"] == 1


def test_stats_returned() -> None:
    calc = ShannonHartleyCalculator()
    cap1 = calc.compute_channel_capacity(context_entropy=2.0, response_entropy=1.3, noise=0.1)
    cap2 = calc.compute_channel_capacity(context_entropy=1.8, response_entropy=1.1, noise=0.2)
    calc.record_measurement("s-1", cap1)
    calc.record_measurement("s-2", cap2)
    stats = calc.get_stats()
    assert stats["measurements"] == 2
    assert "avg_utilization" in stats
    assert "avg_capacity" in stats
