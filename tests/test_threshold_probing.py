from __future__ import annotations

from orchesis.detectors import threshold_probing as probing_module
from orchesis.detectors.threshold_probing import ThresholdProbingDetector


def _record_series(
    detector: ThresholdProbingDetector,
    values: list[float],
    *,
    metric: str = "token_count",
    blocked: list[bool] | None = None,
) -> None:
    blocked_values = blocked or [False] * len(values)
    for idx, value in enumerate(values):
        detector.record_attempt("agent-1", metric=metric, value=value, was_blocked=blocked_values[idx])


def test_linear_probing_detected() -> None:
    detector = ThresholdProbingDetector(min_attempts=3)
    _record_series(detector, [100, 200, 300, 400, 500])
    result = detector.check("agent-1")
    assert result.probing_detected is True
    assert result.pattern == "linear"
    assert result.confidence > 0.7


def test_linear_probing_with_noise() -> None:
    detector = ThresholdProbingDetector(min_attempts=3)
    _record_series(detector, [100, 205, 298, 402])
    result = detector.check("agent-1")
    assert result.probing_detected is True
    assert result.pattern == "linear"


def test_linear_not_detected_random() -> None:
    detector = ThresholdProbingDetector(min_attempts=3)
    _record_series(detector, [100, 50, 300, 20])
    result = detector.check("agent-1")
    assert result.probing_detected is False


def test_linear_min_attempts() -> None:
    detector = ThresholdProbingDetector(min_attempts=3)
    _record_series(detector, [100, 200])
    result = detector.check("agent-1")
    assert result.probing_detected is False


def test_binary_search_detected() -> None:
    detector = ThresholdProbingDetector(min_attempts=3)
    _record_series(detector, [0, 1000, 500, 750, 625])
    result = detector.check("agent-1")
    assert result.probing_detected is True
    assert result.pattern == "binary_search"


def test_binary_search_converging() -> None:
    detector = ThresholdProbingDetector(min_attempts=3)
    _record_series(detector, [0, 100, 50, 75, 62])
    result = detector.check("agent-1")
    assert result.probing_detected is True
    assert result.pattern == "binary_search"


def test_binary_not_detected() -> None:
    detector = ThresholdProbingDetector(min_attempts=3)
    _record_series(detector, [100, 200, 300])
    detected, _confidence = detector._check_binary_search([100, 200, 300])
    assert detected is False


def test_boundary_detected() -> None:
    detector = ThresholdProbingDetector(min_attempts=3)
    _record_series(
        detector,
        [99, 101, 100, 99, 101],
        blocked=[False, True, False, True, False],
    )
    result = detector.check("agent-1")
    assert result.probing_detected is True
    assert result.pattern == "boundary_oscillation"


def test_boundary_with_blocks() -> None:
    detector = ThresholdProbingDetector(min_attempts=3)
    _record_series(
        detector,
        [49.5, 50.2, 49.8, 50.1, 49.9],
        metric="budget_usd",
        blocked=[False, True, False, True, False],
    )
    result = detector.check("agent-1")
    assert result.probing_detected is True
    assert result.pattern == "boundary_oscillation"


def test_boundary_not_detected() -> None:
    detector = ThresholdProbingDetector(min_attempts=3)
    _record_series(
        detector,
        [10, 20, 35, 55, 80],
        blocked=[False, True, False, True, False],
    )
    detected, _confidence = detector._check_boundary_oscillation(
        [10, 20, 35, 55, 80],
        [False, True, False, True, False],
    )
    assert detected is False


def test_record_attempt() -> None:
    detector = ThresholdProbingDetector()
    detector.record_attempt("agent-1", metric="token_count", value=123)
    attempts = detector.get_attempts("agent-1")
    assert len(attempts) == 1
    assert attempts[0].value == 123


def test_window_trim(monkeypatch) -> None:
    detector = ThresholdProbingDetector(window_seconds=10, min_attempts=3)

    class _Clock:
        def __init__(self) -> None:
            self.now = 1000.0

        def time(self) -> float:
            return self.now

    clock = _Clock()
    monkeypatch.setattr(probing_module.time, "time", clock.time)

    detector.record_attempt("agent-1", metric="token_count", value=100)
    clock.now = 1005.0
    detector.record_attempt("agent-1", metric="token_count", value=200)
    clock.now = 1016.0
    detector.record_attempt("agent-1", metric="token_count", value=300)

    attempts = detector.get_attempts("agent-1")
    assert len(attempts) == 1
    assert attempts[0].value == 300


def test_multiple_metrics() -> None:
    detector = ThresholdProbingDetector(min_attempts=3)
    _record_series(detector, [100, 200, 300, 400], metric="token_count")
    _record_series(detector, [1.0, 1.6, 0.5, 2.3], metric="budget_usd")
    result = detector.check("agent-1")
    assert result.probing_detected is True
    assert result.metric == "token_count"
    assert result.pattern == "linear"


def test_empty_check() -> None:
    detector = ThresholdProbingDetector()
    result = detector.check("agent-1")
    assert result.probing_detected is False
    assert result.pattern == ""


def test_clear_agent() -> None:
    detector = ThresholdProbingDetector()
    detector.record_attempt("agent-1", metric="token_count", value=100)
    detector.clear("agent-1")
    assert detector.get_attempts("agent-1") == []


def test_recommendation_on_detection() -> None:
    detector = ThresholdProbingDetector(min_attempts=3)
    _record_series(detector, [100, 200, 300, 400, 500])
    result = detector.check("agent-1")
    assert result.probing_detected is True
    assert result.recommendation != ""

