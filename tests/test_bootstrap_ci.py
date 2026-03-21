from __future__ import annotations

import json
import time
from pathlib import Path

from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis.stats.bootstrap_ci import (
    BootstrapCI,
    BootstrapResult,
    r_squared,
    zipf_alpha_estimator,
)


def _zipf_counts(alpha: float, n: int, scale: int = 1000) -> list[int]:
    return [max(1, int(round(scale / ((rank + 1) ** alpha)))) for rank in range(n)]


def test_zipf_alpha_known_distribution() -> None:
    data = _zipf_counts(alpha=1.5, n=50)
    estimate = zipf_alpha_estimator(data)
    assert abs(estimate - 1.5) < 0.3


def test_zipf_alpha_uniform() -> None:
    estimate = zipf_alpha_estimator([10] * 20)
    assert abs(estimate) < 1e-9


def test_zipf_alpha_single_element() -> None:
    assert zipf_alpha_estimator([100]) == 0.0


def test_r_squared_perfect_zipf() -> None:
    score = r_squared(_zipf_counts(alpha=1.4, n=40))
    assert score > 0.95


def test_bootstrap_ci_basic() -> None:
    ci = BootstrapCI(_zipf_counts(alpha=1.5, n=30), seed=7)
    result = ci.compute(n_bootstrap=200, confidence=0.95)

    assert isinstance(result, BootstrapResult)
    assert result.n_bootstrap == 200
    assert result.n_data == 30
    assert len(result.bootstrap_distribution) == 200


def test_bootstrap_ci_contains_estimate() -> None:
    result = BootstrapCI(_zipf_counts(alpha=1.5, n=30), seed=7).compute(n_bootstrap=500)
    assert result.ci_lower <= result.estimate <= result.ci_upper


def test_bootstrap_ci_reproducible() -> None:
    data = _zipf_counts(alpha=1.6, n=35)
    left = BootstrapCI(data, seed=123).compute(n_bootstrap=400, confidence=0.9)
    right = BootstrapCI(data, seed=123).compute(n_bootstrap=400, confidence=0.9)

    assert left.estimate == right.estimate
    assert left.ci_lower == right.ci_lower
    assert left.ci_upper == right.ci_upper
    assert left.bootstrap_distribution == right.bootstrap_distribution


def test_bootstrap_ci_wider_with_less_data() -> None:
    def statistic_fn(values):
        return sum(values) / len(values)

    base = [0.0, 0.1, 0.2, 0.4, 0.8, 1.0, 0.3, 0.6, 0.9, 0.5]
    small = BootstrapCI(base, statistic_fn=statistic_fn, seed=42).compute(n_bootstrap=1000)
    large = BootstrapCI(base * 10, statistic_fn=statistic_fn, seed=42).compute(n_bootstrap=1000)

    small_width = small.ci_upper - small.ci_lower
    large_width = large.ci_upper - large.ci_lower
    assert small_width > large_width


def test_bootstrap_ci_confidence_levels() -> None:
    data = _zipf_counts(alpha=1.5, n=30)
    low = BootstrapCI(data, seed=42).compute(n_bootstrap=1000, confidence=0.90)
    high = BootstrapCI(data, seed=42).compute(n_bootstrap=1000, confidence=0.99)

    assert (high.ci_upper - high.ci_lower) >= (low.ci_upper - low.ci_lower)


def test_bootstrap_ci_performance() -> None:
    data = _zipf_counts(alpha=1.5, n=25)
    start = time.perf_counter()
    result = BootstrapCI(data, seed=42).compute(n_bootstrap=10000, confidence=0.95)
    elapsed = time.perf_counter() - start

    assert result.n_bootstrap == 10000
    assert elapsed < 5.0


def test_result_summary() -> None:
    result = BootstrapResult(
        estimate=1.672,
        ci_lower=1.58,
        ci_upper=1.76,
        confidence=0.95,
        n_bootstrap=10000,
        n_data=41,
        se=0.04,
        bias=0.01,
    )
    summary = result.summary()
    assert "95% CI" in summary
    assert "[1.5800, 1.7600]" in summary


def test_result_fields() -> None:
    result = BootstrapResult(
        estimate=1.0,
        ci_lower=0.8,
        ci_upper=1.2,
        confidence=0.95,
        n_bootstrap=100,
        n_data=10,
        se=0.1,
        bias=0.01,
        bootstrap_distribution=[0.9, 1.0, 1.1],
    )
    assert isinstance(result.estimate, float)
    assert isinstance(result.ci_lower, float)
    assert isinstance(result.ci_upper, float)
    assert isinstance(result.confidence, float)
    assert isinstance(result.n_bootstrap, int)
    assert isinstance(result.n_data, int)
    assert isinstance(result.bootstrap_distribution, list)


def test_bootstrap_ci_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["bootstrap-ci", "--help"])
    assert result.exit_code == 0
    assert "Compute bootstrap CI for Zipf alpha estimate" in result.output


def test_bootstrap_ci_module_import() -> None:
    from orchesis.stats import bootstrap_ci

    assert bootstrap_ci.BootstrapCI is not None


def test_bootstrap_ci_cli_json(tmp_path: Path) -> None:
    data_path = tmp_path / "freqs.json"
    data_path.write_text(json.dumps(_zipf_counts(alpha=1.5, n=20)), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["bootstrap-ci", "--data-file", str(data_path), "--n-bootstrap", "200", "--format", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "estimate" in payload
    assert "ci_lower" in payload
    assert "ci_upper" in payload
