"""Bootstrap Confidence Intervals for NLCE statistical estimates.

Primary use: CI for Zipf alpha estimate from tool usage distributions.
Also generic enough for any bootstrap CI computation.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Callable

from orchesis.utils.log import get_logger

logger = get_logger(__name__)

# Paper-aligned N=41 default frequency curve used by the CLI when no data file is provided.
DEFAULT_NLCE_TOOL_FREQUENCIES = [
    1000,
    314,
    159,
    98,
    67,
    49,
    38,
    30,
    25,
    21,
    18,
    15,
    13,
    12,
    11,
    9,
    9,
    8,
    7,
    7,
    6,
    6,
    5,
    5,
    5,
    4,
    4,
    4,
    4,
    3,
    3,
    3,
    3,
    3,
    3,
    2,
    2,
    2,
    2,
    2,
    2,
]


@dataclass
class BootstrapResult:
    """Result of bootstrap CI computation."""

    estimate: float
    ci_lower: float
    ci_upper: float
    confidence: float
    n_bootstrap: int
    n_data: int
    se: float = 0.0
    bias: float = 0.0
    bootstrap_distribution: list[float] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"Estimate: {self.estimate:.4f}\n"
            f"{self.confidence * 100:.0f}% CI: [{self.ci_lower:.4f}, {self.ci_upper:.4f}]\n"
            f"SE: {self.se:.4f}, Bias: {self.bias:.4f}\n"
            f"N={self.n_data}, B={self.n_bootstrap}"
        )


def zipf_alpha_estimator(frequencies: list[int]) -> float:
    """Estimate Zipf alpha from frequency data using OLS on log-log."""
    freqs = sorted((int(f) for f in frequencies if isinstance(f, int | float)), reverse=True)
    freqs = [f for f in freqs if f > 0]
    if len(freqs) < 2:
        return 0.0

    n = len(freqs)
    log_ranks = [math.log(i + 1) for i in range(n)]
    log_freqs = [math.log(f) for f in freqs]

    sum_x = sum(log_ranks)
    sum_y = sum(log_freqs)
    sum_xy = sum(x * y for x, y in zip(log_ranks, log_freqs))
    sum_x2 = sum(x * x for x in log_ranks)

    denom = n * sum_x2 - sum_x * sum_x
    if abs(denom) < 1e-12:
        return 0.0

    slope = (n * sum_xy - sum_x * sum_y) / denom
    return -slope


def r_squared(frequencies: list[int]) -> float:
    """Compute R^2 of Zipf fit."""
    freqs = sorted((int(f) for f in frequencies if isinstance(f, int | float)), reverse=True)
    freqs = [f for f in freqs if f > 0]
    if len(freqs) < 2:
        return 0.0

    n = len(freqs)
    log_ranks = [math.log(i + 1) for i in range(n)]
    log_freqs = [math.log(f) for f in freqs]

    sum_x = sum(log_ranks)
    sum_y = sum(log_freqs)
    sum_xy = sum(x * y for x, y in zip(log_ranks, log_freqs))
    sum_x2 = sum(x * x for x in log_ranks)
    mean_y = sum_y / n

    denom = n * sum_x2 - sum_x * sum_x
    if abs(denom) < 1e-12:
        return 0.0

    slope = (n * sum_xy - sum_x * sum_y) / denom
    intercept = (sum_y - slope * sum_x) / n

    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(log_ranks, log_freqs))
    ss_tot = sum((y - mean_y) ** 2 for y in log_freqs)
    if ss_tot < 1e-12:
        return 1.0
    return 1.0 - (ss_res / ss_tot)


class BootstrapCI:
    """Generic bootstrap confidence interval calculator."""

    def __init__(
        self,
        data: list[Any],
        statistic_fn: Callable[[list[Any]], float] | None = None,
        seed: int = 42,
    ):
        self.data = list(data)
        self.statistic_fn = statistic_fn or zipf_alpha_estimator
        self.seed = int(seed)

    def _resample(self, rng: random.Random) -> list[Any]:
        """Generate one bootstrap sample with replacement."""
        n = len(self.data)
        return [self.data[rng.randint(0, n - 1)] for _ in range(n)]

    def compute(self, n_bootstrap: int = 10000, confidence: float = 0.95) -> BootstrapResult:
        """Compute bootstrap CI using the percentile method."""
        if not self.data:
            raise ValueError("bootstrap data must not be empty")
        if int(n_bootstrap) <= 0:
            raise ValueError("n_bootstrap must be > 0")
        if not 0.0 < float(confidence) < 1.0:
            raise ValueError("confidence must be between 0 and 1")

        logger.info(
            "Starting bootstrap CI",
            extra={
                "component": "bootstrap",
                "n_data": len(self.data),
                "n_bootstrap": int(n_bootstrap),
                "confidence": float(confidence),
            },
        )

        rng = random.Random(self.seed)
        point_estimate = float(self.statistic_fn(self.data))

        boot_estimates: list[float] = []
        for _ in range(int(n_bootstrap)):
            sample = self._resample(rng)
            boot_estimates.append(float(self.statistic_fn(sample)))

        boot_estimates.sort()

        alpha = 1.0 - float(confidence)
        lower_idx = int(math.floor((alpha / 2.0) * int(n_bootstrap)))
        upper_idx = int(math.ceil((1.0 - alpha / 2.0) * int(n_bootstrap))) - 1
        lower_idx = max(0, min(lower_idx, int(n_bootstrap) - 1))
        upper_idx = max(0, min(upper_idx, int(n_bootstrap) - 1))

        ci_lower = float(boot_estimates[lower_idx])
        ci_upper = float(boot_estimates[upper_idx])

        mean_boot = sum(boot_estimates) / len(boot_estimates)
        variance = (
            sum((value - mean_boot) ** 2 for value in boot_estimates) / max(1, len(boot_estimates) - 1)
        )
        se = math.sqrt(variance)
        bias = mean_boot - point_estimate

        result = BootstrapResult(
            estimate=point_estimate,
            ci_lower=ci_lower,
            ci_upper=ci_upper,
            confidence=float(confidence),
            n_bootstrap=int(n_bootstrap),
            n_data=len(self.data),
            se=float(se),
            bias=float(bias),
            bootstrap_distribution=boot_estimates,
        )

        logger.info(
            "Bootstrap CI complete",
            extra={
                "component": "bootstrap",
                "ci_lower": round(ci_lower, 6),
                "ci_upper": round(ci_upper, 6),
                "estimate": round(point_estimate, 6),
            },
        )
        return result
