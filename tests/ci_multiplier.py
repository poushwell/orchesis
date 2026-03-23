"""Shared timing slack for performance assertions; optional CI sleep scaling."""

from __future__ import annotations

import os


def get_ci_multiplier() -> float:
    """Scale performance / timing assertions on CI runners.

    Override with ORCHESIS_CI_MULTIPLIER (minimum 1.0). When unset and CI is set,
    default is 10.0 (was 5.0; CI VMs are often 5–10× slower than local).
    """
    raw = os.environ.get("ORCHESIS_CI_MULTIPLIER")
    if raw is not None:
        try:
            return max(1.0, float(raw))
        except ValueError:
            pass
    if os.getenv("CI"):
        return 10.0
    # Windows dev machines are often slower than Unix laptops for the same micro-benchmarks.
    if os.name == "nt":
        return 5.0
    return 1.0


def get_sleep_scale() -> float:
    """Scale ``time.sleep`` in tests (conftest autouse). Kept separate from
    :func:`get_ci_multiplier` so performance slack can be 10× without turning
    e.g. ``sleep(1.1)`` into ~11s on every CI run.

    Override with ORCHESIS_SLEEP_SCALE. On CI, default 5.0; locally 1.0.
    """
    raw = os.environ.get("ORCHESIS_SLEEP_SCALE")
    if raw is not None:
        try:
            return max(1.0, float(raw))
        except ValueError:
            pass
    if os.getenv("CI"):
        return 5.0
    return 1.0


CI_MULTIPLIER = get_ci_multiplier()
