import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

CI_MULTIPLIER = 5.0 if os.getenv("CI") else 1.0


@pytest.fixture(autouse=True)
def _scale_test_sleep_for_ci(monkeypatch: pytest.MonkeyPatch):
    """Scale test sleeps in CI to reduce timing flakiness."""
    if CI_MULTIPLIER == 1.0:
        yield
        return

    original_sleep = time.sleep

    def _scaled_sleep(seconds: float) -> None:
        try:
            value = float(seconds)
        except (TypeError, ValueError):
            value = 0.0
        original_sleep(max(0.0, value * CI_MULTIPLIER))

    monkeypatch.setattr(time, "sleep", _scaled_sleep)
    yield
