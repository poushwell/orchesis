import os
import sys
import time

_tests_dir = os.path.dirname(os.path.abspath(__file__))
if _tests_dir not in sys.path:
    sys.path.insert(0, _tests_dir)

import pytest  # noqa: E402

from ci_multiplier import get_sleep_scale  # noqa: E402


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "slow: tests that typically take several seconds or more")
    config.addinivalue_line("markers", "performance: timing or benchmark-style assertions")
    config.addinivalue_line(
        "markers", "integration: tests that need external services or full stack"
    )
    config.addinivalue_line("markers", "fuzz: fuzz or property-based tests")
    config.addinivalue_line(
        "markers", "flaky: may need reruns (use with pytest-rerunfailures if installed)"
    )
    config.addinivalue_line("markers", "security: red-team / abuse / hardening scenarios")
    config.addinivalue_line(
        "markers", "stress: heavy load, timing, or adversarial edge-case scenarios"
    )


@pytest.fixture(autouse=True)
def _scale_test_sleep_for_ci(monkeypatch: pytest.MonkeyPatch):
    """Scale test sleeps in CI to reduce timing flakiness."""
    mult = get_sleep_scale()
    if mult == 1.0:
        yield
        return

    original_sleep = time.sleep

    def _scaled_sleep(seconds: float) -> None:
        try:
            value = float(seconds)
        except (TypeError, ValueError):
            value = 0.0
        original_sleep(max(0.0, value * mult))

    monkeypatch.setattr(time, "sleep", _scaled_sleep)
    yield
