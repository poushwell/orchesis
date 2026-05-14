from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from orchesis.config import load_policy
from orchesis.engine import evaluate
from orchesis.models import Decision

pytestmark = pytest.mark.fuzz

JSON_SCALAR = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(),
)

JSON_VALUE = st.recursive(
    JSON_SCALAR,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=6),
    ),
    max_leaves=25,
)


@settings(max_examples=120, deadline=None)
@given(
    request=st.dictionaries(st.text(min_size=1, max_size=15), JSON_VALUE, max_size=8),
)
def test_random_requests_always_return_decision(request: dict[str, object]) -> None:
    policy = {
        "rules": [
            {"name": "budget_limit", "max_cost_per_call": 1.0},
            {"name": "file_access", "allowed_paths": ["/data", "/tmp"], "denied_paths": ["/etc"]},
            {"name": "sql_restriction", "denied_operations": ["DROP", "DELETE"]},
            {"name": "rate_limit", "max_requests_per_minute": 100},
        ]
    }

    result = evaluate(request, policy)

    assert isinstance(result, Decision)
    assert isinstance(result.allowed, bool)
    assert isinstance(result.reasons, list)
    assert isinstance(result.rules_checked, list)


@settings(max_examples=120, deadline=None)
@given(
    request=st.dictionaries(st.text(min_size=1, max_size=15), JSON_VALUE, max_size=8),
    unknown_rule_name=st.text(min_size=1, max_size=20),
)
def test_engine_is_deterministic_for_same_input(
    request: dict[str, object], unknown_rule_name: str
) -> None:
    policy = {
        "rules": [
            {"name": "budget_limit", "max_cost_per_call": 0.5},
            {"name": "file_access", "denied_paths": ["/etc", "/root"]},
            {"name": "sql_restriction", "denied_operations": ["DROP"]},
            {"name": "rate_limit", "max_requests_per_minute": 20},
            {"name": unknown_rule_name},
        ]
    }

    first = evaluate(request, policy)
    second = evaluate(request, policy)

    assert first.allowed == second.allowed
    assert first.reasons == second.reasons
    assert first.rules_checked == second.rules_checked


@settings(max_examples=120, deadline=None)
@given(content=st.text(max_size=500))
def test_random_yaml_input_never_crashes_loader(content: str) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        policy_path = Path(temp_dir) / "random_policy.yaml"
        policy_path.write_text(content, encoding="utf-8")

        try:
            loaded = load_policy(policy_path)
        except ValueError:
            return
        except Exception as error:  # pragma: no cover
            pytest.fail(f"Unexpected exception type: {type(error).__name__}: {error}")

        assert isinstance(loaded, dict)
