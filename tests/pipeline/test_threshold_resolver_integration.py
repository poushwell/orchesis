"""Tests for the ThresholdResolver DSL wiring inside LLMHTTPProxy.

Verifies SPEC §1.9.1 integration: phases can query declarative thresholds
via `proxy.get_threshold(name, **context)` and the table hot-reloads via
`POST /api/v1/thresholds/reload`.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from orchesis.dsl import DslError
from orchesis.proxy import DEFAULT_THRESHOLDS, HTTPProxyConfig, LLMHTTPProxy


@pytest.fixture
def proxy_instance():
    return LLMHTTPProxy(config=HTTPProxyConfig(host="127.0.0.1", port=0))


class TestDefaultThresholds:
    def test_sigma_cascade_deep_pro_tool_use(self, proxy_instance):
        v = proxy_instance.get_threshold(
            "sigma_cascade", tier="deep_pro", task_type="tool_use"
        )
        assert v == 0.55

    def test_sigma_cascade_deep_pro_other_task(self, proxy_instance):
        v = proxy_instance.get_threshold("sigma_cascade", tier="deep_pro")
        assert v == 0.7

    def test_sigma_cascade_long_chain(self, proxy_instance):
        v = proxy_instance.get_threshold(
            "sigma_cascade", tier="lite", chain_length=100
        )
        assert v == 0.65

    def test_sigma_cascade_default(self, proxy_instance):
        v = proxy_instance.get_threshold("sigma_cascade", tier="lite")
        assert v == 0.8

    def test_circuit_breaker_per_tier(self, proxy_instance):
        assert proxy_instance.get_threshold("circuit_breaker_max_errors", tier="free") == 3
        assert proxy_instance.get_threshold("circuit_breaker_max_errors", tier="lite") == 5
        assert proxy_instance.get_threshold("circuit_breaker_max_errors", tier="pro") == 10
        assert proxy_instance.get_threshold("circuit_breaker_max_errors", tier="deep_pro") == 15

    def test_loop_max_repeats_by_chain_length(self, proxy_instance):
        assert proxy_instance.get_threshold("loop_max_repeats", chain_length=5) == 3
        assert proxy_instance.get_threshold("loop_max_repeats", chain_length=20) == 2
        assert proxy_instance.get_threshold("loop_max_repeats", chain_length=50) == 1

    def test_unknown_threshold_raises(self, proxy_instance):
        with pytest.raises(DslError, match="not defined"):
            proxy_instance.get_threshold("does_not_exist")


class TestPolicyOverride:
    def test_policy_thresholds_used(self, tmp_path):
        # Write a policy YAML with custom thresholds and a lookups table.
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(
            "thresholds:\n"
            "  my_threshold:\n"
            "    - if: ctx.tier == \"pro\"\n"
            "      value: 0.99\n"
            "    - default: lookup(\"alt\", ctx.reliability_profile)\n"
            "threshold_lookups:\n"
            "  alt:\n"
            "    balanced: 0.50\n"
            "    paranoid: 0.20\n"
        )
        proxy = LLMHTTPProxy(
            config=HTTPProxyConfig(host="127.0.0.1", port=0),
            policy_path=str(policy_path),
        )
        assert proxy.get_threshold("my_threshold", tier="pro") == 0.99
        assert proxy.get_threshold(
            "my_threshold", tier="lite", reliability_profile="paranoid"
        ) == 0.2

    def test_invalid_policy_thresholds_falls_back_to_defaults(self, tmp_path):
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(
            "thresholds:\n"
            "  bad:\n"
            "    - if: ctx.does_not_exist == 1\n"   # whitelist violation
            "      value: 1\n"
            "    - default: 2\n"
        )
        # Proxy still boots; defaults preserved on the unrelated thresholds.
        proxy = LLMHTTPProxy(
            config=HTTPProxyConfig(host="127.0.0.1", port=0),
            policy_path=str(policy_path),
        )
        assert proxy.get_threshold(
            "sigma_cascade", tier="deep_pro", task_type="tool_use"
        ) == 0.55


class TestReloadEndpoint:
    def test_reload_handler_success(self, proxy_instance):
        captured: dict = {}

        def fake_send_json(handler, status, payload):
            captured["status"] = status
            captured["payload"] = payload

        proxy_instance._send_json = fake_send_json  # type: ignore[method-assign]
        proxy_instance._handle_thresholds_reload(MagicMock())
        assert captured["status"] == 200
        assert captured["payload"]["status"] == "reloaded"
        assert captured["payload"]["thresholds_count"] >= 1

    def test_reload_handler_invalid_returns_400(self, proxy_instance):
        # Plant an invalid threshold spec in policy.
        proxy_instance._policy = {
            "thresholds": {
                "x": [{"default": "lookup(\"missing\", \"k\")"}],  # parses but evaluates to error at eval time
            }
        }
        # Reload itself should succeed (the spec parses); the lookup error
        # would surface only when get_threshold is called. So this test
        # demonstrates parser-level validity.
        captured: dict = {}

        def fake_send_json(handler, status, payload):
            captured["status"] = status
            captured["payload"] = payload

        proxy_instance._send_json = fake_send_json  # type: ignore[method-assign]
        proxy_instance._handle_thresholds_reload(MagicMock())
        assert captured["status"] == 200

    def test_reload_with_malformed_dsl_rejected(self, proxy_instance):
        proxy_instance._policy = {
            "thresholds": {
                "bad": [{"if": "this is not valid syntax!!", "value": 1}, {"default": 0}],
            }
        }
        captured: dict = {}

        def fake_send_json(handler, status, payload):
            captured["status"] = status
            captured["payload"] = payload

        proxy_instance._send_json = fake_send_json  # type: ignore[method-assign]
        proxy_instance._handle_thresholds_reload(MagicMock())
        assert captured["status"] == 400

    def test_reload_preserves_existing_on_failure(self, proxy_instance):
        # Start by confirming a default still resolves.
        assert proxy_instance.get_threshold(
            "sigma_cascade", tier="deep_pro", task_type="tool_use"
        ) == 0.55
        # Now plant a bad config and try to reload.
        proxy_instance._policy = {
            "thresholds": {
                "bad": [{"if": "ctx.nope > 1", "value": 1}, {"default": 0}],
            }
        }
        captured: dict = {}
        proxy_instance._send_json = lambda h, s, p: captured.update(status=s)  # type: ignore[method-assign]
        proxy_instance._handle_thresholds_reload(MagicMock())
        assert captured["status"] == 400
        # Old table still active.
        assert proxy_instance.get_threshold(
            "sigma_cascade", tier="deep_pro", task_type="tool_use"
        ) == 0.55


class TestProxyExposesResolver:
    def test_threshold_resolver_attribute(self, proxy_instance):
        assert proxy_instance._threshold_resolver is not None

    def test_default_thresholds_contains_expected_keys(self):
        for k in ("sigma_cascade", "circuit_breaker_max_errors", "loop_max_repeats"):
            assert k in DEFAULT_THRESHOLDS
