from __future__ import annotations

from orchesis.fast_path import (
    FRAMEWORK_TRUST,
    MANDATORY_PHASES,
    SKIPPABLE_PHASES,
    FastPathEvaluator,
    TrustLevel,
)


def test_untrusted_no_skip() -> None:
    decision = FastPathEvaluator().evaluate(headers={"user-agent": "unknown-agent/1.0"})
    assert decision.fast_path is False
    assert decision.skip_phases == []


def test_basic_trust_openclaw() -> None:
    decision = FastPathEvaluator().evaluate(headers={"user-agent": "OpenClaw/1.0"})
    assert decision.trust_level == TrustLevel.BASIC
    assert decision.skip_phases == ["experiment", "flow_xray", "cascade", "adaptive_detection"]


def test_trusted_registered() -> None:
    evaluator = FastPathEvaluator(registered_agents={"agent-1"})
    decision = evaluator.evaluate(headers={"x-orchesis-agent-id": "agent-1"})
    assert decision.trust_level == TrustLevel.TRUSTED
    assert len(decision.skip_phases) == 7


def test_manual_trust_override() -> None:
    evaluator = FastPathEvaluator()
    evaluator.set_trust("a1", TrustLevel.INTERNAL)
    decision = evaluator.evaluate(headers={"x-orchesis-agent-id": "a1"})
    assert decision.trust_level == TrustLevel.INTERNAL


def test_detect_openclaw_ua() -> None:
    assert FastPathEvaluator()._detect_framework({"user-agent": "OpenClaw/1.0"}) == "openclaw"  # noqa: SLF001


def test_detect_paperclip_header() -> None:
    assert FastPathEvaluator()._detect_framework({"x-orchesis-framework": "paperclip"}) == "paperclip"  # noqa: SLF001


def test_detect_unknown() -> None:
    assert FastPathEvaluator()._detect_framework({}) == ""  # noqa: SLF001


def test_mandatory_never_skipped() -> None:
    for phases in SKIPPABLE_PHASES.values():
        for mandatory in MANDATORY_PHASES:
            assert mandatory not in phases


def test_policy_always_mandatory() -> None:
    assert "policy" in FastPathEvaluator().get_mandatory_phases()


def test_secrets_always_mandatory() -> None:
    assert "secrets" in FastPathEvaluator().get_mandatory_phases()


def test_openclaw_skips_4_phases() -> None:
    decision = FastPathEvaluator().evaluate(headers={"user-agent": "OpenClaw/1.0"})
    assert decision.fast_path is True
    assert len(decision.skip_phases) == 4


def test_trusted_skips_7_phases() -> None:
    evaluator = FastPathEvaluator(registered_agents={"agent-1"})
    decision = evaluator.evaluate(headers={"x-orchesis-agent-id": "agent-1"})
    assert len(decision.skip_phases) == 7


def test_empty_headers() -> None:
    decision = FastPathEvaluator().evaluate(headers={})
    assert decision.trust_level == TrustLevel.UNTRUSTED


def test_decision_has_reason() -> None:
    basic = FastPathEvaluator().evaluate(headers={"user-agent": "OpenClaw/1.0"})
    unknown = FastPathEvaluator().evaluate(headers={})
    assert basic.reason
    assert unknown.reason
