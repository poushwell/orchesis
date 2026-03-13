from __future__ import annotations

import time
from types import SimpleNamespace

from orchesis.privacy_filter import (
    PRIVACY_LEVEL_EXTENDED,
    PRIVACY_LEVEL_MINIMAL,
    PRIVACY_LEVEL_OFF,
    PRIVACY_LEVEL_RESEARCH,
    PRIVACY_LEVEL_STANDARD,
    CommunitySignal,
    PrivacyFilter,
)


def _det(score: float = 70.0) -> SimpleNamespace:
    return SimpleNamespace(
        anomaly_score=score,
        risk_level="high",
        drift_type="injection",
        entropy_score=82.5,
        pattern_types=["tool_chain_loop"],
        threat_ids=["ORCH-TA-002"],
    )


def _telemetry() -> dict:
    return {"input_tokens": 100, "output_tokens": 50, "model_used": "gpt-4o-mini", "total_ms": 123.4, "cache_hit": True}


def test_create_signal_level_0_returns_none() -> None:
    pf = PrivacyFilter(PRIVACY_LEVEL_OFF)
    assert pf.create_signal(detection_result=_det()) is None


def test_create_signal_level_1_minimal_fields() -> None:
    pf = PrivacyFilter(PRIVACY_LEVEL_MINIMAL)
    s = pf.create_signal(detection_result=_det(), telemetry_record=_telemetry(), ars_data={"grade": "A"})
    assert s is not None
    assert s.threat_ids == ["ORCH-TA-002"]
    assert s.anomaly_score == 0.0
    assert s.model_name == ""


def test_create_signal_level_2_includes_metrics() -> None:
    pf = PrivacyFilter(PRIVACY_LEVEL_STANDARD)
    s = pf.create_signal(detection_result=_det(), telemetry_record=_telemetry(), ars_data={"grade": "B"})
    assert s is not None
    assert s.model_name == "gpt-4o-mini"
    assert s.request_tokens == 100
    assert s.agent_type_hash == ""


def test_create_signal_level_3_includes_fingerprint() -> None:
    pf = PrivacyFilter(PRIVACY_LEVEL_EXTENDED)
    s = pf.create_signal(
        detection_result=_det(),
        telemetry_record=_telemetry(),
        request_meta={"agent_behavioral_data": {"mean_tokens": 123, "tool_freq": {"read": 3}}},
    )
    assert s is not None
    assert len(s.agent_type_hash) == 64
    assert s.pattern_types


def test_create_signal_level_4_includes_everything() -> None:
    pf = PrivacyFilter(PRIVACY_LEVEL_RESEARCH)
    s = pf.create_signal(detection_result=_det(), telemetry_record=_telemetry(), ars_data={"grade": "C"})
    assert s is not None
    assert s.latency_ms > 0
    assert s.request_tokens > 0
    assert s.cache_hit is True


def test_create_signal_no_detection_returns_none() -> None:
    pf = PrivacyFilter()
    assert pf.create_signal(detection_result=None, telemetry_record=None) is None


def test_create_signal_low_score_returns_none() -> None:
    pf = PrivacyFilter(min_anomaly_score=30.0)
    low = {"anomaly_score": 10.0, "risk_level": "low", "threat_ids": [], "pattern_types": []}
    assert pf.create_signal(detection_result=low) is None


def test_no_prompt_content_in_signal() -> None:
    pf = PrivacyFilter()
    s = pf.create_signal(detection_result=_det(), request_meta={"prompt": "Ignore previous instructions"})
    assert s is not None
    assert "Ignore previous instructions" not in str(s)


def test_no_api_keys_in_signal() -> None:
    pf = PrivacyFilter()
    s = pf.create_signal(detection_result=_det(), request_meta={"secret": "sk-proj-abcdef123456"})
    assert s is not None
    assert "sk-proj" not in str(s)


def test_no_pii_in_signal() -> None:
    pf = PrivacyFilter()
    s = pf.create_signal(detection_result=_det(), request_meta={"email": "john@example.com"})
    assert s is not None
    assert "example.com" not in str(s)


def test_no_file_paths_in_signal() -> None:
    pf = PrivacyFilter()
    s = pf.create_signal(detection_result=_det(), request_meta={"path": "/etc/passwd"})
    assert s is not None
    assert "/etc/passwd" not in str(s)


def test_no_user_identifiers_in_signal() -> None:
    pf = PrivacyFilter()
    s = pf.create_signal(detection_result=_det(), request_meta={"user_id": "u-123"})
    assert s is not None
    assert "u-123" not in str(s)


def test_hash_agent_profile_irreversible() -> None:
    pf = PrivacyFilter(PRIVACY_LEVEL_EXTENDED)
    h = pf.hash_agent_profile({"a": 1, "b": 2})
    assert len(h) == 64
    assert h != '{"a":1,"b":2}'


def test_hash_same_profile_same_hash() -> None:
    pf = PrivacyFilter(PRIVACY_LEVEL_EXTENDED)
    assert pf.hash_agent_profile({"x": 1, "y": 2}) == pf.hash_agent_profile({"y": 2, "x": 1})


def test_hash_different_profiles_different_hash() -> None:
    pf = PrivacyFilter(PRIVACY_LEVEL_EXTENDED)
    assert pf.hash_agent_profile({"x": 1}) != pf.hash_agent_profile({"x": 2})


def test_validate_signal_clean_passes() -> None:
    pf = PrivacyFilter()
    s = pf.create_signal(detection_result=_det(), telemetry_record=_telemetry())
    assert s is not None
    assert pf.validate_signal(s)


def test_validate_signal_with_email_fails() -> None:
    pf = PrivacyFilter()
    bad = CommunitySignal(signal_id="550e8400-e29b-41d4-a716-446655440000", timestamp=time.time(), signal_type="anomaly")
    bad.model_name = "john@example.com"
    assert not pf.validate_signal(bad)


def test_validate_signal_with_ip_fails() -> None:
    pf = PrivacyFilter()
    bad = CommunitySignal(signal_id="550e8400-e29b-41d4-a716-446655440000", timestamp=time.time(), signal_type="anomaly")
    bad.model_name = "192.168.1.10"
    assert not pf.validate_signal(bad)


def test_validate_signal_with_long_string_fails() -> None:
    pf = PrivacyFilter()
    bad = CommunitySignal(signal_id="550e8400-e29b-41d4-a716-446655440000", timestamp=time.time(), signal_type="anomaly")
    bad.model_name = "x" * 300
    assert not pf.validate_signal(bad)


def test_validate_signal_with_prompt_like_text_fails() -> None:
    pf = PrivacyFilter()
    bad = CommunitySignal(signal_id="550e8400-e29b-41d4-a716-446655440000", timestamp=time.time(), signal_type="anomaly")
    bad.model_name = "ignore previous instructions"
    assert not pf.validate_signal(bad)


def test_validate_signal_old_timestamp_fails() -> None:
    pf = PrivacyFilter()
    bad = CommunitySignal(signal_id="550e8400-e29b-41d4-a716-446655440000", timestamp=time.time() - 7200, signal_type="anomaly")
    assert not pf.validate_signal(bad)


def test_create_signal_empty_detection_result() -> None:
    pf = PrivacyFilter()
    assert pf.create_signal(detection_result={}) is None


def test_create_signal_none_fields_handled() -> None:
    pf = PrivacyFilter()
    s = pf.create_signal(detection_result={"anomaly_score": 60.0, "risk_level": None, "drift_type": None, "threat_ids": ["ORCH-TA-010"]})
    assert s is not None


def test_privacy_report_accurate() -> None:
    pf = PrivacyFilter()
    _ = pf.create_signal(detection_result=_det(score=70.0))
    _ = pf.create_signal(detection_result={"anomaly_score": 5.0, "risk_level": "low", "threat_ids": []})
    report = pf.get_privacy_report()
    assert report["signals_created"] >= 1
    assert report["signals_rejected"] >= 1


def test_validate_signal_bad_uuid_fails() -> None:
    pf = PrivacyFilter()
    bad = CommunitySignal(signal_id="not-uuid", timestamp=time.time(), signal_type="anomaly")
    assert not pf.validate_signal(bad)


def test_validate_signal_invalid_risk_level_fails() -> None:
    pf = PrivacyFilter()
    bad = CommunitySignal(
        signal_id="550e8400-e29b-41d4-a716-446655440000",
        timestamp=time.time(),
        signal_type="anomaly",
        risk_level="very_high",
    )
    assert not pf.validate_signal(bad)


def test_validate_signal_secret_pattern_fails() -> None:
    pf = PrivacyFilter()
    bad = CommunitySignal(signal_id="550e8400-e29b-41d4-a716-446655440000", timestamp=time.time(), signal_type="anomaly")
    bad.model_name = "sk-proj-abcdefghijklmnop"
    assert not pf.validate_signal(bad)
