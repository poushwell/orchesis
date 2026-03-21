from __future__ import annotations

from orchesis.detectors.anti_collusion import AntiCollusionDetector


def _set_timestamps(detector: AntiCollusionDetector, assignments: dict[str, list[float]]) -> None:
    for agent_id, timestamps in assignments.items():
        actions = detector._actions.get(agent_id, [])
        for idx, ts in enumerate(timestamps):
            if idx < len(actions):
                actions[idx].timestamp = float(ts)


def test_temporal_correlation() -> None:
    detector = AntiCollusionDetector(temporal_window_s=10.0, correlation_threshold=0.7)
    detector.record_action("a1", "search")
    detector.record_action("a2", "search")
    _set_timestamps(detector, {"a1": [100.0], "a2": [102.0]})

    result = detector.check_fleet()
    assert any(p.signal_type == "temporal" for p in result.pairs)


def test_temporal_no_correlation() -> None:
    detector = AntiCollusionDetector(temporal_window_s=10.0, correlation_threshold=0.7)
    detector.record_action("a1", "search")
    detector.record_action("a2", "search")
    _set_timestamps(detector, {"a1": [100.0], "a2": [160.0]})

    result = detector.check_fleet()
    assert not any(p.signal_type == "temporal" for p in result.pairs)


def test_temporal_threshold() -> None:
    detector = AntiCollusionDetector(temporal_window_s=10.0, correlation_threshold=0.8)
    detector.record_action("a1", "search")
    detector.record_action("a1", "search")
    detector.record_action("a2", "search")
    detector.record_action("a2", "search")
    _set_timestamps(detector, {"a1": [0.0, 100.0], "a2": [2.0, 200.0]})

    result = detector.check_fleet()
    assert not any(p.signal_type == "temporal" for p in result.pairs)


def test_data_flow_detected() -> None:
    detector = AntiCollusionDetector(temporal_window_s=10.0)
    detector.record_action("a1", "read_file", output_hashes=["x"])
    detector.record_action("a2", "send_email", input_hashes=["x"])
    _set_timestamps(detector, {"a1": [10.0], "a2": [11.0]})

    result = detector.check_fleet()
    assert any(p.signal_type == "data_flow" for p in result.pairs)


def test_data_flow_no_match() -> None:
    detector = AntiCollusionDetector(temporal_window_s=10.0)
    detector.record_action("a1", "read_file", output_hashes=["x"])
    detector.record_action("a2", "send_email", input_hashes=["y"])
    _set_timestamps(detector, {"a1": [10.0], "a2": [11.0]})

    result = detector.check_fleet()
    assert not any(p.signal_type == "data_flow" for p in result.pairs)


def test_data_flow_timing() -> None:
    detector = AntiCollusionDetector(temporal_window_s=5.0)
    detector.record_action("a1", "read_file", output_hashes=["x"])
    detector.record_action("a2", "send_email", input_hashes=["x"])
    _set_timestamps(detector, {"a1": [10.0], "a2": [30.0]})

    result = detector.check_fleet()
    assert not any(p.signal_type == "data_flow" for p in result.pairs)


def test_role_split_detected() -> None:
    detector = AntiCollusionDetector()
    detector.record_action("a1", "read_file")
    detector.record_action("a2", "send_email")
    _set_timestamps(detector, {"a1": [50.0], "a2": [51.0]})

    result = detector.check_fleet()
    assert any(p.signal_type == "role_split" for p in result.pairs)


def test_role_split_single_agent() -> None:
    detector = AntiCollusionDetector()
    detector.record_action("a1", "read_file")
    detector.record_action("a1", "send_email")
    _set_timestamps(detector, {"a1": [50.0, 51.0]})

    result = detector.check_fleet()
    assert not any(p.signal_type == "role_split" for p in result.pairs)


def test_role_split_safe_actions() -> None:
    detector = AntiCollusionDetector()
    detector.record_action("a1", "search")
    detector.record_action("a2", "search")
    _set_timestamps(detector, {"a1": [1.0], "a2": [2.0]})

    result = detector.check_fleet()
    assert not any(p.signal_type == "role_split" for p in result.pairs)


def test_sync_anomaly_detected() -> None:
    detector = AntiCollusionDetector(temporal_window_s=10.0)
    detector.record_action("a1", "search")
    detector.record_action("a2", "search")
    detector.record_action("a3", "search")
    _set_timestamps(detector, {"a1": [100.0], "a2": [101.0], "a3": [103.0]})

    result = detector.check_fleet()
    assert any(p.signal_type == "sync_anomaly" for p in result.pairs)


def test_sync_anomaly_normal() -> None:
    detector = AntiCollusionDetector(temporal_window_s=10.0)
    detector.record_action("a1", "search")
    detector.record_action("a2", "search")
    detector.record_action("a3", "search")
    _set_timestamps(detector, {"a1": [100.0], "a2": [120.0], "a3": [145.0]})

    result = detector.check_fleet()
    assert not any(p.signal_type == "sync_anomaly" for p in result.pairs)


def test_check_fleet_clean() -> None:
    detector = AntiCollusionDetector(temporal_window_s=5.0)
    detector.record_action("a1", "search")
    detector.record_action("a2", "search")
    _set_timestamps(detector, {"a1": [10.0], "a2": [30.0]})

    result = detector.check_fleet()
    assert result.collusion_detected is False
    assert result.fleet_risk_score == 0.0


def test_check_fleet_multiple_signals() -> None:
    detector = AntiCollusionDetector(temporal_window_s=10.0)
    detector.record_action("a1", "read_file", output_hashes=["x"])
    detector.record_action("a2", "send_email", input_hashes=["x"])
    _set_timestamps(detector, {"a1": [10.0], "a2": [12.0]})

    result = detector.check_fleet()
    signal_types = {p.signal_type for p in result.pairs}
    assert "temporal" in signal_types
    assert "data_flow" in signal_types


def test_fleet_risk_score() -> None:
    detector = AntiCollusionDetector()
    detector.record_action("a1", "read_file", output_hashes=["x"])
    detector.record_action("a2", "send_email", input_hashes=["x"])
    _set_timestamps(detector, {"a1": [1.0], "a2": [2.0]})

    result = detector.check_fleet()
    assert result.collusion_detected is True
    assert result.fleet_risk_score > 0.0


def test_empty_fleet() -> None:
    detector = AntiCollusionDetector()
    result = detector.check_fleet()
    assert result.collusion_detected is False
    assert result.pairs == []


def test_single_agent() -> None:
    detector = AntiCollusionDetector()
    detector.record_action("solo", "read_file")
    detector.record_action("solo", "send_email")
    _set_timestamps(detector, {"solo": [1.0, 2.0]})

    result = detector.check_fleet()
    assert result.collusion_detected is False
    assert result.pairs == []

