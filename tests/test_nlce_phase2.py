from __future__ import annotations

from unittest.mock import patch

from orchesis.core.nlce_pipeline import AgentState, Phase2_ContextQualityAssessment


def test_slope_cqs_detects_decline() -> None:
    phase2 = Phase2_ContextQualityAssessment()
    state = AgentState(slope_cqs_window=[0.9, 0.82, 0.74, 0.66, 0.58, 0.5, 0.42, 0.34])
    slope = phase2._compute_slope_cqs(state)
    assert slope < -0.025


def test_psi_crystal_phase() -> None:
    phase2 = Phase2_ContextQualityAssessment()
    state = AgentState(zipf_alpha=2.6, causal_fan_out_variance=0.0)
    psi = phase2._compute_psi(state)
    assert psi >= 0.7
    assert phase2._get_phase(psi) == "CRYSTAL"


def test_psi_gas_phase() -> None:
    phase2 = Phase2_ContextQualityAssessment()
    state = AgentState(zipf_alpha=1.1, causal_fan_out_variance=2.0)
    psi = phase2._compute_psi(state)
    assert psi < 0.3
    assert phase2._get_phase(psi) == "GAS"


def test_stale_crystal_detected() -> None:
    phase2 = Phase2_ContextQualityAssessment()
    state = AgentState(
        psi=0.8,
        slope_cqs_window=[0.86, 0.84, 0.8, 0.77, 0.73, 0.68, 0.64, 0.6],
    )
    slope = phase2._compute_slope_cqs(state)
    assert phase2._check_stale_crystal(state, slope) is True


def test_kalman_full_3x3_update() -> None:
    phase2 = Phase2_ContextQualityAssessment()
    state = AgentState(
        kalman_x=[0.5, 1.0, 1.0],
        kalman_P_full=[1, 0, 0, 0, 1, 0, 0, 0, 1],
        observation_noise=0.2,
    )
    observation = {"cognitive_load": 0.8, "context_quality": 0.7, "coherence": 0.6}
    result = phase2._kalman_full_update(state, observation)
    assert len(result["x"]) == 3
    assert len(result["P_full"]) == 9
    assert len(result["innovation"]) == 3
    assert float(result["innovation_norm"]) > 0.0


def test_slope_written_by_assess() -> None:
    phase2 = Phase2_ContextQualityAssessment()
    state = AgentState(slope_cqs_window=[0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3])

    phase2.assess(state, {"cqs": 0.2})

    assert state.slope_cqs != 0.0


def test_slope_not_duplicated() -> None:
    phase2 = Phase2_ContextQualityAssessment()
    state = AgentState(slope_cqs_window=[0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3])

    with patch.object(phase2, "_compute_slope_cqs", wraps=phase2._compute_slope_cqs) as mock_slope:
        phase2.assess(state, {"cqs": 0.2})

    assert mock_slope.call_count == 1
