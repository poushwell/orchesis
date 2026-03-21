from __future__ import annotations

from orchesis.core.nlce_pipeline import AgentState


def test_agent_state_has_ghost_fields() -> None:
    state = AgentState()

    assert state.slope_cqs == 0.0
    assert state.ews_tau == 0.0
    assert state.kalman_state == "nominal"
    assert state.agent_id == ""
    assert state.task_type == "default"


def test_agent_state_no_stale_psi_window() -> None:
    state = AgentState()

    assert not hasattr(state, "stale_psi_window")


def test_cognitive_load_property() -> None:
    state = AgentState(kalman_x=[0.2, 0.7, 0.9])

    assert state.cognitive_load == 0.2


def test_context_quality_property() -> None:
    state = AgentState(kalman_x=[0.2, 0.7, 0.9])

    assert state.context_quality == 0.7


def test_coherence_property() -> None:
    state = AgentState(kalman_x=[0.2, 0.7, 0.9])

    assert state.coherence == 0.9
