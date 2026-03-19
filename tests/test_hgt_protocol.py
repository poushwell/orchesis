from __future__ import annotations

from orchesis.hgt_protocol import HGTProtocol


def test_hgt_stub_mode_by_default() -> None:
    hgt = HGTProtocol()
    stats = hgt.get_stats()
    assert stats["enabled"] is False
    assert stats["stub_mode"] is True
    assert hgt.should_transfer("a", "b", 0.1) is False


def test_record_outcome_bounded() -> None:
    hgt = HGTProtocol()
    for i in range(10005):
        hgt.record_outcome(f"agent-{i}", {"score": i})
    stats = hgt.get_stats()
    assert stats["outcomes_recorded"] == 10000
    assert hgt._outcomes[0]["agent_id"] == "agent-5"
    assert hgt._outcomes[-1]["agent_id"] == "agent-10004"


def test_transfer_candidates_by_dna_similarity() -> None:
    hgt = HGTProtocol({"enabled": True})
    dna_scores = {
        "agent-a": 0.10,
        "agent-b": 0.20,
        "agent-c": 0.70,
        "agent-d": 0.27,
    }
    candidates = hgt.get_transfer_candidates(dna_scores)
    assert ("agent-b", "agent-d", 0.07) in candidates
    assert ("agent-a", "agent-b", 0.1) in candidates
    assert ("agent-a", "agent-c", 0.6) not in candidates
    assert candidates[0][2] <= candidates[-1][2]

