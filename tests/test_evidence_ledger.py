from __future__ import annotations

from pathlib import Path

from orchesis.core.evidence_ledger import EvidenceLedger


def test_evidence_ledger_buffers_writes(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = EvidenceLedger(path, max_buffer_size=10, flush_interval=0.0)
    try:
        ledger.record({"k": 1})
        ledger.record({"k": 2})
        ledger.record({"k": 3})
        assert not path.exists() or path.read_text(encoding="utf-8").strip() == ""
    finally:
        ledger.close()


def test_evidence_ledger_auto_flush_at_max(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = EvidenceLedger(path, max_buffer_size=2, flush_interval=0.0)
    try:
        ledger.record({"a": 1})
        assert not path.exists() or path.read_text(encoding="utf-8").strip() == ""
        ledger.record({"b": 2})
        text = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(text) == 2
        assert ledger.verify_chain()
    finally:
        ledger.close()


def test_evidence_ledger_flush_on_close(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = EvidenceLedger(path, max_buffer_size=100, flush_interval=0.0)
    ledger.record({"only": True})
    ledger.close()
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert ledger.verify_chain()
