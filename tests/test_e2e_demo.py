from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run_e2e_demo import run_demo


def test_demo_script_runs_without_error() -> None:
    result = asyncio.run(run_demo(rate_burst=20))
    assert result["total"] > 0


def test_demo_produces_audit_log() -> None:
    _ = asyncio.run(run_demo(rate_burst=20))
    log_path = Path(".orchesis/decisions.jsonl")
    assert log_path.exists()
    lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) > 0


def test_demo_invariants_pass() -> None:
    result = asyncio.run(run_demo(rate_burst=20))
    assert result["invariants_passed"] == 1
