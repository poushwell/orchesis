from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run_e2e_demo import run_demo


_REQUIRES_ORCHESIS_CLI = pytest.mark.skipif(
    shutil.which("orchesis") is None,
    reason="requires orchesis CLI installed",
)


@_REQUIRES_ORCHESIS_CLI
def test_demo_script_runs_without_error() -> None:
    result = asyncio.run(run_demo(rate_burst=20))
    assert result["total"] > 0


@_REQUIRES_ORCHESIS_CLI
def test_demo_produces_audit_log() -> None:
    _ = asyncio.run(run_demo(rate_burst=20))
    log_path = Path(".orchesis/decisions.jsonl")
    assert log_path.exists()
    lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) > 0


@_REQUIRES_ORCHESIS_CLI
def test_demo_invariants_pass() -> None:
    result = asyncio.run(run_demo(rate_burst=20))
    assert result["invariants_passed"] == 1
