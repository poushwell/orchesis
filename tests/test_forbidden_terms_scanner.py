"""Tests for the masking pre-commit scanner."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest


# Add `scripts/` to path so we can import the hook module.
_HOOK_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_HOOK_DIR))
import check_forbidden_terms as fk  # noqa: E402


def _diff(file_path: str, new_lines: list[str]) -> str:
    """Build a minimal unified diff string from added lines."""
    out = [f"+++ b/{file_path}"]
    for line in new_lines:
        out.append(f"+{line}")
    return "\n".join(out) + "\n"


class TestHardMatches:
    def test_nlce_blocked(self):
        diff = _diff("docs/foo.md", ["This is NLCE architecture"])
        hits = fk.scan_lines(diff.splitlines(), fk.FORBIDDEN_HARD, "HARD")
        assert any("NLCE" in h["match"] for h in hits)

    def test_kalman_blocked(self):
        # \b doesn't match between 'kalman' and '_' (underscore is a word
        # character in Python regex), so "kalman_filter" is fine.
        # The Kalman pattern targets prose like "Kalman filter" or "Kalman update".
        diff = _diff("src/x.py", ["# Kalman update applied"])
        hits = fk.scan_lines(diff.splitlines(), fk.FORBIDDEN_HARD, "HARD")
        assert any("kalman" in h["match"].lower() for h in hits)

    def test_hypothesis_numbering_blocked(self):
        diff = _diff("docs/foo.md", ["H17 was confirmed", "H43 needs more data"])
        hits = fk.scan_lines(diff.splitlines(), fk.FORBIDDEN_HARD, "HARD")
        labels = [h["match"] for h in hits]
        assert any("H17" in l for l in labels) or any("H43" in l for l in labels)

    def test_phase_enumeration_blocked(self):
        diff = _diff("docs/foo.md", ["Run Phase 17 first"])
        hits = fk.scan_lines(diff.splitlines(), fk.FORBIDDEN_HARD, "HARD")
        assert any("Phase 17" in h["match"] for h in hits)

    def test_only_files_with_known_extensions_scanned(self):
        # .csv is not in DEFAULT_EXTENSIONS — no hit expected.
        diff = _diff("data/x.csv", ["NLCE,1,2,3"])
        hits = fk.scan_lines(diff.splitlines(), fk.FORBIDDEN_HARD, "HARD")
        assert hits == []


class TestSoftMatches:
    def test_thompson_warns_but_doesnt_block(self):
        diff = _diff("src/x.py", ["# Uses Thompson sampling for routing"])
        soft = fk.scan_lines(diff.splitlines(), fk.FORBIDDEN_SOFT, "SOFT")
        assert any("Thompson sampling" in h["match"] for h in soft)
        hard = fk.scan_lines(diff.splitlines(), fk.FORBIDDEN_HARD, "HARD")
        assert hard == []

    def test_sigma_word_warns(self):
        diff = _diff("README.md", ["The sigma threshold trips at 0.5"])
        soft = fk.scan_lines(diff.splitlines(), fk.FORBIDDEN_SOFT, "SOFT")
        assert any("sigma" in h["match"].lower() for h in soft)


class TestCleanDiff:
    def test_no_hits_on_innocent_changes(self):
        diff = _diff("src/x.py", [
            "def update_estimate(self, observations):",
            "    return self._state",
        ])
        hard = fk.scan_lines(diff.splitlines(), fk.FORBIDDEN_HARD, "HARD")
        soft = fk.scan_lines(diff.splitlines(), fk.FORBIDDEN_SOFT, "SOFT")
        assert hard == []
        assert soft == []


class TestMainEntryPoint:
    def test_audit_mode_returns_zero_on_hit(self, tmp_path, capsys, monkeypatch):
        diff_path = tmp_path / "d.diff"
        diff_path.write_text(_diff("a.md", ["NLCE pipeline is here"]))
        monkeypatch.setattr(sys, "argv", [
            "check_forbidden_terms.py",
            "--mode", "audit",
            "--diff-file", str(diff_path),
        ])
        rc = fk.main()
        out = capsys.readouterr().out
        assert rc == 0
        assert "BLOCKED" in out
        assert "Audit mode" in out

    def test_block_mode_returns_one_on_hard_hit(self, tmp_path, capsys, monkeypatch):
        diff_path = tmp_path / "d.diff"
        diff_path.write_text(_diff("a.md", ["NLCE pipeline"]))
        monkeypatch.setattr(sys, "argv", [
            "check_forbidden_terms.py",
            "--block",
            "--diff-file", str(diff_path),
        ])
        rc = fk.main()
        out = capsys.readouterr().out
        assert rc == 1
        assert "Commit blocked" in out

    def test_block_mode_returns_zero_on_clean(self, tmp_path, monkeypatch, capsys):
        diff_path = tmp_path / "d.diff"
        diff_path.write_text(_diff("a.py", ["def f(x): return x + 1"]))
        monkeypatch.setattr(sys, "argv", [
            "check_forbidden_terms.py",
            "--block",
            "--diff-file", str(diff_path),
        ])
        rc = fk.main()
        out = capsys.readouterr().out
        assert rc == 0
        assert "No forbidden terms" in out

    def test_block_mode_passes_on_soft_only(self, tmp_path, monkeypatch, capsys):
        diff_path = tmp_path / "d.diff"
        diff_path.write_text(_diff("a.py", ["# soft: Thompson sampling here"]))
        monkeypatch.setattr(sys, "argv", [
            "check_forbidden_terms.py",
            "--block",
            "--diff-file", str(diff_path),
        ])
        rc = fk.main()
        out = capsys.readouterr().out
        assert rc == 0
        assert "SOFT warning" in out
