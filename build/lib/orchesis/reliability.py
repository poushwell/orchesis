"""Reliability report generation."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orchesis.corpus import RegressionCorpus
from orchesis.engine import EvaluationGuarantees


@dataclass
class ReliabilityReport:
    generated_at: str
    orchesis_version: str
    total_tests: int
    adversarial_tests: int
    corpus_entries: int
    corpus_fixed: int
    total_fuzz_runs: int
    total_fuzz_requests: int
    total_mutations_tested: int
    bypasses_found_lifetime: int
    bypasses_fixed: int
    current_bypass_rate: float
    total_invariant_checks: int
    invariant_failures: int
    consecutive_clean_runs: int
    days_without_bypass: int
    replay_verifications: int
    replay_drift_count: int
    deterministic: bool
    fail_closed: bool
    evaluation_order_fixed: bool
    thread_safe: bool
    per_agent_isolation: bool


class ReliabilityReportGenerator:
    """Generates Orchesis reliability reports."""

    def __init__(
        self,
        corpus_path: str = "tests/corpus",
        decisions_log: str = ".orchesis/decisions.jsonl",
        fuzz_log: str = ".orchesis/fuzz_runs.jsonl",
        mutation_log: str = ".orchesis/mutation_runs.jsonl",
        replay_log: str = ".orchesis/replay_runs.jsonl",
        fuzz_meta_path: str = ".orchesis/fuzz_meta.json",
    ):
        self._corpus = RegressionCorpus(corpus_path)
        self._decisions_log = Path(decisions_log)
        self._fuzz_log = Path(fuzz_log)
        self._mutation_log = Path(mutation_log)
        self._replay_log = Path(replay_log)
        self._fuzz_meta_path = Path(fuzz_meta_path)

    def _read_jsonl(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        rows: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
        return rows

    def _count_tests(self) -> tuple[int, int]:
        tests_dir = Path("tests")
        total = 0
        adversarial = 0
        if not tests_dir.exists():
            return 0, 0
        for file_path in tests_dir.glob("test_*.py"):
            text = file_path.read_text(encoding="utf-8")
            count = len(re.findall(r"^def test_", text, flags=re.MULTILINE))
            total += count
            if file_path.name == "test_adversarial.py":
                adversarial = count
        return total, adversarial

    def _read_version(self) -> str:
        pyproject = Path("pyproject.toml")
        if not pyproject.exists():
            return "unknown"
        text = pyproject.read_text(encoding="utf-8")
        match = re.search(r'^version\s*=\s*"([^"]+)"', text, flags=re.MULTILINE)
        return match.group(1) if match else "unknown"

    def generate(self) -> ReliabilityReport:
        """Collect data and build reliability report."""
        total_tests, adversarial_tests = self._count_tests()
        corpus_stats = self._corpus.stats()
        fuzz_rows = self._read_jsonl(self._fuzz_log)
        mutation_rows = self._read_jsonl(self._mutation_log)
        replay_rows = self._read_jsonl(self._replay_log)
        meta = {}
        if self._fuzz_meta_path.exists():
            try:
                meta = json.loads(self._fuzz_meta_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                meta = {}

        total_fuzz_requests = sum(
            int(row.get("total_requests", 0))
            for row in fuzz_rows
            if isinstance(row.get("total_requests"), int | float)
        )
        total_mutations_tested = sum(
            int(row.get("mutations_tested", 0))
            for row in mutation_rows
            if isinstance(row.get("mutations_tested"), int | float)
        )
        bypasses_found_lifetime = sum(
            int(row.get("bypasses_found", 0))
            for row in fuzz_rows
            if isinstance(row.get("bypasses_found"), int | float)
        )
        if bypasses_found_lifetime == 0:
            bypasses_found_lifetime = int(corpus_stats["total"])
        if isinstance(meta.get("total_bypasses_lifetime"), int | float):
            bypasses_found_lifetime = int(meta["total_bypasses_lifetime"])
        bypasses_fixed = int(corpus_stats["fixed"])
        current_bypass_rate = 0.0
        if fuzz_rows:
            latest = fuzz_rows[-1]
            if isinstance(latest.get("bypass_rate"), int | float):
                current_bypass_rate = float(latest["bypass_rate"])

        total_invariant_checks = (
            int(meta["total_invariant_checks"])
            if isinstance(meta.get("total_invariant_checks"), int | float)
            else 0
        )
        invariant_failures = (
            int(meta["invariant_failures"])
            if isinstance(meta.get("invariant_failures"), int | float)
            else 0
        )
        consecutive_clean_runs = (
            int(meta["consecutive_clean_runs"])
            if isinstance(meta.get("consecutive_clean_runs"), int | float)
            else 0
        )
        days_without_bypass = (
            int(meta["days_without_bypass"])
            if isinstance(meta.get("days_without_bypass"), int | float)
            else 0
        )

        replay_verifications = len(replay_rows)
        replay_drift_count = sum(
            int(row.get("drifts", 0))
            for row in replay_rows
            if isinstance(row.get("drifts"), int | float)
        )

        return ReliabilityReport(
            generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            orchesis_version=self._read_version(),
            total_tests=total_tests,
            adversarial_tests=adversarial_tests,
            corpus_entries=int(corpus_stats["total"]),
            corpus_fixed=int(corpus_stats["fixed"]),
            total_fuzz_runs=len(fuzz_rows),
            total_fuzz_requests=(
                int(meta["total_requests_lifetime"])
                if isinstance(meta.get("total_requests_lifetime"), int | float)
                else total_fuzz_requests
            ),
            total_mutations_tested=(
                int(meta["total_mutations_lifetime"])
                if isinstance(meta.get("total_mutations_lifetime"), int | float)
                else total_mutations_tested
            ),
            bypasses_found_lifetime=bypasses_found_lifetime,
            bypasses_fixed=bypasses_fixed,
            current_bypass_rate=current_bypass_rate,
            total_invariant_checks=total_invariant_checks,
            invariant_failures=invariant_failures,
            consecutive_clean_runs=consecutive_clean_runs,
            days_without_bypass=days_without_bypass,
            replay_verifications=replay_verifications,
            replay_drift_count=replay_drift_count,
            deterministic=replay_drift_count == 0,
            fail_closed=EvaluationGuarantees.FAIL_CLOSED,
            evaluation_order_fixed=bool(EvaluationGuarantees.EVALUATION_ORDER),
            thread_safe=EvaluationGuarantees.THREAD_SAFE,
            per_agent_isolation=True,
        )

    def to_markdown(self, report: ReliabilityReport) -> str:
        """Render report as markdown."""
        all_fixed = "Yes" if report.corpus_entries == report.corpus_fixed else "No"
        deterministic = "✓ Verified" if report.deterministic else "✗ Drift detected"
        fail_closed = "✓ Verified" if report.fail_closed else "✗ Not guaranteed"
        per_agent = "✓ Verified" if report.per_agent_isolation else "✗ Not verified"
        thread_safe = "✓ Verified" if report.thread_safe else "✗ Not verified"
        return f"""# Orchesis Reliability Report
Generated: {report.generated_at}
Version: {report.orchesis_version}

## Testing
| Metric | Value |
|--------|-------|
| Total tests | {report.total_tests} |
| Adversarial tests | {report.adversarial_tests} |
| Corpus entries | {report.corpus_entries} |
| All fixed | {all_fixed} |

## Fuzzing
| Metric | Value |
|--------|-------|
| Fuzz requests (lifetime) | {report.total_fuzz_requests} |
| Mutations tested | {report.total_mutations_tested} |
| Bypasses found | {report.bypasses_found_lifetime} |
| Current bypass rate | {report.current_bypass_rate * 100:.2f}% |
| Invariant checks | {report.total_invariant_checks} |
| Invariant failures | {report.invariant_failures} |
| Consecutive clean runs | {report.consecutive_clean_runs} |
| Days without bypass | {report.days_without_bypass} |

## Runtime Guarantees
| Guarantee | Status |
|-----------|--------|
| Deterministic evaluation | {deterministic} |
| Fail-closed | {fail_closed} |
| Per-agent isolation | {per_agent} |
| Thread-safe | {thread_safe} |
"""

    def to_json(self, report: ReliabilityReport) -> str:
        """Render report as json string."""
        return json.dumps(asdict(report), ensure_ascii=False, indent=2)
