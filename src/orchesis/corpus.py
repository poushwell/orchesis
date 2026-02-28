"""Regression corpus manager for discovered bypasses."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import math
from pathlib import Path
from typing import Any

from orchesis.fuzzer import FuzzResult


@dataclass
class CorpusEntry:
    id: str
    category: str
    mutation: str
    request: dict[str, Any]
    expected_decision: str
    discovered_at: str
    fixed: bool = False
    fixed_at: str | None = None
    cve_reference: str | None = None


class RegressionCorpus:
    """Manages corpus of known attack patterns."""

    def __init__(self, corpus_path: str = "tests/corpus"):
        self.corpus_path = Path(corpus_path)
        self.corpus_path.mkdir(parents=True, exist_ok=True)

    def _entry_path(self, entry_id: str) -> Path:
        return self.corpus_path / f"{entry_id}.json"

    def _next_id(self) -> str:
        max_seen = 0
        for path in self.corpus_path.glob("BYPASS-*.json"):
            stem = path.stem
            try:
                number = int(stem.split("-", 1)[1])
            except (IndexError, ValueError):
                continue
            max_seen = max(max_seen, number)
        return f"BYPASS-{max_seen + 1:03d}"

    def add_bypass(self, result: FuzzResult) -> CorpusEntry:
        """Add bypass and persist JSON entry."""
        entry = CorpusEntry(
            id=self._next_id(),
            category=result.category,
            mutation=result.mutation,
            request=result.request,
            expected_decision="DENY",
            discovered_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            fixed=False,
        )
        self._entry_path(entry.id).write_text(
            json.dumps(asdict(entry), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return entry

    def load_all(self) -> list[CorpusEntry]:
        """Load all corpus entries."""
        entries: list[CorpusEntry] = []
        for path in sorted(self.corpus_path.glob("BYPASS-*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            try:
                entries.append(CorpusEntry(**payload))
            except TypeError:
                continue
        return entries

    def mark_fixed(self, entry_id: str) -> None:
        """Mark a bypass as fixed."""
        path = self._entry_path(entry_id)
        if not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(payload, dict):
            return
        payload["fixed"] = True
        payload["fixed_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def generate_test_file(self) -> str:
        """Generate regression test file from corpus entries."""
        target = self.corpus_path.parent / "test_corpus_regression.py"
        content = '''"""Auto-generated regression tests from attack corpus.
DO NOT EDIT MANUALLY. Regenerate with: orchesis corpus --generate-tests
"""
import json
import pytest
from pathlib import Path
from orchesis.engine import evaluate
from orchesis.config import load_policy

CORPUS_DIR = Path(__file__).parent / "corpus"
POLICY_PATH = Path(__file__).parent.parent / "examples" / "production_policy.yaml"

def _load_corpus_entries():
    entries = []
    for f in sorted(CORPUS_DIR.glob("BYPASS-*.json")):
        with f.open(encoding="utf-8") as fh:
            entries.append(json.load(fh))
    return entries

@pytest.mark.parametrize("entry", _load_corpus_entries(), ids=lambda e: e["id"])
def test_corpus_regression(entry):
    """Verify that known bypass is now correctly handled."""
    policy = load_policy(POLICY_PATH)
    decision = evaluate(entry["request"], policy)
    assert not decision.allowed, (
        f"{entry['id']} ({entry['category']}): "
        f"expected DENY but got ALLOW. "
        f"Mutation: {entry['mutation']}"
    )
'''
        target.write_text(content, encoding="utf-8")
        return str(target)

    def stats(self) -> dict[str, Any]:
        """Return aggregate corpus statistics."""
        entries = self.load_all()
        fixed = sum(1 for entry in entries if entry.fixed)
        by_category: dict[str, int] = {}
        for entry in entries:
            by_category[entry.category] = by_category.get(entry.category, 0) + 1
        return {
            "total": len(entries),
            "fixed": fixed,
            "unfixed": len(entries) - fixed,
            "by_category": by_category,
        }

    def quality_report(self) -> dict[str, Any]:
        """Analyze corpus quality and identify coverage gaps."""
        entries = self.load_all()
        total = len(entries)
        fixed = sum(1 for entry in entries if entry.fixed)
        categories: dict[str, int] = {}
        for entry in entries:
            categories[entry.category] = categories.get(entry.category, 0) + 1

        expected_categories = [
            "path_traversal",
            "sql_injection",
            "cost_manipulation",
            "identity_spoofing",
            "regex_evasion",
            "rate_limit",
            "composite",
        ]
        gaps = [name for name in expected_categories if categories.get(name, 0) == 0]

        if total == 0:
            balance = 0.0
        else:
            ideal = 1.0 / len(expected_categories)
            distance = 0.0
            for name in expected_categories:
                observed = categories.get(name, 0) / total
                distance += abs(observed - ideal)
            balance = max(0.0, 1.0 - (distance / 2.0))

        newest: datetime | None = None
        for entry in entries:
            raw = entry.discovered_at
            if not isinstance(raw, str):
                continue
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                continue
            newest = dt if newest is None else max(newest, dt)
        if newest is None:
            staleness_days = 0
        else:
            staleness_days = max(0, (datetime.now(timezone.utc) - newest).days)

        total_mutations = 0
        for entry in entries:
            request = entry.request if isinstance(entry.request, dict) else {}
            mutations = request.get("mutations")
            if isinstance(mutations, list):
                total_mutations += len(mutations)
        avg_mutations = (total_mutations / total) if total else 0.0

        suggestions: list[str] = []
        for gap in gaps:
            suggestions.append(f"Add {gap} bypass entries")
        if categories:
            threshold = max(1, math.ceil(total / (len(expected_categories) * 2)))
            for category, count in sorted(categories.items()):
                if count < threshold:
                    suggestions.append(f"{category} underrepresented ({count} entry)")

        return {
            "total_entries": total,
            "fixed": fixed,
            "unfixed": total - fixed,
            "categories": categories,
            "category_balance": round(balance, 2),
            "gaps": gaps,
            "staleness_days": staleness_days,
            "avg_mutations_per_entry": round(avg_mutations, 2),
            "suggestions": suggestions,
        }
