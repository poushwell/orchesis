"""Auto-generated regression tests from attack corpus.
DO NOT EDIT MANUALLY. Regenerate with: orchesis corpus --generate-tests
"""

import json
from pathlib import Path

import pytest

from orchesis.config import load_policy
from orchesis.engine import evaluate

CORPUS_DIR = Path(__file__).parent / "corpus"
POLICY_PATH = Path(__file__).parent.parent / "examples" / "production_policy.yaml"


def _load_corpus_entries():
    entries = []
    for file_path in sorted(CORPUS_DIR.glob("BYPASS-*.json")):
        with file_path.open(encoding="utf-8") as handle:
            entries.append(json.load(handle))
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
