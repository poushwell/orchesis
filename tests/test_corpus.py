from __future__ import annotations

import ast
import json
from pathlib import Path

from orchesis.config import load_policy
from orchesis.corpus import RegressionCorpus
from orchesis.engine import evaluate
from orchesis.fuzzer import FuzzResult


def _sample_bypass() -> FuzzResult:
    return FuzzResult(
        request={"tool": "read_file", "params": {"path": "/etc/passwd"}, "cost": 0.1},
        decision_allowed=True,
        decision_reasons=[],
        expected_deny=True,
        is_bypass=True,
        category="path_traversal",
        mutation="sample_mutation",
    )


def test_corpus_add_and_load(tmp_path: Path) -> None:
    corpus = RegressionCorpus(str(tmp_path / "corpus"))
    added = corpus.add_bypass(_sample_bypass())
    loaded = corpus.load_all()
    assert len(loaded) == 1
    assert loaded[0].id == added.id
    assert loaded[0].category == "path_traversal"


def test_corpus_mark_fixed(tmp_path: Path) -> None:
    corpus = RegressionCorpus(str(tmp_path / "corpus"))
    added = corpus.add_bypass(_sample_bypass())
    corpus.mark_fixed(added.id)
    loaded = corpus.load_all()
    assert loaded[0].fixed is True
    assert loaded[0].fixed_at is not None


def test_corpus_generate_test_file(tmp_path: Path) -> None:
    corpus = RegressionCorpus(str(tmp_path / "corpus"))
    corpus.add_bypass(_sample_bypass())
    generated = Path(corpus.generate_test_file())
    assert generated.exists()
    source = generated.read_text(encoding="utf-8")
    ast.parse(source)


def test_corpus_stats(tmp_path: Path) -> None:
    corpus = RegressionCorpus(str(tmp_path / "corpus"))
    first = corpus.add_bypass(_sample_bypass())
    second = corpus.add_bypass(
        FuzzResult(
            request={"tool": "run_sql", "params": {"query": "DROP TABLE users"}, "cost": 0.1},
            decision_allowed=True,
            decision_reasons=[],
            expected_deny=True,
            is_bypass=True,
            category="sql_injection",
            mutation="sql_mutation",
        )
    )
    third = corpus.add_bypass(
        FuzzResult(
            request={"tool": "run_command", "params": {"command": "rm -rf /"}, "cost": 0.1},
            decision_allowed=True,
            decision_reasons=[],
            expected_deny=True,
            is_bypass=True,
            category="regex_evasion",
            mutation="regex_mutation",
        )
    )
    corpus.mark_fixed(first.id)
    corpus.mark_fixed(second.id)
    _ = third
    summary = corpus.stats()
    assert summary["total"] == 3
    assert summary["fixed"] == 2
    assert summary["unfixed"] == 1
    assert summary["by_category"]["path_traversal"] == 1


def test_corpus_seeded_entries_exist() -> None:
    corpus_dir = Path(__file__).parent / "corpus"
    files = sorted(corpus_dir.glob("BYPASS-*.json"))
    required = {f"BYPASS-{idx:03d}.json" for idx in range(1, 15)}
    present = {path.name for path in files}
    assert required.issubset(present)
    payloads = [json.loads((corpus_dir / name).read_text(encoding="utf-8")) for name in sorted(required)]
    assert all(item.get("fixed") is True for item in payloads)


def test_generated_regression_tests_pass(tmp_path: Path) -> None:
    source_corpus = Path(__file__).parent / "corpus"
    dest_corpus = tmp_path / "corpus"
    dest_corpus.mkdir(parents=True, exist_ok=True)
    for path in sorted(source_corpus.glob("BYPASS-*.json"))[:14]:
        (dest_corpus / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    corpus = RegressionCorpus(str(dest_corpus))
    generated = Path(corpus.generate_test_file())
    assert generated.exists()

    policy = load_policy(Path(__file__).parent.parent / "examples" / "production_policy.yaml")
    for file_path in sorted(dest_corpus.glob("BYPASS-*.json")):
        entry = json.loads(file_path.read_text(encoding="utf-8"))
        decision = evaluate(entry["request"], policy)
        assert decision.allowed is False
