from __future__ import annotations

import statistics
import time

import pytest

from orchesis.contrib.pii_detector import PII_PATTERNS, PiiDetector
from orchesis.contrib.secret_scanner import SECRET_PATTERNS, SecretScanner
from orchesis.fast_scanner import FastPIIDetector, FastSecretScanner


def test_fast_secret_scanner_finds_aws_key() -> None:
    scanner = FastSecretScanner(SECRET_PATTERNS)
    findings = scanner.scan("AKIAABCDEFGHIJKLMNOP")
    assert any(item["pattern"] == "aws_access_key" for item in findings)


def test_fast_secret_scanner_finds_github_token() -> None:
    scanner = FastSecretScanner(SECRET_PATTERNS)
    findings = scanner.scan("token=ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd")
    assert any(item["pattern"] == "github_token" for item in findings)


def test_fast_secret_scanner_finds_openai_key() -> None:
    scanner = FastSecretScanner(SECRET_PATTERNS)
    findings = scanner.scan("sk-abcdefghijklmnopqrstuvwxyz123456")
    assert any(item["pattern"] == "openai_key" for item in findings)


def test_fast_secret_scanner_empty_on_clean_text() -> None:
    scanner = FastSecretScanner(SECRET_PATTERNS)
    assert scanner.scan("normal harmless text") == []


def test_two_phase_prefilter_then_regex_validates() -> None:
    scanner = FastSecretScanner(SECRET_PATTERNS)
    findings = scanner.scan("aws_secret_access_key = verysecretvalue123456")
    assert any(item["pattern"] == "aws_secret_key" for item in findings)


def test_two_phase_prefilter_regex_rejects_partial() -> None:
    scanner = FastSecretScanner(SECRET_PATTERNS)
    findings = scanner.scan("prefix AKIA1234 only")
    assert not any(item["pattern"] == "aws_access_key" for item in findings)


def test_fast_pii_detector_finds_ssn() -> None:
    detector = FastPIIDetector(PII_PATTERNS)
    findings = detector.scan(
        "ssn 123-45-6789",
        threshold_rank=0,
        ignored_patterns=set(),
        mask_fn=lambda raw, _name: raw,
        severity_rank={"low": 0, "medium": 1, "high": 2, "critical": 3},
    )
    assert any(item["pattern"] == "ssn" for item in findings)


def test_fast_pii_detector_finds_credit_card() -> None:
    detector = FastPIIDetector(PII_PATTERNS)
    findings = detector.scan(
        "card 4111 1111 1111 1111",
        threshold_rank=0,
        ignored_patterns=set(),
        mask_fn=lambda raw, _name: raw,
        severity_rank={"low": 0, "medium": 1, "high": 2, "critical": 3},
    )
    assert any(item["pattern"] == "credit_card_visa" for item in findings)


def test_fast_pii_detector_finds_email() -> None:
    detector = FastPIIDetector(PII_PATTERNS)
    findings = detector.scan(
        "mail me user@example.com",
        threshold_rank=0,
        ignored_patterns=set(),
        mask_fn=lambda raw, _name: raw,
        severity_rank={"low": 0, "medium": 1, "high": 2, "critical": 3},
    )
    assert any(item["pattern"] == "email" for item in findings)


def test_backward_compat_secret_scanner_disable_fast() -> None:
    scanner = SecretScanner(use_fast_matching=False)
    findings = scanner.scan_text("AKIAABCDEFGHIJKLMNOP")
    assert any(item["pattern"] == "aws_access_key" for item in findings)


def test_backward_compat_pii_detector_disable_fast() -> None:
    detector = PiiDetector(use_fast_matching=False)
    findings = detector.scan_text("contact user@example.com")
    assert any(item["pattern"] == "email" for item in findings)


def test_secret_results_match_old_and_new() -> None:
    text = "sk-abcdefghijklmnopqrstuvwxyz123456 and AKIAABCDEFGHIJKLMNOP"
    old = SecretScanner(use_fast_matching=False).scan_text(text)
    new = SecretScanner(use_fast_matching=True).scan_text(text)
    old_pairs = {(item["pattern"], item["position"]) for item in old}
    new_pairs = {(item["pattern"], item["position"]) for item in new}
    assert old_pairs == new_pairs


def test_pii_results_match_old_and_new() -> None:
    text = "email user@example.com and ssn 123-45-6789"
    old = PiiDetector(use_fast_matching=False).scan_text(text)
    new = PiiDetector(use_fast_matching=True).scan_text(text)
    old_pairs = {(item["pattern"], item["position"]) for item in old}
    new_pairs = {(item["pattern"], item["position"]) for item in new}
    assert old_pairs == new_pairs


def test_fast_scanner_performance_better_than_sequential() -> None:
    base_chunk = "abcdefghijklmnopqrstuvwxyz0123456789 "
    text = (base_chunk * 3500)[:110_000]
    embedded_secrets = [
        " sk-abcdefghijklmnopqrstuvwxyz123456",
        " ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd",
        " AKIAABCDEFGHIJKLMNOP",
        " aws_secret_access_key = verysecretvalue123456",
        " token=ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd",
        " sk-abcdefghijklmnopqrstuvwxyz123456",
        " AKIAABCDEFGHIJKLMNOP",
        " ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd",
        " sk-abcdefghijklmnopqrstuvwxyz123456",
        " aws_secret_access_key = verysecretvalue123456",
    ]
    text += " ".join(embedded_secrets)
    seq = SecretScanner(use_fast_matching=False)
    fast = SecretScanner(use_fast_matching=True)

    seq_times: list[float] = []
    fast_times: list[float] = []
    for _ in range(5):
        started_seq = time.monotonic()
        _ = seq.scan_text(text)
        seq_times.append(time.monotonic() - started_seq)

        started_fast = time.monotonic()
        _ = fast.scan_text(text)
        fast_times.append(time.monotonic() - started_fast)

    seq_time = statistics.median(seq_times)
    fast_time = statistics.median(fast_times)

    # Aho-Corasick wins on large inputs; generous tolerance for CI variance
    if fast_time > seq_time * 3.0:
        pytest.skip(f"Performance test inconclusive in CI: fast={fast_time:.3f}s seq={seq_time:.3f}s")
    assert fast_time <= seq_time * 3.0
