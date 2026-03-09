from __future__ import annotations

from typing import Any


def _load_pii_detector() -> Any:
    try:
        from orchesis.pii_detector import PiiDetector  # type: ignore
    except Exception:
        from orchesis.contrib.pii_detector import PiiDetector
    return PiiDetector


def _load_secret_scanner() -> Any:
    try:
        from orchesis.secret_scanner import SecretScanner  # type: ignore
    except Exception:
        from orchesis.contrib.secret_scanner import SecretScanner
    return SecretScanner


PII_CRASH_INPUT = (
    b"&C+8\xe6\xbc\xa2\xe5\xad\x97\xe2\xad\x83\xe3\xa4\xb8\xe1\x84\x85\xee\xa8\xb9"
    b"\xea\xb6\xb6\xeb\x9b\xaa +1 202-555-0147\xd8\xa7\xd9\x84\xd8\xb9\xd8\xb1\xd8\xa8"
    b"\xd9\x8a\xd8\xa9998\xd1999\xb79+9999998\xb783+99919,\xb999+9\xb7\xc7\xcb\xc6\xc655H"
)

SECRET_CRASH_INPUT = b"\x00\x00\xff\xff\x8c,u,\x00\x00\x88"


def test_pii_detector_fuzz_crash_regression() -> None:
    PiiDetector = _load_pii_detector()
    detector = PiiDetector(use_fast_matching=True)
    text = PII_CRASH_INPUT.decode("utf-8", errors="replace")
    findings = detector.scan_text(text)
    assert isinstance(findings, list)


def test_pii_detector_fuzz_crash_bytes_input() -> None:
    PiiDetector = _load_pii_detector()
    detector = PiiDetector(use_fast_matching=True)
    findings = detector.scan_text(PII_CRASH_INPUT)
    assert isinstance(findings, list)


def test_pii_detector_null_bytes() -> None:
    PiiDetector = _load_pii_detector()
    detector = PiiDetector(use_fast_matching=True)
    findings = detector.scan_text("\x00\x00\x00foo@example.com\x00")
    assert isinstance(findings, list)


def test_pii_detector_pure_binary() -> None:
    PiiDetector = _load_pii_detector()
    detector = PiiDetector(use_fast_matching=True)
    binary_blob = bytes(range(256))
    findings = detector.scan_text(binary_blob)
    assert isinstance(findings, list)


def test_secret_scanner_fuzz_crash_regression() -> None:
    SecretScanner = _load_secret_scanner()
    scanner = SecretScanner(use_fast_matching=True)
    text = SECRET_CRASH_INPUT.decode("utf-8", errors="replace")
    findings = scanner.scan_text(text)
    assert isinstance(findings, list)


def test_secret_scanner_fuzz_crash_bytes_input() -> None:
    SecretScanner = _load_secret_scanner()
    scanner = SecretScanner(use_fast_matching=True)
    findings = scanner.scan_text(SECRET_CRASH_INPUT)
    assert isinstance(findings, list)


def test_secret_scanner_null_bytes() -> None:
    SecretScanner = _load_secret_scanner()
    scanner = SecretScanner(use_fast_matching=True)
    findings = scanner.scan_text("\x00\x00\x00sk-proj-abcdefghijklmnopqrstuvwxyz1234567890\x00")
    assert isinstance(findings, list)


def test_secret_scanner_pure_binary() -> None:
    SecretScanner = _load_secret_scanner()
    scanner = SecretScanner(use_fast_matching=True)
    binary_blob = bytes(range(256))
    findings = scanner.scan_text(binary_blob)
    assert isinstance(findings, list)
