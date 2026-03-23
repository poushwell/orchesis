from __future__ import annotations

from pathlib import Path

import pytest

from orchesis.config import load_policy
from orchesis.contrib.pii_detector import PiiDetector
from orchesis.contrib.secret_scanner import SecretScanner

pytestmark = pytest.mark.fuzz


def test_secret_scanner_binary_0xff() -> None:
    scanner = SecretScanner()
    data = b"\xff" * 7 + b"\x02" + b"\x00" * 3
    findings = scanner.scan_text(data)
    assert isinstance(findings, list)


def test_secret_scanner_null_bytes() -> None:
    scanner = SecretScanner()
    findings = scanner.scan_text(b"\x00" * 100)
    assert isinstance(findings, list)


def test_secret_scanner_mixed_binary() -> None:
    scanner = SecretScanner()
    findings = scanner.scan_text(b"api_key=\xff\xff\x00test")
    assert isinstance(findings, list)


def test_pii_detector_0x8a_repetition() -> None:
    detector = PiiDetector()
    findings = detector.detect(b"\x8a" * 100 + b"123-45-6789")
    assert isinstance(findings, list)


def test_pii_detector_mixed_binary_ssn() -> None:
    detector = PiiDetector()
    payload = (
        b">+2hhhhhh\x9b\x97\x97\x97hhh"
        + (b"\x8a" * 360)
        + b"123-45-6789"
        + b"\xff\xff"
        + b"\x01\x00"
        + (b"\xec\xb7\x8d" * 120)
        + (b"\x8a" * 20)
    )
    findings = detector.detect(payload)
    assert isinstance(findings, list)


def test_pii_detector_orphaned_continuation() -> None:
    detector = PiiDetector()
    findings = detector.detect(b"\xec\xb7\x8d" * 50)
    assert isinstance(findings, list)


def test_policy_yaml_0x8a(tmp_path: Path) -> None:
    policy_file = tmp_path / "fuzz_policy_8a.yaml"
    policy_file.write_bytes(b"s0x_:\n" + (b"\x8a" * 62) + b"\r\r\r")
    loaded = load_policy(policy_file)
    assert isinstance(loaded, dict)


def test_policy_yaml_null_in_yaml(tmp_path: Path) -> None:
    policy_file = tmp_path / "fuzz_policy_null.yaml"
    policy_file.write_bytes(b"key: val\x00ue\n")
    loaded = load_policy(policy_file)
    assert isinstance(loaded, dict)


def test_policy_yaml_pure_binary(tmp_path: Path) -> None:
    policy_file = tmp_path / "fuzz_policy_binary.yaml"
    policy_file.write_bytes(b"\xff" * 100)
    loaded = load_policy(policy_file)
    assert isinstance(loaded, dict)

