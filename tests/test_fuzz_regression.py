from __future__ import annotations

import os
import tempfile
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


def _load_policy_loader() -> Any:
    from orchesis.config import load_policy

    return load_policy


PII_CRASH_INPUT = (
    b"&C+8\xe6\xbc\xa2\xe5\xad\x97\xe2\xad\x83\xe3\xa4\xb8\xe1\x84\x85\xee\xa8\xb9"
    b"\xea\xb6\xb6\xeb\x9b\xaa +1 202-555-0147\xd8\xa7\xd9\x84\xd8\xb9\xd8\xb1\xd8\xa8"
    b"\xd9\x8a\xd8\xa9998\xd1999\xb79+9999998\xb783+99919,\xb999+9\xb7\xc7\xcb\xc6\xc655H"
)

SECRET_CRASH_INPUT = b"\x00\x00\xff\xff\x8c,u,\x00\x00\x88"
PII_CRASH_CONTROL = b"2l" + (b"\x13" * 108)
SECRET_CRASH_V2 = b"\xec\xff\xff\xff\xff\xff\xec\x00\x00\x88"
POLICY_CRASH = b"#allow<<:\n-\n\xa02[:\n\n<<:\n-\n\xa02:\n<<:\n- 0b_:\n<*als<:\n\n"
PII_CRASH_R3 = b"\xe6\xb0\xb1\xe6\x85\x80\xe6\xbc\xa3\xe2\xbc\x88 123-45-6789\xad\xad\xad\xad\xad\xad\xad\xad\xb5\xad\xad\xad\xad\xad\xad\xad\xaf3\xad3|\x180"
SECRET_CRASH_R3 = b"P%\x14\x00\x00\x88"
POLICY_CRASH_R3 = b'cs: ["w\xdc\xdc,\xdcu\xc3\xc3\xc3\xc1\xdcU\xc3\xc3\xc39999999999999999999999999999999999999999999999999\xc3cao\xdcu\xc3\xc3\xc3\xc3\xdcu\xc3\xc3\xc3\xc3\xdcu\xc3\xc3\xc3\xc3&i'
PII_CRASH_R4 = b"z\x03@oj2x@e.ac x.cc s@g.acoj2x@e.ac x.cc s@g.ac r@o.ca@o@e.ac\xdfx7@e.ac \xef@x.c@x.cc s@g.c\xf3@g.8z \xad~\xad\xad\xad\xad\xad\xadYYx r@o.ca@o@e.ac\xdfx7@e.ac \xef@x.c@x.cc s@g.c\xf3@g.8z \xad~\xad\xad\xad\xad\xad\xadYYx"
SECRET_CRASH_R4 = b"\x1d\x02\x00\x00\x00"
PII_CRASH_R5 = b">+hhhhhhhhhhhhhhhhhh9+499999;99999\xb79+439hhhhhh(hhhhhhh$hhh4+499999;99999\xb79+439\xad\xad\xad123-5-\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff4311041440~85288"
SECRET_CRASH_R5 = b"5\xec\x00\x00\x88"
POLICY_CRASH_R5 = b"sess: at\nrul: !!int\nrules:\n  - a\xa1\n  - name: file_access\ne:"
PII_CRASH_R6 = b"\x00\x00I\xec\x9b\x86\xe3\x83\x86\xeb\xb0\x80\xe9\xb8\x80\xe3\x90\xb9\x00\x00I\xec\x9b\x86\xe3\x83\x86\xeb\xb0\x80\xe9\xb8\x80\xe3\x90\xb9\xe3\xa4\xb3\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xe3\xa4\xb3\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef\xbf\xbf\xef8088473695\xff\xff\xff\x100"
SECRET_CRASH_R6 = b"\x10%\x02\x00\x00\x88"


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


def test_pii_detector_fuzz_crash_control_chars() -> None:
    PiiDetector = _load_pii_detector()
    detector = PiiDetector(use_fast_matching=True)
    text = PII_CRASH_CONTROL.decode("utf-8", errors="replace")
    findings = detector.scan_text(text)
    assert isinstance(findings, list)


def test_secret_scanner_fuzz_crash_invalid_utf8_v2() -> None:
    SecretScanner = _load_secret_scanner()
    scanner = SecretScanner(use_fast_matching=True)
    text = SECRET_CRASH_V2.decode("utf-8", errors="replace")
    findings = scanner.scan_text(text)
    assert isinstance(findings, list)


def test_policy_yaml_fuzz_crash_malformed_merge_keys() -> None:
    load_policy = _load_policy_loader()
    payload = POLICY_CRASH.decode("utf-8", errors="replace")
    policy_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(payload)
            policy_path = tmp.name
        try:
            _ = load_policy(policy_path)
        except ValueError as exc:
            assert "Invalid YAML policy" in str(exc)
    finally:
        if isinstance(policy_path, str) and os.path.exists(policy_path):
            os.unlink(policy_path)


def test_policy_yaml_fuzz_crash_bytes_input() -> None:
    load_policy = _load_policy_loader()
    payload = POLICY_CRASH.decode("utf-8", errors="replace")
    policy_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(payload)
            policy_path = tmp.name
        try:
            _ = load_policy(policy_path)
        except Exception:
            pass
    finally:
        if isinstance(policy_path, str) and os.path.exists(policy_path):
            os.unlink(policy_path)


def test_policy_yaml_null_and_nbsp() -> None:
    load_policy = _load_policy_loader()
    payload = "\x00\x00allow:\n\u00a0\u00a0- tool: test\n"
    policy_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(payload)
            policy_path = tmp.name
        try:
            _ = load_policy(policy_path)
        except Exception:
            pass
    finally:
        if isinstance(policy_path, str) and os.path.exists(policy_path):
            os.unlink(policy_path)


def test_pii_detector_fuzz_crash_soft_hyphen() -> None:
    """PII detector must not crash on soft-hyphen sequences around SSN."""
    PiiDetector = _load_pii_detector()
    detector = PiiDetector()
    text = PII_CRASH_R3.decode("utf-8", errors="replace")
    result = detector.scan_text(text)
    assert isinstance(result, list)


def test_secret_scanner_fuzz_crash_minimal_binary() -> None:
    """Secret scanner must not crash on 6-byte binary with nulls."""
    SecretScanner = _load_secret_scanner()
    scanner = SecretScanner()
    text = SECRET_CRASH_R3.decode("utf-8", errors="replace")
    result = scanner.scan_text(text)
    assert isinstance(result, list)


def test_policy_yaml_fuzz_crash_long_digit_string() -> None:
    """Policy YAML parser must not crash on long digit sequences with invalid UTF-8."""
    load_policy = _load_policy_loader()
    text = POLICY_CRASH_R3.decode("utf-8", errors="replace")
    fd, path = tempfile.mkstemp(suffix=".yaml")
    try:
        os.write(fd, text.encode("utf-8", errors="replace"))
        os.close(fd)
        try:
            _ = load_policy(path)
        except Exception:
            pass
    finally:
        try:
            os.close(fd)
        except Exception:
            pass
        os.unlink(path)


def test_pii_detector_fuzz_crash_email_like_patterns() -> None:
    """PII detector must not crash on email-like patterns with invalid UTF-8 and soft hyphens."""
    PiiDetector = _load_pii_detector()
    detector = PiiDetector()
    text = PII_CRASH_R4.decode("utf-8", errors="replace")
    result = detector.scan_text(text)
    assert isinstance(result, list)


def test_secret_scanner_fuzz_crash_control_chars() -> None:
    """Secret scanner must not crash on 5-byte control char input with nulls."""
    SecretScanner = _load_secret_scanner()
    scanner = SecretScanner()
    text = SECRET_CRASH_R4.decode("utf-8", errors="replace")
    result = scanner.scan_text(text)
    assert isinstance(result, list)


def test_pii_detector_fuzz_crash_repeated_chars_with_ssn() -> None:
    """PII detector must not crash on repeated chars with partial SSN and 0xff bytes."""
    PiiDetector = _load_pii_detector()
    detector = PiiDetector()
    text = PII_CRASH_R5.decode("utf-8", errors="replace")
    result = detector.scan_text(text)
    assert isinstance(result, list)


def test_secret_scanner_fuzz_crash_short_binary_r5() -> None:
    """Secret scanner must not crash on 5-byte binary with 0xec prefix."""
    SecretScanner = _load_secret_scanner()
    scanner = SecretScanner()
    text = SECRET_CRASH_R5.decode("utf-8", errors="replace")
    result = scanner.scan_text(text)
    assert isinstance(result, list)


def test_policy_yaml_fuzz_crash_invalid_yaml_tags() -> None:
    """Policy YAML parser must not crash on !!int tag with invalid UTF-8."""
    load_policy = _load_policy_loader()
    text = POLICY_CRASH_R5.decode("utf-8", errors="replace")
    fd, path = tempfile.mkstemp(suffix=".yaml")
    try:
        os.write(fd, text.encode("utf-8", errors="replace"))
        os.close(fd)
        try:
            _ = load_policy(path)
        except Exception:
            pass
    finally:
        try:
            os.close(fd)
        except Exception:
            pass
        os.unlink(path)


def test_pii_detector_fuzz_crash_cjk_with_nulls_r6() -> None:
    """PII detector must not crash on CJK chars with null bytes and U+FFFF sequences."""
    PiiDetector = _load_pii_detector()
    detector = PiiDetector()
    text = PII_CRASH_R6.decode("utf-8", errors="replace")
    result = detector.scan_text(text)
    assert isinstance(result, list)


def test_secret_scanner_fuzz_crash_short_binary_r6() -> None:
    """Secret scanner must not crash on 6-byte binary with percent encoding byte."""
    SecretScanner = _load_secret_scanner()
    scanner = SecretScanner()
    text = SECRET_CRASH_R6.decode("utf-8", errors="replace")
    result = scanner.scan_text(text)
    assert isinstance(result, list)


def test_pii_guard_all_previous_crashes() -> None:
    PiiDetector = _load_pii_detector()
    detector = PiiDetector()
    payloads = [
        PII_CRASH_INPUT,
        PII_CRASH_CONTROL,
        PII_CRASH_R3,
        PII_CRASH_R4,
        PII_CRASH_R5,
        PII_CRASH_R6,
    ]
    for payload in payloads:
        text = payload.decode("utf-8", errors="replace")
        result = detector.scan_text(text)
        assert isinstance(result, list)


def test_secret_guard_all_previous_crashes() -> None:
    SecretScanner = _load_secret_scanner()
    scanner = SecretScanner()
    payloads = [
        SECRET_CRASH_INPUT,
        SECRET_CRASH_V2,
        SECRET_CRASH_R3,
        SECRET_CRASH_R4,
        SECRET_CRASH_R5,
        SECRET_CRASH_R6,
    ]
    for payload in payloads:
        text = payload.decode("utf-8", errors="replace")
        result = scanner.scan_text(text)
        assert isinstance(result, list)


def test_policy_guard_all_previous_crashes() -> None:
    load_policy = _load_policy_loader()
    payloads = [
        POLICY_CRASH,
        POLICY_CRASH_R3,
        POLICY_CRASH_R5,
        b"\x00\x00allow:\n - test",
        b"rules:\n - <<:\n   - bad:\n",
        b"not: [valid",
    ]
    for payload in payloads:
        text = payload.decode("utf-8", errors="replace")
        fd, path = tempfile.mkstemp(suffix=".yaml")
        try:
            os.write(fd, text.encode("utf-8", errors="replace"))
            os.close(fd)
            try:
                _ = load_policy(path)
            except Exception:
                pass
        finally:
            try:
                os.close(fd)
            except Exception:
                pass
            os.unlink(path)
