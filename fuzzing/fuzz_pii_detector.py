"""Fuzz PII detector with unicode-heavy edge cases."""

from __future__ import annotations

import sys

try:
    import atheris
except ImportError:
    print("Atheris not installed. Install with: pip install atheris")
    print("Recommended: use Linux or WSL2")
    sys.exit(1)

with atheris.instrument_imports():
    from orchesis.contrib.pii_detector import PiiDetector


def _fullwidth_digits(value: str) -> str:
    return "".join(chr(ord("０") + int(ch)) if ch.isdigit() else ch for ch in value)


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    detector = PiiDetector(use_fast_matching=True)

    base = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 2048))
    snippets = [
        "123-45-6789",
        "4111-1111-1111-1111",
        "user@example.com",
        "+1 202-555-0147",
        "测试abc@example.comمرحبا",
    ]
    seed = fdp.PickValueInList(snippets)
    text = base + " " + seed

    if fdp.ConsumeBool():
        text = text.replace("-", "\u200b-\u200b")
    if fdp.ConsumeBool():
        text = "\u202e" + text
    if fdp.ConsumeBool():
        text = _fullwidth_digits(text)
    if fdp.ConsumeBool():
        text = "漢字" + text + "العربية"

    try:
        findings = detector.scan_text(text)
    except (ValueError, TypeError, KeyError):
        return
    if not isinstance(findings, list):
        raise TypeError("PII detector must return a list")
    for item in findings:
        if not isinstance(item, dict):
            raise TypeError("PII detector list items must be dicts")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
