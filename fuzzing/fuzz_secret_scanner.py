"""Fuzz secret scanner for ReDoS and evasion gaps."""

from __future__ import annotations

import base64
import sys
import time
import urllib.parse

try:
    import atheris
except ImportError:
    print("Atheris not installed. Install with: pip install atheris")
    print("Recommended: use Linux or WSL2")
    sys.exit(1)

with atheris.instrument_imports():
    from orchesis.contrib.secret_scanner import SECRET_PATTERNS, SecretScanner


_KNOWN_SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd",
    "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890",
]


def _to_homoglyphs(value: str) -> str:
    table = str.maketrans({"A": "А", "E": "Е", "O": "О", "a": "а", "e": "е", "o": "о"})
    return value.translate(table)


def _mutate_secret(secret: str, evasion_type: int) -> str:
    if evasion_type == 0:
        return secret
    if evasion_type == 1:
        return secret.replace("-", "-\n")
    if evasion_type == 2:
        return urllib.parse.quote(secret, safe="")
    if evasion_type == 3:
        return base64.b64encode(secret.encode("utf-8")).decode("ascii")
    if evasion_type == 4:
        return _to_homoglyphs(secret)
    if evasion_type == 5:
        return "noise_prefix_" + secret + "_noise_suffix"
    if evasion_type == 6:
        return "xxx\u200b" + secret + "\u200bzzz"
    return "random-" + secret + "-tail"


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    scanner = SecretScanner(use_fast_matching=True)

    # Part A: ReDoS detection on a random pattern.
    pattern_name = fdp.PickValueInList(list(SECRET_PATTERNS.keys()))
    compiled, _, _ = SECRET_PATTERNS[pattern_name]
    probe = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 4000))
    started = time.monotonic()
    _ = compiled.search(probe)
    elapsed = time.monotonic() - started
    if elapsed > 0.5:
        raise RuntimeError(f"Potential ReDoS in {pattern_name}: {elapsed:.3f}s")

    # Part B: Evasion testing.
    secret = fdp.PickValueInList(_KNOWN_SECRETS)
    evasion_type = fdp.ConsumeIntInRange(0, 7)
    mutated = _mutate_secret(secret, evasion_type)
    findings = scanner.scan_text(mutated)
    if evasion_type >= 5 and secret in mutated and not findings:
        raise AssertionError("FALSE NEGATIVE")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
