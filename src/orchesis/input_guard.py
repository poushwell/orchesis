"""Defensive input validation for text-processing modules."""

from __future__ import annotations


def sanitize_text(text: object) -> str | None:
    """Sanitize text input for downstream scanners/detectors.

    Returns sanitized string, or None if input is not processable text.
    """

    if text is None:
        return None

    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8", errors="replace")
        except Exception:
            return None

    if not isinstance(text, str):
        return None

    if not text or not text.strip():
        return None

    text = text.replace("\x00", "")

    cleaned: list[str] = []
    for ch in text:
        code = ord(ch)
        if code < 32 and ch not in ("\n", "\r", "\t"):
            continue
        if 0xD800 <= code <= 0xDFFF:
            continue
        cleaned.append(ch)
    text = "".join(cleaned)

    if not text.strip():
        return None
    return text


def is_valid_text(text: object) -> bool:
    """Quick check if input is valid processable text.

    Bytes are treated as invalid for this quick-path check.
    """

    if not isinstance(text, str):
        return False
    return sanitize_text(text) is not None

