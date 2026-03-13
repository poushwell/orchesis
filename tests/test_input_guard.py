from __future__ import annotations

from orchesis.input_guard import is_valid_text, sanitize_text


def test_sanitize_none_returns_none() -> None:
    assert sanitize_text(None) is None


def test_sanitize_empty_string_returns_none() -> None:
    assert sanitize_text("") is None


def test_sanitize_whitespace_only_returns_none() -> None:
    assert sanitize_text("   \n\t  ") is None


def test_sanitize_bytes_valid_utf8() -> None:
    assert sanitize_text("hello".encode("utf-8")) == "hello"


def test_sanitize_bytes_invalid_utf8() -> None:
    out = sanitize_text(b"\xff\xfehello")
    assert isinstance(out, str)
    assert "hello" in out


def test_sanitize_integer_returns_none() -> None:
    assert sanitize_text(123) is None


def test_sanitize_normal_text_unchanged() -> None:
    assert sanitize_text("normal text 123") == "normal text 123"


def test_sanitize_null_bytes_stripped() -> None:
    assert sanitize_text("\x00ab\x00cd\x00") == "abcd"


def test_sanitize_control_chars_stripped() -> None:
    out = sanitize_text("ab\x01\x02cd\x03")
    assert out == "abcd"


def test_sanitize_newlines_preserved() -> None:
    out = sanitize_text("a\nb\nc")
    assert out == "a\nb\nc"


def test_sanitize_tabs_preserved() -> None:
    out = sanitize_text("a\tb\tc")
    assert out == "a\tb\tc"


def test_sanitize_surrogate_pairs_stripped() -> None:
    out = sanitize_text("a\ud800b\udfffc")
    assert out == "abc"


def test_sanitize_cjk_text_preserved() -> None:
    out = sanitize_text("漢字 テスト 한국어")
    assert out == "漢字 テスト 한국어"


def test_sanitize_emoji_preserved() -> None:
    out = sanitize_text("safe 😀 text")
    assert out == "safe 😀 text"


def test_sanitize_mixed_valid_invalid() -> None:
    out = sanitize_text("\x00ok\x01\n\t\ud800done")
    assert out == "ok\n\tdone"


def test_sanitize_very_long_text() -> None:
    text = ("a" * 100_000) + "\x00\x01" + ("b" * 100_000)
    out = sanitize_text(text)
    assert isinstance(out, str)
    assert "\x00" not in out
    assert len(out) >= 200_000


def test_sanitize_repeated_ffff() -> None:
    text = "abc" + ("\uffff" * 50) + "xyz"
    out = sanitize_text(text)
    assert isinstance(out, str)
    assert out.startswith("abc")
    assert out.endswith("xyz")


def test_is_valid_text_true() -> None:
    assert is_valid_text("hello")


def test_is_valid_text_false_none() -> None:
    assert not is_valid_text(None)


def test_is_valid_text_false_bytes() -> None:
    assert not is_valid_text(b"hello")


def test_is_valid_text_false_empty() -> None:
    assert not is_valid_text("")

