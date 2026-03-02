from __future__ import annotations

from orchesis.ahocorasick import AhoCorasickMatcher


def test_single_pattern_found() -> None:
    matcher = AhoCorasickMatcher({"p1": "secret"})
    matches = matcher.search("my secret here")
    assert len(matches) == 1
    assert matches[0].pattern_id == "p1"


def test_single_pattern_not_found() -> None:
    matcher = AhoCorasickMatcher({"p1": "secret"})
    assert matcher.search("clean text") == []


def test_multiple_patterns_all_found() -> None:
    matcher = AhoCorasickMatcher({"a": "alpha", "b": "beta", "g": "gamma"})
    text = "alpha beta gamma"
    ids = [item.pattern_id for item in matcher.search(text)]
    assert {"a", "b", "g"}.issubset(set(ids))


def test_multiple_patterns_some_found() -> None:
    matcher = AhoCorasickMatcher({"a": "alpha", "b": "beta"})
    ids = [item.pattern_id for item in matcher.search("alpha only")]
    assert "a" in ids
    assert "b" not in ids


def test_overlapping_matches_he_her() -> None:
    matcher = AhoCorasickMatcher({"he": "he", "her": "her"})
    matches = matcher.search("her")
    found = {(item.pattern_id, item.start, item.end) for item in matches}
    assert ("he", 0, 2) in found
    assert ("her", 0, 3) in found


def test_empty_text() -> None:
    matcher = AhoCorasickMatcher({"a": "x"})
    assert matcher.search("") == []


def test_empty_patterns() -> None:
    matcher = AhoCorasickMatcher({})
    assert matcher.search("anything") == []


def test_unicode_patterns_cyrillic() -> None:
    matcher = AhoCorasickMatcher({"ru": "привет"})
    matches = matcher.search("мир привет мир")
    assert len(matches) == 1
    assert matches[0].matched_text == "привет"


def test_unicode_patterns_cjk() -> None:
    matcher = AhoCorasickMatcher({"cjk": "安全"})
    matches = matcher.search("这是安全测试")
    assert matches and matches[0].pattern_id == "cjk"


def test_unicode_patterns_emoji() -> None:
    matcher = AhoCorasickMatcher({"em": "🔒"})
    matches = matcher.search("token 🔒 hidden")
    assert len(matches) == 1


def test_case_insensitive_matching() -> None:
    matcher = AhoCorasickMatcher({"a": "Secret"}, case_insensitive=True)
    matches = matcher.search("my secret")
    assert len(matches) == 1
    assert matches[0].pattern_id == "a"


def test_very_long_text() -> None:
    matcher = AhoCorasickMatcher({"x": "needle"})
    text = ("a" * 100_000) + "needle"
    matches = matcher.search(text)
    assert len(matches) == 1
    assert matches[0].start == 100_000


def test_pattern_start_middle_end() -> None:
    matcher = AhoCorasickMatcher({"s": "start", "m": "middle", "e": "end"})
    matches = matcher.search("start and middle and end")
    ids = [m.pattern_id for m in matches]
    assert "s" in ids and "m" in ids and "e" in ids


def test_search_first_returns_first_match() -> None:
    matcher = AhoCorasickMatcher({"a": "alpha", "b": "beta"})
    first = matcher.search_first("zz alpha then beta")
    assert first is not None
    assert first.pattern_id == "a"


def test_duplicate_patterns_different_ids() -> None:
    matcher = AhoCorasickMatcher({"a1": "key", "a2": "key"})
    matches = matcher.search("key")
    ids = sorted(item.pattern_id for item in matches)
    assert ids == ["a1", "a2"]
