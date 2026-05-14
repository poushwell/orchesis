"""Tests for orchesis.canonical — JCS + N1-N7 canonical form."""

from __future__ import annotations

import hashlib
import json

import pytest

from orchesis.canonical import (
    CanonicalError,
    MAX_OUTPUT_AMPLIFICATION,
    canonicalize,
    canonicalize_documents,
    canonicalize_messages,
    canonicalize_tools,
    canonicalize_with_offsets,
    jcs_encode,
    nfc,
    normalize_text,
    parse_sections,
    split_records,
)


# ---------------------------------------------------------------------------
# N2 NFC
# ---------------------------------------------------------------------------


class TestNFC:
    def test_combining_to_precomposed(self):
        # 'é' as 'e' + combining acute (U+0065 U+0301) → 'é' (U+00E9)
        decomposed = "é"
        assert nfc(decomposed) == "é"
        assert len(nfc(decomposed)) == 1

    def test_already_nfc(self):
        assert nfc("hello") == "hello"


# ---------------------------------------------------------------------------
# N1 whitespace
# ---------------------------------------------------------------------------


class TestNormalizeText:
    def test_collapse_internal_spaces(self):
        assert normalize_text("a   b\t\tc") == "a b c"

    def test_strip_trailing_whitespace(self):
        assert normalize_text("hello   \nworld\t\n") == "hello\nworld"

    def test_collapse_blank_lines(self):
        text = "a\n\n\n\nb"
        assert normalize_text(text) == "a\n\nb"

    def test_normalize_line_endings(self):
        assert normalize_text("a\r\nb\rc\nd") == "a\nb\nc\nd"

    def test_strip_outer_whitespace(self):
        assert normalize_text("\n\n  hello  \n\n") == "hello"

    def test_nbsp_collapsed_outside_fence(self):
        # NBSP (U+00A0) survives NFC; should be collapsed by N1.
        assert normalize_text("a  b") == "a b"

    def test_code_fence_preserves_whitespace(self):
        text = "before\n```python\n  indented   code\n    more  spaces\n```\nafter"
        out = normalize_text(text)
        # Inside fence: spaces preserved.
        assert "  indented   code" in out
        assert "    more  spaces" in out

    def test_code_fence_with_tildes_not_special(self):
        # We only recognize backtick fences per SPEC.
        text = "~~~\n  spaces  \n~~~"
        out = normalize_text(text)
        assert "spaces" in out
        # Spaces collapsed because not a recognized fence
        assert "  spaces  " not in out

    def test_fence_with_more_ticks_closer_required(self):
        text = "````python\ncontent ```still inside\n````"
        out = normalize_text(text)
        assert "content ```still inside" in out

    def test_rejects_non_str(self):
        with pytest.raises(CanonicalError):
            normalize_text(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# JCS — happy paths
# ---------------------------------------------------------------------------


class TestJCSBasics:
    def test_null(self):
        assert jcs_encode(None) == b"null"

    def test_bool(self):
        assert jcs_encode(True) == b"true"
        assert jcs_encode(False) == b"false"

    def test_simple_string(self):
        assert jcs_encode("hello") == b'"hello"'

    def test_string_with_quote(self):
        assert jcs_encode('say "hi"') == b'"say \\"hi\\""'

    def test_string_with_backslash(self):
        assert jcs_encode("a\\b") == b'"a\\\\b"'

    def test_string_control_chars(self):
        assert jcs_encode("\b") == b'"\\b"'
        assert jcs_encode("\t") == b'"\\t"'
        assert jcs_encode("\n") == b'"\\n"'
        assert jcs_encode("\f") == b'"\\f"'
        assert jcs_encode("\r") == b'"\\r"'
        assert jcs_encode("\x00") == b'"\\u0000"'
        assert jcs_encode("\x1f") == b'"\\u001f"'

    def test_unicode_above_001f_emitted_as_is(self):
        # Per RFC 8785: characters above U+001F (except " and \) emit as UTF-8.
        assert jcs_encode("漢字") == "\"漢字\"".encode("utf-8")
        assert jcs_encode("é") == "\"é\"".encode("utf-8")

    def test_empty_object(self):
        assert jcs_encode({}) == b"{}"

    def test_empty_array(self):
        assert jcs_encode([]) == b"[]"


class TestJCSNumbers:
    @pytest.mark.parametrize("value,expected", [
        (0, "0"),
        (1, "1"),
        (-1, "-1"),
        (100, "100"),
        (-100, "-100"),
        (0.0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (1.5, "1.5"),
        (-1.5, "-1.5"),
        (0.1, "0.1"),
        (0.001, "0.001"),
        (0.0000001, "1e-7"),    # n=-6 → scientific
        (0.000001, "0.000001"),  # n=-5 → fixed
        (100.0, "100"),
        (1e20, "100000000000000000000"),  # n=21, fixed
        (1e21, "1e+21"),
        (1.5e21, "1.5e+21"),
    ])
    def test_number_format(self, value, expected):
        assert jcs_encode(value) == expected.encode("ascii")

    def test_nan_rejected(self):
        with pytest.raises(CanonicalError, match="NaN"):
            jcs_encode(float("nan"))

    def test_inf_rejected(self):
        with pytest.raises(CanonicalError, match="Infinity"):
            jcs_encode(float("inf"))

    def test_large_int_rejected(self):
        with pytest.raises(CanonicalError, match="safe range"):
            jcs_encode(2 ** 60)


class TestJCSObjectSort:
    def test_keys_sorted_lex_utf16(self):
        out = jcs_encode({"b": 1, "a": 2})
        assert out == b'{"a":2,"b":1}'

    def test_nested_object(self):
        out = jcs_encode({"z": {"b": 1, "a": 2}, "y": 3})
        assert out == b'{"y":3,"z":{"a":2,"b":1}}'

    def test_array_order_preserved(self):
        assert jcs_encode([3, 1, 2]) == b"[3,1,2]"

    def test_non_string_key_rejected(self):
        with pytest.raises(CanonicalError, match="key must be str"):
            jcs_encode({1: "a"})


class TestJCSDeterminism:
    def test_two_dicts_same_order(self):
        a = {"x": [1, 2, 3], "y": {"b": True, "a": None}}
        b = {"y": {"a": None, "b": True}, "x": [1, 2, 3]}
        assert jcs_encode(a) == jcs_encode(b)


class TestJCSDepthLimit:
    def test_deep_nesting_rejected(self):
        obj: dict | list = []
        for _ in range(250):
            obj = [obj]
        with pytest.raises(CanonicalError, match="depth"):
            jcs_encode(obj)


# ---------------------------------------------------------------------------
# N4 tools
# ---------------------------------------------------------------------------


class TestCanonicalizeTools:
    def test_single_tool(self):
        recs = canonicalize_tools([
            {"name": "search", "description": "find  things", "parameters": {"type": "object"}}
        ])
        assert len(recs) == 1
        # Description collapsed: "find  things" → "find things"
        decoded = json.loads(recs[0])
        assert decoded["description"] == "find things"

    def test_sorted_lex_by_name(self):
        recs = canonicalize_tools([
            {"name": "zebra", "parameters": {}},
            {"name": "apple", "parameters": {}},
            {"name": "mango", "parameters": {}},
        ])
        names = [json.loads(r)["name"] for r in recs]
        assert names == ["apple", "mango", "zebra"]

    def test_duplicate_name_rejected(self):
        with pytest.raises(CanonicalError, match="duplicate"):
            canonicalize_tools([
                {"name": "x", "parameters": {}},
                {"name": "x", "parameters": {}},
            ])

    def test_missing_name(self):
        with pytest.raises(CanonicalError):
            canonicalize_tools([{"parameters": {}}])

    def test_nested_parameters_sorted(self):
        recs = canonicalize_tools([
            {"name": "x", "parameters": {"properties": {"b": 1, "a": 2}}},
        ])
        # The parameters object inside the JCS encoding should have sorted keys
        # at every level. Check that 'a' appears before 'b' in bytes.
        assert recs[0].index(b'"a"') < recs[0].index(b'"b"')


# ---------------------------------------------------------------------------
# N5 messages
# ---------------------------------------------------------------------------


class TestCanonicalizeMessages:
    def test_simple_user_message(self):
        recs = canonicalize_messages([{"role": "USER", "content": "hi  there"}])
        decoded = json.loads(recs[0])
        assert decoded["role"] == "user"
        assert decoded["content"] == "hi there"

    def test_invalid_role(self):
        with pytest.raises(CanonicalError, match="role"):
            canonicalize_messages([{"role": "bot", "content": "x"}])

    def test_tool_calls_only_on_assistant(self):
        with pytest.raises(CanonicalError, match="tool_calls"):
            canonicalize_messages([
                {"role": "user", "content": "x", "tool_calls": [{"id": "1"}]}
            ])

    def test_tool_call_id_only_on_tool_role(self):
        with pytest.raises(CanonicalError, match="tool_call_id"):
            canonicalize_messages([
                {"role": "user", "content": "x", "tool_call_id": "abc"}
            ])

    def test_content_list_parts_normalized(self):
        recs = canonicalize_messages([
            {"role": "user", "content": [
                {"type": "text", "text": "a   b"},
                {"type": "image", "url": "https://example.com"},
            ]}
        ])
        decoded = json.loads(recs[0])
        # The "text" field was a string, so it got N1-normalized.
        parts = decoded["content"]
        assert parts[0]["text"] == "a b"

    def test_none_content_becomes_empty_string(self):
        recs = canonicalize_messages([{"role": "assistant", "content": None}])
        decoded = json.loads(recs[0])
        assert decoded["content"] == ""


# ---------------------------------------------------------------------------
# N6 documents
# ---------------------------------------------------------------------------


class TestCanonicalizeDocuments:
    def test_id_auto_computed(self):
        recs = canonicalize_documents([{"content": "hello world"}])
        decoded = json.loads(recs[0])
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert decoded["id"] == expected

    def test_id_preserved_when_provided(self):
        recs = canonicalize_documents([{"id": "my-doc", "content": "abc"}])
        decoded = json.loads(recs[0])
        assert decoded["id"] == "my-doc"

    def test_metadata_jcs_encoded(self):
        recs = canonicalize_documents([
            {"id": "d1", "content": "x", "metadata": {"z": 1, "a": 2}}
        ])
        # Keys 'a' before 'z' in JCS object order.
        assert recs[0].index(b'"a"') < recs[0].index(b'"z"')

    def test_order_preserved(self):
        recs = canonicalize_documents([
            {"id": "z", "content": "first"},
            {"id": "a", "content": "second"},
        ])
        ids = [json.loads(r)["id"] for r in recs]
        assert ids == ["z", "a"]


# ---------------------------------------------------------------------------
# N7 section assembly
# ---------------------------------------------------------------------------


class TestCanonicalize:
    def test_only_messages(self):
        out = canonicalize(messages=[{"role": "user", "content": "hi"}])
        assert out.startswith(b"==MESSAGES==\n")
        assert out.endswith(b"==/MESSAGES==\n")
        # No SYSTEM section emitted.
        assert b"==SYSTEM==" not in out

    def test_section_order_fixed(self):
        out = canonicalize(
            system="sys",
            tools=[{"name": "alpha", "parameters": {}}],
            documents=[{"content": "doc"}],
            messages=[{"role": "user", "content": "hi"}],
        )
        # Sections appear in fixed order regardless of arg order.
        sys_pos = out.index(b"==SYSTEM==")
        tools_pos = out.index(b"==TOOLS==")
        docs_pos = out.index(b"==DOCUMENTS==")
        msgs_pos = out.index(b"==MESSAGES==")
        assert sys_pos < tools_pos < docs_pos < msgs_pos

    def test_prefix_stability_appending_message(self):
        """Adding a message must not change bytes of preceding sections."""
        msgs = [{"role": "user", "content": "first"}]
        out1 = canonicalize(system="hello", messages=msgs)
        msgs.append({"role": "assistant", "content": "second"})
        out2 = canonicalize(system="hello", messages=msgs)
        # Prefix up to end of first message's section opener+first record
        # should match in both — adding a new message extends bytes after the
        # first message's record terminator.
        # System section is fully stable:
        sys_end = out1.index(b"==/SYSTEM==\n") + len(b"==/SYSTEM==\n")
        assert out1[:sys_end] == out2[:sys_end]
        # First record of messages section is byte-stable too.
        # Find first message record by locating ==MESSAGES==\n then up to first \n
        msgs_start = out1.index(b"==MESSAGES==\n") + len(b"==MESSAGES==\n")
        end_first_record = out1.index(b"\n", msgs_start)
        assert out1[:end_first_record] == out2[:end_first_record]

    def test_empty_sections_omitted(self):
        out = canonicalize(system="", tools=[], documents=[], messages=[])
        assert out == b""

    def test_offsets_returned(self):
        out, offsets = canonicalize_with_offsets(
            system="sys", messages=[{"role": "user", "content": "hi"}]
        )
        assert "system" in offsets and "messages" in offsets
        s_start, s_end = offsets["system"]
        assert out[s_start:s_end].startswith(b"==SYSTEM==")
        assert out[s_start:s_end].endswith(b"==/SYSTEM==\n")


# ---------------------------------------------------------------------------
# N7 round-trip parsing for differential testing
# ---------------------------------------------------------------------------


class TestParseSections:
    def test_roundtrip(self):
        out = canonicalize(
            system="hello",
            tools=[{"name": "t", "parameters": {}}],
            messages=[{"role": "user", "content": "hi"}],
        )
        parts = parse_sections(out)
        assert set(parts.keys()) == {"system", "tools", "messages"}
        assert parts["system"] == b"hello\n"

    def test_split_records_in_section(self):
        out = canonicalize(
            messages=[
                {"role": "user", "content": "a"},
                {"role": "assistant", "content": "b"},
            ]
        )
        parts = parse_sections(out)
        recs = split_records(parts["messages"])
        assert len(recs) == 2


# ---------------------------------------------------------------------------
# Determinism — fundamental contract
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_input_same_bytes(self):
        kwargs = dict(
            system="hello",
            tools=[
                {"name": "alpha", "parameters": {"type": "object"}},
                {"name": "beta", "parameters": {"required": ["x"]}},
            ],
            messages=[
                {"role": "user", "content": "first"},
                {"role": "assistant", "content": "second"},
            ],
        )
        out1 = canonicalize(**kwargs)
        out2 = canonicalize(**kwargs)
        assert out1 == out2

    def test_tool_input_order_does_not_matter(self):
        kw_a = dict(tools=[{"name": "a", "parameters": {}}, {"name": "b", "parameters": {}}])
        kw_b = dict(tools=[{"name": "b", "parameters": {}}, {"name": "a", "parameters": {}}])
        assert canonicalize(**kw_a) == canonicalize(**kw_b)


# ---------------------------------------------------------------------------
# Size amplification guard
# ---------------------------------------------------------------------------


class TestSizeGuard:
    def test_amplification_check_passes(self):
        out = canonicalize(
            system="abc",
            messages=[{"role": "user", "content": "hi"}],
            input_size_hint=10_000,
        )
        assert len(out) > 0

    def test_amplification_check_rejects(self):
        # Tiny hint, must reject by far.
        with pytest.raises(CanonicalError, match="amplification"):
            canonicalize(
                system="x" * 200,
                input_size_hint=5,
            )
