"""Tests for ProviderAdapter Protocol + Anthropic / OpenAI adapters.

SPEC §1.6.3-§1.6.5 coverage.
"""

from __future__ import annotations

import json

import pytest

from orchesis.providers import (
    AnthropicAdapter,
    OpenAIAdapter,
    LogicalContext,
    RequestParams,
    SessionHistory,
    adapter_for_model,
    adapter_names,
    get_adapter,
    register_adapter,
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_default_adapters_present(self):
        # Importing the package registers anthropic + openai.
        assert "anthropic" in adapter_names()
        assert "openai" in adapter_names()

    def test_get_by_name(self):
        a = get_adapter("anthropic")
        assert isinstance(a, AnthropicAdapter)
        o = get_adapter("openai")
        assert isinstance(o, OpenAIAdapter)

    def test_unknown_name_raises(self):
        with pytest.raises(KeyError, match="no provider adapter"):
            get_adapter("nope")

    def test_adapter_for_model(self):
        assert adapter_for_model("gpt-4o").name == "openai"
        assert adapter_for_model("claude-3-5-sonnet").name == "anthropic"
        assert adapter_for_model("o1-preview").name == "openai"
        assert adapter_for_model("anthropic.claude-3").name == "anthropic"
        assert adapter_for_model("unknown-model-xyz") is None

    def test_register_rejects_non_protocol(self):
        with pytest.raises(TypeError, match="Protocol"):
            register_adapter("not an adapter")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Anthropic adapter
# ---------------------------------------------------------------------------


class TestAnthropicSupportsModel:
    def test_claude_supported(self):
        assert AnthropicAdapter().supports_model("claude-3-5-sonnet-20240620")
        assert AnthropicAdapter().supports_model("claude-3-opus")

    def test_bedrock_prefix_supported(self):
        assert AnthropicAdapter().supports_model("anthropic.claude-3-haiku")

    def test_gpt_rejected(self):
        assert not AnthropicAdapter().supports_model("gpt-4o")


class TestAnthropicCacheAnchors:
    def _ctx(self, **overrides):
        defaults = dict(
            messages=(
                {"role": "user", "content": "a"},
                {"role": "assistant", "content": "b"},
                {"role": "user", "content": "c"},
            ),
            tools=({"name": "alpha_tool", "parameters": {}}, {"name": "beta_tool", "parameters": {}}),
            documents=(),
            system_present=True,
            system_tokens_estimate=200,
            chain_length=3,
            document_tokens_estimate=0,
        )
        defaults.update(overrides)
        return LogicalContext(**defaults)

    def _offsets(self, **k):
        # System / tools / messages all present in offsets by default.
        defaults = {
            "system": (0, 50),
            "tools": (50, 200),
            "messages": (200, 400),
        }
        defaults.update(k)
        return defaults

    def test_system_anchor(self):
        anchors = AnthropicAdapter().place_cache_anchors(self._offsets(), self._ctx())
        sections = [a.section for a in anchors]
        assert "system" in sections
        sys_anchor = next(a for a in anchors if a.section == "system")
        assert sys_anchor.position == "end_of_section"

    def test_tools_anchor_at_last(self):
        anchors = AnthropicAdapter().place_cache_anchors(self._offsets(), self._ctx())
        tools_anchor = next(a for a in anchors if a.section == "tools")
        assert tools_anchor.position == "1"  # 2 tools → index 1

    def test_message_anchor_at_n_minus_2(self):
        anchors = AnthropicAdapter().place_cache_anchors(self._offsets(), self._ctx())
        msg_anchor = next(a for a in anchors if a.section == "messages")
        # 3 messages → anchor at index 1 (n-2)
        assert msg_anchor.position == "1"

    def test_no_message_anchor_when_only_one_message(self):
        anchors = AnthropicAdapter().place_cache_anchors(
            self._offsets(),
            self._ctx(messages=({"role": "user", "content": "a"},), chain_length=1),
        )
        assert not any(a.section == "messages" for a in anchors)

    def test_no_tools_anchor_when_no_tools(self):
        anchors = AnthropicAdapter().place_cache_anchors(
            self._offsets(),
            self._ctx(tools=()),
        )
        assert not any(a.section == "tools" for a in anchors)

    def test_documents_anchor_only_above_threshold(self):
        # Below threshold — no doc anchor.
        anchors = AnthropicAdapter().place_cache_anchors(
            self._offsets(documents=(0, 100)),
            self._ctx(
                documents=({"id": "d1", "content": "small"},),
                document_tokens_estimate=200,
            ),
        )
        assert not any(a.section == "documents" for a in anchors)
        # Above threshold — doc anchor placed.
        anchors2 = AnthropicAdapter().place_cache_anchors(
            self._offsets(documents=(0, 100)),
            self._ctx(
                documents=({"id": "d1", "content": "big" * 1000},),
                document_tokens_estimate=2000,
            ),
        )
        assert any(a.section == "documents" for a in anchors2)


class TestAnthropicPrepareRequestBody:
    def _basic_ctx(self):
        return LogicalContext(
            messages=({"role": "user", "content": "hi"}, {"role": "assistant", "content": "hey"}),
            tools=(),
            documents=(),
            system_present=False,
            chain_length=2,
        )

    def test_basic_body_shape(self):
        body = AnthropicAdapter().prepare_request_body(
            canonical_bytes=b"",
            section_offsets={"messages": (0, 100)},
            logical_context=self._basic_ctx(),
            request_params=RequestParams(model="claude-3-5-sonnet", temperature=0.7),
        )
        parsed = json.loads(body.body)
        assert parsed["model"] == "claude-3-5-sonnet"
        assert parsed["temperature"] == 0.7
        assert "max_tokens" in parsed  # always required for Anthropic
        assert len(parsed["messages"]) == 2

    def test_system_inlined_when_present(self):
        ctx = LogicalContext(
            messages=({"role": "user", "content": "hi"},),
            tools=(),
            documents=(),
            system_present=True,
            chain_length=1,
        )
        canonical = b"==SYSTEM==\nyou are helpful\n==/SYSTEM==\n"
        body = AnthropicAdapter().prepare_request_body(
            canonical_bytes=canonical,
            section_offsets={"system": (0, len(canonical))},
            logical_context=ctx,
            request_params=RequestParams(model="claude-3-haiku"),
        )
        parsed = json.loads(body.body)
        assert parsed["system"]
        assert parsed["system"][0]["text"] == "you are helpful"

    def test_cache_control_on_message(self):
        ctx = LogicalContext(
            messages=(
                {"role": "user", "content": "a"},
                {"role": "assistant", "content": "b"},
                {"role": "user", "content": "c"},
            ),
            tools=(),
            documents=(),
            system_present=False,
            chain_length=3,
        )
        body = AnthropicAdapter().prepare_request_body(
            canonical_bytes=b"",
            section_offsets={"messages": (0, 100)},
            logical_context=ctx,
            request_params=RequestParams(model="claude-3-opus"),
        )
        parsed = json.loads(body.body)
        # Message at index n-2 (=1) carries cache_control on its last content block.
        assert "cache_control" in parsed["messages"][1]["content"][-1]
        # Other messages don't.
        assert "cache_control" not in parsed["messages"][0]["content"][-1]
        assert "cache_control" not in parsed["messages"][2]["content"][-1]

    def test_beta_header_added_with_anchors(self):
        body = AnthropicAdapter().prepare_request_body(
            canonical_bytes=b"==SYSTEM==\nhelpful\n==/SYSTEM==\n",
            section_offsets={"system": (0, 32)},
            logical_context=LogicalContext(
                messages=({"role": "user", "content": "x"},),
                system_present=True,
                chain_length=1,
            ),
            request_params=RequestParams(model="claude-3-5-sonnet"),
        )
        assert "prompt-caching" in body.headers.get("anthropic-beta", "")


class TestAnthropicParseResponse:
    def test_text_content(self):
        resp = json.dumps({
            "content": [{"type": "text", "text": "hello"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }).encode("utf-8")
        result = AnthropicAdapter().parse_response(resp)
        assert result.content == "hello"
        assert result.finish_reason == "end_turn"
        assert result.tool_calls == ()

    def test_tool_use_content(self):
        resp = json.dumps({
            "content": [
                {"type": "text", "text": "let me search"},
                {"type": "tool_use", "id": "tu_1", "name": "search", "input": {"q": "x"}},
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }).encode("utf-8")
        result = AnthropicAdapter().parse_response(resp)
        assert "let me search" in result.content
        assert len(result.tool_calls) == 1
        assert result.tool_calls[0]["name"] == "search"


class TestAnthropicParseUsage:
    def test_with_cache_tokens(self):
        resp = json.dumps({
            "usage": {
                "input_tokens": 1000,
                "output_tokens": 50,
                "cache_read_input_tokens": 800,
                "cache_creation_input_tokens": 100,
            }
        }).encode("utf-8")
        usage = AnthropicAdapter().parse_usage(resp)
        assert usage.input_tokens == 1000
        assert usage.output_tokens == 50
        assert usage.cache_read_tokens == 800
        assert usage.cache_creation_tokens == 100
        assert usage.uncached_input_tokens == 100  # 1000 - 800 - 100

    def test_without_cache_tokens(self):
        resp = json.dumps({"usage": {"input_tokens": 50, "output_tokens": 5}}).encode("utf-8")
        usage = AnthropicAdapter().parse_usage(resp)
        assert usage.cache_read_tokens == 0
        assert usage.cache_creation_tokens == 0
        assert usage.uncached_input_tokens == 50


class TestAnthropicCacheHitEstimate:
    def test_zero_when_no_observations(self):
        e = AnthropicAdapter().estimate_cache_hit_rate(SessionHistory())
        assert e.expected_hit_rate == 0.0
        assert e.confidence == 0.0

    def test_rate_when_observations(self):
        e = AnthropicAdapter().estimate_cache_hit_rate(SessionHistory(
            recent_cache_read_tokens=800,
            recent_uncached_input_tokens=200,
            request_count=10,
        ))
        assert e.expected_hit_rate == 0.8
        assert 0.0 < e.confidence < 1.0

    def test_confidence_saturates_at_20_requests(self):
        e = AnthropicAdapter().estimate_cache_hit_rate(SessionHistory(
            recent_cache_read_tokens=100,
            recent_uncached_input_tokens=100,
            request_count=100,
        ))
        assert e.confidence == 1.0


# ---------------------------------------------------------------------------
# OpenAI adapter
# ---------------------------------------------------------------------------


class TestOpenAIAdapter:
    def test_supports_gpt(self):
        assert OpenAIAdapter().supports_model("gpt-4o")
        assert OpenAIAdapter().supports_model("gpt-3.5-turbo")
        assert OpenAIAdapter().supports_model("o1-preview")

    def test_rejects_claude(self):
        assert not OpenAIAdapter().supports_model("claude-3-opus")

    def test_no_explicit_cache_anchors(self):
        ctx = LogicalContext(
            messages=({"role": "user", "content": "hi"},),
            tools=({"name": "search", "parameters": {}},),
            documents=(),
            system_present=True,
            chain_length=1,
        )
        anchors = OpenAIAdapter().place_cache_anchors({"system": (0, 10)}, ctx)
        assert anchors == []

    def test_system_inlined_as_first_message(self):
        body = OpenAIAdapter().prepare_request_body(
            canonical_bytes=b"==SYSTEM==\nhelp\n==/SYSTEM==\n",
            section_offsets={"system": (0, 28)},
            logical_context=LogicalContext(
                messages=({"role": "user", "content": "hi"},),
                system_present=True,
                chain_length=1,
            ),
            request_params=RequestParams(model="gpt-4o"),
        )
        parsed = json.loads(body.body)
        assert parsed["messages"][0]["role"] == "system"
        assert parsed["messages"][0]["content"] == "help"

    def test_tools_translated_to_function_format(self):
        body = OpenAIAdapter().prepare_request_body(
            canonical_bytes=b"",
            section_offsets={},
            logical_context=LogicalContext(
                messages=({"role": "user", "content": "x"},),
                tools=({"name": "search", "description": "find", "parameters": {"type": "object"}},),
                chain_length=1,
            ),
            request_params=RequestParams(model="gpt-4o"),
        )
        parsed = json.loads(body.body)
        assert parsed["tools"][0]["type"] == "function"
        assert parsed["tools"][0]["function"]["name"] == "search"

    def test_parse_response_with_tool_calls(self):
        resp = json.dumps({
            "choices": [{
                "message": {
                    "content": "calling tool",
                    "tool_calls": [{
                        "id": "tc_1",
                        "function": {"name": "search", "arguments": "{\"q\":\"x\"}"},
                    }],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }).encode("utf-8")
        result = OpenAIAdapter().parse_response(resp)
        assert result.content == "calling tool"
        assert result.tool_calls[0]["name"] == "search"
        assert result.finish_reason == "tool_calls"

    def test_parse_usage_with_cached(self):
        resp = json.dumps({
            "usage": {
                "prompt_tokens": 1000,
                "completion_tokens": 50,
                "prompt_tokens_details": {"cached_tokens": 800},
            }
        }).encode("utf-8")
        usage = OpenAIAdapter().parse_usage(resp)
        assert usage.input_tokens == 1000
        assert usage.cache_read_tokens == 800
        assert usage.uncached_input_tokens == 200

    def test_parse_response_empty_choices(self):
        resp = json.dumps({"choices": []}).encode("utf-8")
        result = OpenAIAdapter().parse_response(resp)
        assert result.content == ""

    def test_health_check_available(self):
        h = OpenAIAdapter().health_check()
        assert h.available is True
