from __future__ import annotations

from orchesis.compat.anthropic import AnthropicCompatLayer


def test_request_normalized() -> None:
    layer = AnthropicCompatLayer()
    req = {"model": "claude-sonnet-4-6", "messages": [{"role": "user", "content": "hello"}]}
    out = layer.normalize_request(req)
    assert out["model"] == "claude-sonnet-4-6"
    assert out["metadata"]["provider"] == "anthropic"


def test_system_prompt_converted() -> None:
    layer = AnthropicCompatLayer()
    out = layer.normalize_request({"system": "You are helpful", "messages": []})
    assert out["messages"][0]["role"] == "system"
    assert out["messages"][0]["content"] == "You are helpful"


def test_response_normalized() -> None:
    layer = AnthropicCompatLayer()
    response = {"model": "claude-sonnet-4-6", "content": [{"type": "text", "text": "done"}]}
    out = layer.normalize_response(response)
    assert "choices" in out
    assert out["choices"][0]["message"]["content"] == "done"


def test_cost_estimated() -> None:
    layer = AnthropicCompatLayer()
    out = layer.normalize_request({"messages": [{"role": "user", "content": "abc"}]})
    assert out["cost"] >= 0.0


def test_models_listed() -> None:
    layer = AnthropicCompatLayer()
    models = layer.list_supported_models()
    assert "claude-opus-4-6" in models
    assert "claude-haiku-4-5" in models


def test_unknown_model_safe() -> None:
    layer = AnthropicCompatLayer()
    out = layer.normalize_request({"model": "unknown", "messages": []})
    assert out["model"] == "unknown"
    assert out["cost"] >= 0.0


def test_content_block_extracted() -> None:
    layer = AnthropicCompatLayer()
    out = layer.normalize_response({"content": [{"text": "answer"}]})
    assert out["choices"][0]["message"]["content"] == "answer"


def test_unified_format_correct() -> None:
    layer = AnthropicCompatLayer()
    out = layer.normalize_request(
        {
            "system": "sys",
            "messages": [{"role": "user", "content": "q"}],
            "max_tokens": 512,
            "temperature": 0.3,
        }
    )
    assert "model" in out
    assert "messages" in out
    assert "metadata" in out
    assert out["metadata"]["max_tokens"] == 512
