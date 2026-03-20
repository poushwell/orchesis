from __future__ import annotations

from orchesis.compat.openai import OpenAICompatLayer


def test_request_normalized() -> None:
    layer = OpenAICompatLayer()
    req = {"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]}
    out = layer.normalize_request(req)
    assert out["model"] == "gpt-4o"
    assert out["metadata"]["provider"] == "openai"


def test_response_normalized() -> None:
    layer = OpenAICompatLayer()
    out = layer.normalize_response({"model": "gpt-4o", "usage": {"total_tokens": 10}})
    assert "choices" in out
    assert out["choices"][0]["message"]["role"] == "assistant"


def test_cost_estimated() -> None:
    layer = OpenAICompatLayer()
    out = layer.normalize_request({"model": "gpt-4o-mini", "messages": [{"content": "abc"}]})
    assert out["cost"] >= 0.0


def test_model_info_returned() -> None:
    layer = OpenAICompatLayer()
    info = layer.get_model_info("gpt-4o")
    assert info["context"] == 128000


def test_supported_models_listed() -> None:
    layer = OpenAICompatLayer()
    models = layer.list_supported_models()
    assert "gpt-4o" in models
    assert "o3-mini" in models


def test_unknown_model_safe() -> None:
    layer = OpenAICompatLayer()
    info = layer.get_model_info("unknown-model")
    assert info == {}


def test_stream_flag_preserved() -> None:
    layer = OpenAICompatLayer()
    out = layer.normalize_request({"messages": [], "stream": True})
    assert out["metadata"]["stream"] is True


def test_messages_preserved() -> None:
    layer = OpenAICompatLayer()
    messages = [{"role": "system", "content": "rules"}, {"role": "user", "content": "hi"}]
    out = layer.normalize_request({"messages": messages})
    assert out["messages"] == messages
