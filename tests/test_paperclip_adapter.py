from __future__ import annotations

from dataclasses import dataclass

from orchesis.integrations.paperclip import AdapterConfig, PaperclipAdapter, PaperclipAgentProfile


@dataclass
class _MockClient:
    base_url: str = "https://api.openai.com/v1"


def test_adapter_default_url(monkeypatch) -> None:
    monkeypatch.delenv("ORCHESIS_BASE_URL", raising=False)
    adapter = PaperclipAdapter()
    assert adapter.config.orchesis_url == "http://localhost:8100"


def test_adapter_custom_url() -> None:
    adapter = PaperclipAdapter(orchesis_url="http://proxy:9000")
    assert adapter.config.orchesis_url == "http://proxy:9000"


def test_adapter_from_env(monkeypatch) -> None:
    monkeypatch.setenv("ORCHESIS_BASE_URL", "http://env-proxy:7000")
    adapter = PaperclipAdapter()
    assert adapter.config.orchesis_url == "http://env-proxy:7000"


def test_headers_basic() -> None:
    adapter = PaperclipAdapter(orchesis_url="http://localhost:8100")
    headers = adapter.get_orchesis_headers()
    assert headers["X-Orchesis-Framework"] == "paperclip"


def test_headers_with_agent_id() -> None:
    cfg = AdapterConfig(orchesis_url="http://localhost:8100", agent_id="pc-agent-1")
    adapter = PaperclipAdapter(config=cfg)
    headers = adapter.get_orchesis_headers()
    assert headers["X-Orchesis-Agent-Id"] == "pc-agent-1"


def test_headers_with_budget() -> None:
    cfg = AdapterConfig(orchesis_url="http://localhost:8100", budget_daily_usd=12.5)
    adapter = PaperclipAdapter(config=cfg)
    headers = adapter.get_orchesis_headers()
    assert headers["X-Orchesis-Budget-Daily"] == "12.5"


def test_patch_env_sets_openai(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("ORCHESIS_BASE_URL", raising=False)
    adapter = PaperclipAdapter(orchesis_url="http://localhost:8100")
    adapter.patch_env()
    assert adapter.is_active is True
    assert adapter.OPENAI_BASE_URL_KEY in __import__("os").environ
    assert __import__("os").environ["OPENAI_BASE_URL"] == "http://localhost:8100/v1"


def test_patch_env_returns_original(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("ORCHESIS_BASE_URL", "http://old:8100")
    adapter = PaperclipAdapter(orchesis_url="http://localhost:8100")
    original = adapter.patch_env()
    assert original["OPENAI_BASE_URL"] == "https://api.openai.com/v1"
    assert original["ORCHESIS_BASE_URL"] == "http://old:8100"


def test_restore_env(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.delenv("ORCHESIS_BASE_URL", raising=False)
    adapter = PaperclipAdapter(orchesis_url="http://localhost:8100")
    adapter.patch_env()
    adapter.restore_env()
    assert adapter.is_active is False
    assert __import__("os").environ["OPENAI_BASE_URL"] == "https://api.openai.com/v1"
    assert "ORCHESIS_BASE_URL" not in __import__("os").environ


def test_context_manager(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("ORCHESIS_BASE_URL", raising=False)
    with PaperclipAdapter(orchesis_url="http://localhost:8100") as adapter:
        assert adapter.is_active is True
        assert __import__("os").environ["OPENAI_BASE_URL"] == "http://localhost:8100/v1"
    assert "OPENAI_BASE_URL" not in __import__("os").environ
    assert "ORCHESIS_BASE_URL" not in __import__("os").environ


def test_patch_client() -> None:
    client = _MockClient()
    adapter = PaperclipAdapter(orchesis_url="http://proxy:9000")
    patched = adapter.patch_openai_client(client)
    assert patched is client
    assert client.base_url == "http://proxy:9000/v1"


def test_restore_client() -> None:
    client = _MockClient(base_url="https://api.openai.com/v1")
    adapter = PaperclipAdapter(orchesis_url="http://proxy:9000")
    adapter.patch_openai_client(client)
    adapter.restore_openai_client(client)
    assert client.base_url == "https://api.openai.com/v1"


def test_wrap_tool_call() -> None:
    cfg = AdapterConfig(orchesis_url="http://localhost:8100", agent_id="agent-42")
    adapter = PaperclipAdapter(config=cfg)
    wrapped = adapter.wrap_tool_call("search", {"query": "hello"})
    assert "_orchesis_meta" in wrapped
    assert wrapped["_orchesis_meta"]["framework"] == "paperclip"
    assert wrapped["_orchesis_meta"]["tool"] == "search"


def test_get_agent_profile() -> None:
    cfg = AdapterConfig(orchesis_url="http://localhost:8100", agent_id="paperclip-1", budget_daily_usd=3.0)
    adapter = PaperclipAdapter(config=cfg)
    profile = adapter.get_agent_profile()
    assert isinstance(profile, PaperclipAgentProfile)
    assert profile.framework == "paperclip"
    assert profile.agent_id == "paperclip-1"
    assert profile.budget_limit == 3.0

