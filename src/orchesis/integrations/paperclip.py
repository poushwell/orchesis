"""Paperclip/OpenClaw adapter for Orchesis.

Enables transparent proxying of Paperclip agents through
Orchesis control plane with zero code changes.

Integration: set ORCHESIS_BASE_URL env var, Paperclip agents
automatically route through Orchesis proxy.

Usage:
    # In Paperclip config:
    ORCHESIS_BASE_URL=http://localhost:8100

    # Or programmatic:
    adapter = PaperclipAdapter(orchesis_url="http://localhost:8100")
    adapter.patch_openai_client(client)  # monkey-patch base_url
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

from orchesis.utils.log import get_logger

logger = get_logger(__name__)


@dataclass
class PaperclipAgentProfile:
    """Profile of a Paperclip agent for Orchesis tracking."""

    agent_id: str = ""
    agent_name: str = ""
    framework: str = "paperclip"
    framework_version: str = ""
    model: str = ""
    tools: list = field(default_factory=list)
    budget_limit: Optional[float] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class AdapterConfig:
    """Configuration for the Paperclip adapter."""

    orchesis_url: str = ""
    agent_id: Optional[str] = None
    enable_cost_tracking: bool = True
    enable_security_scanning: bool = True
    enable_budget_enforcement: bool = True
    budget_daily_usd: Optional[float] = None
    inject_headers: dict = field(default_factory=dict)


class PaperclipAdapter:
    """Adapter to route Paperclip/OpenClaw agents through Orchesis."""

    ENV_KEY = "ORCHESIS_BASE_URL"
    OPENAI_BASE_URL_KEY = "OPENAI_BASE_URL"

    def __init__(self, config: AdapterConfig | None = None, orchesis_url: str | None = None):
        self.config = config or AdapterConfig()
        if orchesis_url:
            self.config.orchesis_url = orchesis_url
        elif not self.config.orchesis_url:
            self.config.orchesis_url = os.environ.get(self.ENV_KEY, "http://localhost:8100")

        self._original_base_url: Any = None
        self._original_env: dict[str, str | None] = {}
        self._active = False

        logger.info(
            "PaperclipAdapter initialized",
            extra={"component": "paperclip", "orchesis_url": self.config.orchesis_url},
        )

    def get_orchesis_headers(self) -> dict:
        """Generate headers for Orchesis agent identification."""
        headers = {
            "X-Orchesis-Framework": "paperclip",
            "X-Orchesis-Agent-Id": self.config.agent_id or "paperclip-default",
        }
        if self.config.enable_cost_tracking:
            headers["X-Orchesis-Cost-Track"] = "true"
        if self.config.enable_security_scanning:
            headers["X-Orchesis-Security-Scan"] = "true"
        if self.config.budget_daily_usd is not None:
            headers["X-Orchesis-Budget-Daily"] = str(self.config.budget_daily_usd)
        headers.update(self.config.inject_headers)
        return headers

    def patch_env(self) -> dict:
        """Set environment variables to route through Orchesis."""
        original: dict[str, str | None] = {}
        for key in [self.OPENAI_BASE_URL_KEY, self.ENV_KEY]:
            original[key] = os.environ.get(key)

        orchesis_api = f"{self.config.orchesis_url}/v1"
        os.environ[self.OPENAI_BASE_URL_KEY] = orchesis_api
        os.environ[self.ENV_KEY] = self.config.orchesis_url

        self._original_env = original
        self._active = True

        logger.info(
            "Patched env for Paperclip adapter",
            extra={"component": "paperclip", "openai_base_url": orchesis_api},
        )

        return original

    def restore_env(self) -> None:
        """Restore original environment variables."""
        for key, val in self._original_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        self._active = False
        logger.info("Restored original env", extra={"component": "paperclip"})

    def patch_openai_client(self, client: Any) -> Any:
        """Monkey-patch an OpenAI-compatible client base_url."""
        orchesis_api = f"{self.config.orchesis_url}/v1"
        self._original_base_url = getattr(client, "base_url", None)
        try:
            client.base_url = orchesis_api
            logger.info(
                "Patched OpenAI client base_url",
                extra={"component": "paperclip", "base_url": orchesis_api},
            )
        except (AttributeError, TypeError) as exc:
            logger.warning("Could not patch client: %s", exc, extra={"component": "paperclip"})
        self._active = True
        return client

    def restore_openai_client(self, client: Any) -> None:
        """Restore original base_url on OpenAI client."""
        if self._original_base_url is not None:
            try:
                client.base_url = self._original_base_url
            except (AttributeError, TypeError):
                pass
        self._active = False

    def wrap_tool_call(self, tool_name: str, args: dict) -> dict:
        """Intercept and annotate a tool call for Orchesis tracking."""
        annotated = dict(args)
        annotated["_orchesis_meta"] = {
            "framework": "paperclip",
            "agent_id": self.config.agent_id,
            "tool": tool_name,
            "cost_tracking": self.config.enable_cost_tracking,
        }
        return annotated

    def get_cost_report(self) -> dict:
        """Placeholder method for fetching Orchesis cost report."""
        return {"orchesis_url": self.config.orchesis_url, "status": "not_implemented"}

    def get_security_report(self) -> dict:
        """Placeholder method for fetching Orchesis security report."""
        return {"orchesis_url": self.config.orchesis_url, "status": "not_implemented"}

    def get_agent_profile(self) -> PaperclipAgentProfile:
        """Build agent profile for Orchesis registration."""
        return PaperclipAgentProfile(
            agent_id=self.config.agent_id or "paperclip-default",
            framework="paperclip",
            tools=[],
            budget_limit=self.config.budget_daily_usd,
            metadata={"orchesis_url": self.config.orchesis_url},
        )

    @property
    def is_active(self) -> bool:
        return self._active

    def __enter__(self):
        """Context manager: patch env on enter."""
        self.patch_env()
        return self

    def __exit__(self, *args):
        """Context manager: restore env on exit."""
        self.restore_env()

