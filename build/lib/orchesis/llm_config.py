"""Configuration loader for LLM judge integration."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class LLMConfig:
    api_key: str
    model: str = "gpt-4o"
    base_url: str = "https://api.openai.com/v1"
    timeout: int = 30
    max_retries: int = 1


def load_llm_config(model_override: str | None = None) -> LLMConfig | None:
    api_key = os.getenv("ORCHESIS_LLM_API_KEY")
    if not isinstance(api_key, str) or not api_key.strip():
        return None
    env_model = os.getenv("ORCHESIS_LLM_MODEL", "gpt-4o")
    model = model_override.strip() if isinstance(model_override, str) and model_override.strip() else env_model
    base_url = os.getenv("ORCHESIS_LLM_BASE_URL", "https://api.openai.com/v1")
    return LLMConfig(api_key=api_key.strip(), model=model, base_url=base_url.strip())
