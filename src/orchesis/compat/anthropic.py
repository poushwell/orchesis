"""Anthropic compatibility layer for Orchesis proxy."""

from __future__ import annotations

from typing import Any


class AnthropicCompatLayer:
    """Normalizes Anthropic API format for Orchesis pipeline."""

    ANTHROPIC_MODELS = {
        "claude-opus-4-6": {"context": 200000, "cost_per_ktok_in": 0.015, "cost_per_ktok_out": 0.075},
        "claude-sonnet-4-6": {"context": 200000, "cost_per_ktok_in": 0.003, "cost_per_ktok_out": 0.015},
        "claude-haiku-4-5": {"context": 200000, "cost_per_ktok_in": 0.00025, "cost_per_ktok_out": 0.00125},
    }

    def normalize_request(self, request: dict[str, Any]) -> dict[str, Any]:
        payload = request if isinstance(request, dict) else {}
        model = str(payload.get("model", "claude-sonnet-4-6") or "claude-sonnet-4-6")
        messages = payload.get("messages", [])
        if not isinstance(messages, list):
            messages = []
        system = str(payload.get("system", "") or "")

        unified_messages: list[dict[str, Any]] = []
        if system:
            unified_messages.append({"role": "system", "content": system})
        unified_messages.extend(messages)

        return {
            "model": model,
            "messages": unified_messages,
            "metadata": {
                "provider": "anthropic",
                "max_tokens": int(payload.get("max_tokens", 1024)),
                "temperature": float(payload.get("temperature", 1.0)),
            },
            "cost": self._estimate_cost(unified_messages, model),
        }

    def normalize_response(self, response: dict[str, Any]) -> dict[str, Any]:
        payload = response if isinstance(response, dict) else {}
        if "content" in payload and "choices" not in payload:
            content = payload["content"]
            text = content[0].get("text", "") if isinstance(content, list) and content else str(content)
            return {
                "choices": [{"message": {"role": "assistant", "content": text}}],
                "model": payload.get("model", "unknown"),
                "usage": payload.get("usage", {}),
            }
        return payload

    def _estimate_cost(self, messages: list[dict[str, Any]], model: str) -> float:
        model_info = self.ANTHROPIC_MODELS.get(str(model), {"cost_per_ktok_in": 0.003})
        total_chars = sum(len(str(item.get("content", ""))) for item in messages if isinstance(item, dict))
        return (float(total_chars) / 4000.0) * float(model_info["cost_per_ktok_in"])

    def list_supported_models(self) -> list[str]:
        return list(self.ANTHROPIC_MODELS.keys())
