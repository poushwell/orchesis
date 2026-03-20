"""OpenAI compatibility layer for Orchesis proxy.

Drop-in replacement: point openai.base_url to Orchesis proxy.
Handles OpenAI-specific request/response format normalization.
"""

from __future__ import annotations

from typing import Any


class OpenAICompatLayer:
    """Normalizes OpenAI API format for Orchesis pipeline."""

    OPENAI_MODELS = {
        "gpt-4o": {"context": 128000, "cost_per_ktok_in": 0.005, "cost_per_ktok_out": 0.015},
        "gpt-4o-mini": {"context": 128000, "cost_per_ktok_in": 0.00015, "cost_per_ktok_out": 0.0006},
        "gpt-4-turbo": {"context": 128000, "cost_per_ktok_in": 0.01, "cost_per_ktok_out": 0.03},
        "o1": {"context": 200000, "cost_per_ktok_in": 0.015, "cost_per_ktok_out": 0.06},
        "o3-mini": {"context": 200000, "cost_per_ktok_in": 0.0011, "cost_per_ktok_out": 0.0044},
    }

    def normalize_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Normalize OpenAI chat completions request for Orchesis."""
        payload = request if isinstance(request, dict) else {}
        model = str(payload.get("model", "gpt-4o") or "gpt-4o")
        messages = payload.get("messages", [])
        if not isinstance(messages, list):
            messages = []
        return {
            "model": model,
            "messages": list(messages),
            "metadata": {
                "provider": "openai",
                "stream": bool(payload.get("stream", False)),
                "temperature": float(payload.get("temperature", 1.0)),
                "max_tokens": payload.get("max_tokens"),
            },
            "cost": self._estimate_cost(messages, model),
        }

    def normalize_response(self, response: dict[str, Any]) -> dict[str, Any]:
        """Ensure response matches OpenAI format."""
        payload = response if isinstance(response, dict) else {}
        if "choices" not in payload:
            return {
                "choices": [{"message": {"role": "assistant", "content": str(payload)}}],
                "model": payload.get("model", "unknown"),
                "usage": payload.get("usage", {}),
            }
        return payload

    def _estimate_cost(self, messages: list[dict[str, Any]], model: str) -> float:
        model_info = self.OPENAI_MODELS.get(str(model), {"cost_per_ktok_in": 0.005})
        total_chars = sum(len(str(item.get("content", ""))) for item in messages if isinstance(item, dict))
        estimated_tokens = float(total_chars) / 4.0
        return (estimated_tokens / 1000.0) * float(model_info["cost_per_ktok_in"])

    def get_model_info(self, model: str) -> dict[str, Any]:
        return dict(self.OPENAI_MODELS.get(str(model), {}))

    def list_supported_models(self) -> list[str]:
        return list(self.OPENAI_MODELS.keys())
