"""Provider adapter package.

Per SPEC §1.6.3, every supported upstream LLM provider implements the
ProviderAdapter Protocol. The proxy selects an adapter based on the chosen
model/provider and uses it to convert the canonical request form into the
provider's wire format, place cache anchors, parse responses, and report
usage metrics.
"""

from orchesis.providers.base import (
    CacheAnchor,
    CacheHitEstimate,
    LogicalContext,
    LogicalResponse,
    ProviderAdapter,
    ProviderHealth,
    ProviderRequestBody,
    RequestParams,
    SessionHistory,
    StreamChunk,
    UsageMetrics,
    adapter_for_model,
    adapter_names,
    get_adapter,
    register_adapter,
)
from orchesis.providers.anthropic import AnthropicAdapter
from orchesis.providers.openai import OpenAIAdapter

# Register the first-party adapters on import. Third parties can call
# `register_adapter()` from their own entry points.
register_adapter(AnthropicAdapter())
register_adapter(OpenAIAdapter())

__all__ = [
    "AnthropicAdapter",
    "CacheAnchor",
    "CacheHitEstimate",
    "LogicalContext",
    "LogicalResponse",
    "OpenAIAdapter",
    "ProviderAdapter",
    "ProviderHealth",
    "ProviderRequestBody",
    "RequestParams",
    "SessionHistory",
    "StreamChunk",
    "UsageMetrics",
    "adapter_for_model",
    "adapter_names",
    "get_adapter",
    "register_adapter",
]
