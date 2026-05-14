"""ProviderAdapter Protocol + supporting types.

Adapters convert between the canonical request form (produced by
`orchesis.canonical`) and a specific provider's HTTP wire format. They
also decide where to place provider-specific cache anchors and how to
parse responses + usage metrics.

The Protocol is structural: any object with the right shape can be
registered. First-party adapters live next to this module
(`anthropic.py`, `openai.py`).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Mapping, Protocol, Sequence, runtime_checkable


# ---------------------------------------------------------------------------
# Data types passed across the adapter boundary
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LogicalContext:
    """High-level view of the request used for cache-anchor decisions.

    `messages`, `tools`, and `documents` keep their order as it appears in
    the canonical form. `chain_length` is the conversation depth used by
    the rolling cache-anchor heuristic.
    """
    messages: tuple[Mapping[str, Any], ...] = ()
    tools: tuple[Mapping[str, Any], ...] = ()
    documents: tuple[Mapping[str, Any], ...] = ()
    system_present: bool = False
    system_tokens_estimate: int = 0
    chain_length: int = 0
    document_tokens_estimate: int = 0


@dataclass(frozen=True, slots=True)
class RequestParams:
    """Sampling and operational params handed to the adapter."""
    model: str
    temperature: float = 1.0
    max_tokens: int | None = None
    top_p: float | None = None
    stop: tuple[str, ...] = ()
    stream: bool = False
    extra_headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CacheAnchor:
    """Placement instruction for a provider-specific cache marker.

    `section` matches the canonical section names (system, tools,
    documents, messages). `position` is `"end_of_section"` or an index
    expression interpreted per-provider. `metadata` is opaque to the
    proxy — adapters use it to carry provider hints (e.g. Anthropic's
    `cache_control` block).
    """
    section: str
    position: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ProviderRequestBody:
    """Final HTTP body + headers ready to send upstream."""
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)
    url_suffix: str = ""


@dataclass(frozen=True, slots=True)
class UsageMetrics:
    """Token usage broken down by cache state."""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0
    uncached_input_tokens: int = 0


@dataclass(frozen=True, slots=True)
class CacheHitEstimate:
    """Estimated cache hit rate for routing decisions."""
    expected_hit_rate: float          # [0, 1]
    sample_size: int = 0              # number of recent requests considered
    confidence: float = 0.0           # [0, 1] — 0 means no observations yet


@dataclass(frozen=True, slots=True)
class LogicalResponse:
    """Parsed upstream response, provider-agnostic."""
    content: str
    finish_reason: str
    tool_calls: tuple[Mapping[str, Any], ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class StreamChunk:
    """One delta from a streamed response."""
    text: str
    is_final: bool = False
    tool_call_delta: Mapping[str, Any] | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SessionHistory:
    """Rolling per-session metrics used to estimate cache hit rate."""
    recent_cache_read_tokens: int = 0
    recent_cache_creation_tokens: int = 0
    recent_uncached_input_tokens: int = 0
    request_count: int = 0


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    """Health snapshot used by the model router."""
    available: bool
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    error_rate: float = 0.0
    last_checked_at: float = 0.0


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ProviderAdapter(Protocol):
    """Wire-format and cache-policy adapter for one upstream LLM provider."""

    name: str
    version: str

    def supports_model(self, model: str) -> bool: ...

    def prepare_request_body(
        self,
        canonical_bytes: bytes,
        section_offsets: Mapping[str, tuple[int, int]],
        logical_context: LogicalContext,
        request_params: RequestParams,
    ) -> ProviderRequestBody: ...

    def place_cache_anchors(
        self,
        section_offsets: Mapping[str, tuple[int, int]],
        logical_context: LogicalContext,
    ) -> list[CacheAnchor]: ...

    def estimate_cache_hit_rate(
        self,
        session_history: SessionHistory,
    ) -> CacheHitEstimate: ...

    def parse_response(
        self,
        provider_response: bytes,
    ) -> LogicalResponse: ...

    def parse_usage(
        self,
        provider_response: bytes,
    ) -> UsageMetrics: ...

    def stream_chunks(
        self,
        provider_stream: AsyncIterator[bytes],
    ) -> AsyncIterator[StreamChunk]: ...

    def health_check(self) -> ProviderHealth: ...


# ---------------------------------------------------------------------------
# Registry — module-level, threadsafe. Tests reset via `_clear()`.
# ---------------------------------------------------------------------------


_REG: dict[str, ProviderAdapter] = {}
_REG_LOCK = threading.RLock()


def register_adapter(adapter: ProviderAdapter) -> None:
    """Register an adapter under its `name`. Re-registration replaces."""
    if not isinstance(adapter, ProviderAdapter):
        raise TypeError(
            f"object of type {type(adapter).__name__} does not match the "
            "ProviderAdapter Protocol"
        )
    with _REG_LOCK:
        _REG[adapter.name] = adapter


def get_adapter(name: str) -> ProviderAdapter:
    with _REG_LOCK:
        try:
            return _REG[name]
        except KeyError as e:
            raise KeyError(f"no provider adapter registered for {name!r}") from e


def adapter_names() -> tuple[str, ...]:
    with _REG_LOCK:
        return tuple(sorted(_REG))


def adapter_for_model(model: str) -> ProviderAdapter | None:
    """Return the first registered adapter that claims this model."""
    with _REG_LOCK:
        for adapter in _REG.values():
            try:
                if adapter.supports_model(model):
                    return adapter
            except Exception:
                continue
    return None


def _clear() -> None:
    """Test-only: reset the registry. Prod code never calls this."""
    with _REG_LOCK:
        _REG.clear()
