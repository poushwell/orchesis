"""OpenAI provider adapter — stub form.

SPEC §1.6.4 notes OpenAI does automatic caching on prefix ≥ 1024 tokens
with no explicit anchors. This adapter therefore:
  - returns an empty anchor list from `place_cache_anchors`.
  - converts the canonical message list into Chat Completions shape.
  - parses standard `usage` keys when present.
  - leaves streaming-chunk parsing as a placeholder (raises in
    CP3 to make missing coverage loud; CP4 fills it in).
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator, Mapping

from orchesis.providers.base import (
    CacheAnchor,
    CacheHitEstimate,
    LogicalContext,
    LogicalResponse,
    ProviderHealth,
    ProviderRequestBody,
    RequestParams,
    SessionHistory,
    StreamChunk,
    UsageMetrics,
)


class OpenAIAdapter:
    name = "openai"
    version = "0.1.0"

    _MODEL_PREFIXES = (
        "gpt-",
        "o1-",
        "o3",
        "text-davinci",
    )

    def supports_model(self, model: str) -> bool:
        m = model.lower().strip()
        return any(m.startswith(p) for p in self._MODEL_PREFIXES)

    def prepare_request_body(
        self,
        canonical_bytes: bytes,
        section_offsets: Mapping[str, tuple[int, int]],
        logical_context: LogicalContext,
        request_params: RequestParams,
    ) -> ProviderRequestBody:
        # Straight conversion: include the canonical messages as-is.
        openai_messages: list[dict[str, Any]] = []
        if logical_context.system_present:
            sys_range = section_offsets.get("system")
            if sys_range is not None:
                start, end = sys_range
                raw = canonical_bytes[start:end].decode("utf-8")
                lines = raw.splitlines()
                body_lines = lines[1:-1] if len(lines) >= 2 else lines
                sys_text = "\n".join(body_lines)
                if sys_text:
                    openai_messages.append({"role": "system", "content": sys_text})
        for msg in logical_context.messages:
            role = str(msg.get("role", "user")).lower()
            content = msg.get("content", "")
            if isinstance(content, list):
                # OpenAI also supports content parts (images, text); preserve.
                openai_messages.append({"role": role, "content": list(content)})
            else:
                openai_messages.append({"role": role, "content": str(content)})

        body_dict: dict[str, Any] = {
            "model": request_params.model,
            "messages": openai_messages,
            "temperature": request_params.temperature,
        }
        if request_params.max_tokens is not None:
            body_dict["max_tokens"] = request_params.max_tokens
        if request_params.top_p is not None:
            body_dict["top_p"] = request_params.top_p
        if request_params.stop:
            body_dict["stop"] = list(request_params.stop)
        if request_params.stream:
            body_dict["stream"] = True
        if logical_context.tools:
            body_dict["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.get("name"),
                        "description": t.get("description", ""),
                        "parameters": t.get("parameters", {}),
                    },
                }
                for t in logical_context.tools
            ]
        headers = dict(request_params.extra_headers)
        headers.setdefault("Content-Type", "application/json")
        body = json.dumps(body_dict, separators=(",", ":")).encode("utf-8")
        return ProviderRequestBody(
            body=body,
            headers=headers,
            url_suffix="/v1/chat/completions",
        )

    def place_cache_anchors(
        self,
        section_offsets: Mapping[str, tuple[int, int]],
        logical_context: LogicalContext,
    ) -> list[CacheAnchor]:
        # Automatic caching on prefix ≥ 1024 tokens — no explicit anchors.
        return []

    def estimate_cache_hit_rate(self, session_history: SessionHistory) -> CacheHitEstimate:
        total = (
            session_history.recent_cache_read_tokens
            + session_history.recent_uncached_input_tokens
        )
        if total <= 0:
            return CacheHitEstimate(0.0, 0, 0.0)
        rate = session_history.recent_cache_read_tokens / total
        confidence = min(1.0, session_history.request_count / 20.0)
        return CacheHitEstimate(
            expected_hit_rate=rate,
            sample_size=session_history.request_count,
            confidence=confidence,
        )

    def parse_response(self, provider_response: bytes) -> LogicalResponse:
        data = json.loads(provider_response.decode("utf-8"))
        choices = data.get("choices", []) or []
        if not choices:
            return LogicalResponse(content="", finish_reason="", raw=data)
        first = choices[0]
        msg = first.get("message", {}) or {}
        content = str(msg.get("content") or "")
        finish = str(first.get("finish_reason", ""))
        tool_calls_raw = msg.get("tool_calls") or []
        tool_calls = []
        for tc in tool_calls_raw:
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function", {}) or {}
            tool_calls.append({
                "id": tc.get("id"),
                "name": fn.get("name"),
                "arguments": fn.get("arguments", ""),
            })
        return LogicalResponse(
            content=content,
            finish_reason=finish,
            tool_calls=tuple(tool_calls),
            raw=data,
        )

    def parse_usage(self, provider_response: bytes) -> UsageMetrics:
        data = json.loads(provider_response.decode("utf-8"))
        usage = data.get("usage", {}) or {}
        prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
        completion_tokens = int(usage.get("completion_tokens", 0) or 0)
        # OpenAI exposes cached_tokens under prompt_tokens_details (preview API).
        details = usage.get("prompt_tokens_details", {}) or {}
        cached = int(details.get("cached_tokens", 0) or 0)
        uncached = max(0, prompt_tokens - cached)
        return UsageMetrics(
            input_tokens=prompt_tokens,
            output_tokens=completion_tokens,
            cache_creation_tokens=0,
            cache_read_tokens=cached,
            uncached_input_tokens=uncached,
        )

    async def stream_chunks(
        self,
        provider_stream: AsyncIterator[bytes],
    ) -> AsyncIterator[StreamChunk]:
        # Stub: yield nothing. Full parsing lands in CP4.
        if False:
            yield StreamChunk(text="")  # pragma: no cover — keeps the function a generator
        return

    def health_check(self) -> ProviderHealth:
        return ProviderHealth(
            available=True,
            latency_p50_ms=0.0,
            latency_p95_ms=0.0,
            error_rate=0.0,
            last_checked_at=0.0,
        )
