"""Anthropic provider adapter.

Implements SPEC §1.6.4 cache-anchor placement:

  - Anchor 1: end of system content (cache_control on last system block).
  - Anchor 2: last tool definition (cache_control on last tool entry).
  - Anchor 3: if documents > 1024 tokens, last document chunk.
  - Anchor 4 rolling: on the (n-1)-th message, where n is the total
    message count. Putting it on the final message would build a cache
    the next request never benefits from.
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


_DOCUMENT_CACHE_THRESHOLD_TOKENS = 1024


class AnthropicAdapter:
    name = "anthropic"
    version = "0.1.0"

    # ---- model matching --------------------------------------------------

    _MODEL_PREFIXES = (
        "claude-",
        "anthropic.claude",
    )

    def supports_model(self, model: str) -> bool:
        m = model.lower().strip()
        return any(m.startswith(p) for p in self._MODEL_PREFIXES)

    # ---- request preparation --------------------------------------------

    def prepare_request_body(
        self,
        canonical_bytes: bytes,
        section_offsets: Mapping[str, tuple[int, int]],
        logical_context: LogicalContext,
        request_params: RequestParams,
    ) -> ProviderRequestBody:
        anchors = self.place_cache_anchors(section_offsets, logical_context)
        anchor_by_section: dict[str, list[CacheAnchor]] = {}
        for a in anchors:
            anchor_by_section.setdefault(a.section, []).append(a)

        # Build messages payload with cache_control attached on anchored items.
        anthropic_messages: list[dict[str, Any]] = []
        message_anchors = anchor_by_section.get("messages", ())
        anchor_message_indices = {
            int(a.position) for a in message_anchors if a.position.lstrip("-").isdigit()
        }
        for idx, msg in enumerate(logical_context.messages):
            mapped = self._convert_message(msg)
            if idx in anchor_message_indices:
                self._apply_cache_control_to_content(mapped)
            anthropic_messages.append(mapped)

        tools_payload: list[dict[str, Any]] = []
        tool_anchors = anchor_by_section.get("tools", ())
        anchor_tool_indices = {
            int(a.position) for a in tool_anchors if a.position.lstrip("-").isdigit()
        }
        for idx, tool in enumerate(logical_context.tools):
            mapped_tool: dict[str, Any] = {
                "name": tool.get("name"),
                "description": tool.get("description", ""),
                "input_schema": tool.get("parameters", {}),
            }
            if idx in anchor_tool_indices:
                mapped_tool["cache_control"] = {"type": "ephemeral"}
            tools_payload.append(mapped_tool)

        system_payload: list[dict[str, Any]] | None = None
        if logical_context.system_present:
            # Pull system text out of the canonical bytes section.
            sys_range = section_offsets.get("system")
            sys_text = ""
            if sys_range is not None:
                start, end = sys_range
                # System section body sits between the opener and closer
                # sentinels. Decoders skip past them.
                raw = canonical_bytes[start:end].decode("utf-8")
                lines = raw.splitlines()
                # Drop "==SYSTEM==" first line and "==/SYSTEM==" last line.
                body_lines = lines[1:-1] if len(lines) >= 2 else lines
                sys_text = "\n".join(body_lines)
            system_payload = [{"type": "text", "text": sys_text}]
            if anchor_by_section.get("system"):
                system_payload[-1]["cache_control"] = {"type": "ephemeral"}

        body_dict: dict[str, Any] = {
            "model": request_params.model,
            "messages": anthropic_messages,
            "temperature": request_params.temperature,
        }
        if request_params.max_tokens is not None:
            body_dict["max_tokens"] = request_params.max_tokens
        else:
            body_dict["max_tokens"] = 1024  # Anthropic requires a value
        if request_params.top_p is not None:
            body_dict["top_p"] = request_params.top_p
        if request_params.stop:
            body_dict["stop_sequences"] = list(request_params.stop)
        if request_params.stream:
            body_dict["stream"] = True
        if system_payload is not None:
            body_dict["system"] = system_payload
        if tools_payload:
            body_dict["tools"] = tools_payload

        body = json.dumps(body_dict, separators=(",", ":")).encode("utf-8")
        headers = dict(request_params.extra_headers)
        headers.setdefault("Content-Type", "application/json")
        headers.setdefault("anthropic-version", "2023-06-01")
        # Cache-control beta header is needed when any anchor is placed.
        if anchors:
            beta = headers.get("anthropic-beta", "")
            tokens = {t.strip() for t in beta.split(",") if t.strip()}
            tokens.add("prompt-caching-2024-07-31")
            headers["anthropic-beta"] = ",".join(sorted(tokens))
        return ProviderRequestBody(
            body=body,
            headers=headers,
            url_suffix="/v1/messages",
        )

    @staticmethod
    def _convert_message(msg: Mapping[str, Any]) -> dict[str, Any]:
        role = str(msg.get("role", "user")).lower()
        if role == "system":
            # System messages move to the top-level `system` field for
            # Anthropic; the proxy is expected to have stripped them
            # before passing the message list, but tolerate anyway.
            role = "user"
        content = msg.get("content", "")
        if isinstance(content, str):
            return {"role": role, "content": [{"type": "text", "text": content}]}
        if isinstance(content, list):
            return {"role": role, "content": [dict(p) for p in content]}
        return {"role": role, "content": [{"type": "text", "text": str(content)}]}

    @staticmethod
    def _apply_cache_control_to_content(msg: dict[str, Any]) -> None:
        content = msg.get("content")
        if isinstance(content, list) and content:
            # Attach to the last content block.
            content[-1] = dict(content[-1])
            content[-1]["cache_control"] = {"type": "ephemeral"}

    # ---- cache anchor placement -----------------------------------------

    def place_cache_anchors(
        self,
        section_offsets: Mapping[str, tuple[int, int]],
        logical_context: LogicalContext,
    ) -> list[CacheAnchor]:
        anchors: list[CacheAnchor] = []
        if logical_context.system_present and "system" in section_offsets:
            anchors.append(CacheAnchor(
                section="system",
                position="end_of_section",
                metadata={"cache_control": {"type": "ephemeral"}},
            ))
        if logical_context.tools and "tools" in section_offsets:
            anchors.append(CacheAnchor(
                section="tools",
                position=str(len(logical_context.tools) - 1),
                metadata={"cache_control": {"type": "ephemeral"}},
            ))
        if (
            logical_context.documents
            and logical_context.document_tokens_estimate >= _DOCUMENT_CACHE_THRESHOLD_TOKENS
            and "documents" in section_offsets
        ):
            anchors.append(CacheAnchor(
                section="documents",
                position=str(len(logical_context.documents) - 1),
                metadata={"cache_control": {"type": "ephemeral"}},
            ))
        n_msgs = len(logical_context.messages)
        if n_msgs >= 2 and "messages" in section_offsets:
            # Anchor at (n-1)-th message — the second-to-last index, so the
            # cache built this request gets hit by the next request.
            anchors.append(CacheAnchor(
                section="messages",
                position=str(n_msgs - 2),
                metadata={"cache_control": {"type": "ephemeral"}},
            ))
        return anchors

    # ---- cache-hit estimation -------------------------------------------

    def estimate_cache_hit_rate(self, session_history: SessionHistory) -> CacheHitEstimate:
        total = (
            session_history.recent_cache_read_tokens
            + session_history.recent_uncached_input_tokens
        )
        if total <= 0:
            return CacheHitEstimate(
                expected_hit_rate=0.0,
                sample_size=0,
                confidence=0.0,
            )
        rate = session_history.recent_cache_read_tokens / total
        # Confidence grows asymptotically with request count.
        confidence = min(1.0, session_history.request_count / 20.0)
        return CacheHitEstimate(
            expected_hit_rate=rate,
            sample_size=session_history.request_count,
            confidence=confidence,
        )

    # ---- response parsing ------------------------------------------------

    def parse_response(self, provider_response: bytes) -> LogicalResponse:
        data = json.loads(provider_response.decode("utf-8"))
        content_blocks = data.get("content", []) or []
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for block in content_blocks:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype == "text":
                text_parts.append(str(block.get("text", "")))
            elif btype == "tool_use":
                tool_calls.append({
                    "id": block.get("id"),
                    "name": block.get("name"),
                    "input": block.get("input", {}),
                })
        return LogicalResponse(
            content="".join(text_parts),
            finish_reason=str(data.get("stop_reason", "")),
            tool_calls=tuple(tool_calls),
            raw=data,
        )

    def parse_usage(self, provider_response: bytes) -> UsageMetrics:
        data = json.loads(provider_response.decode("utf-8"))
        usage = data.get("usage", {}) or {}
        cache_read = int(usage.get("cache_read_input_tokens", 0) or 0)
        cache_creation = int(usage.get("cache_creation_input_tokens", 0) or 0)
        input_tokens = int(usage.get("input_tokens", 0) or 0)
        output_tokens = int(usage.get("output_tokens", 0) or 0)
        uncached = max(0, input_tokens - cache_read - cache_creation)
        return UsageMetrics(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_creation_tokens=cache_creation,
            cache_read_tokens=cache_read,
            uncached_input_tokens=uncached,
        )

    # ---- streaming -------------------------------------------------------

    async def stream_chunks(
        self,
        provider_stream: AsyncIterator[bytes],
    ) -> AsyncIterator[StreamChunk]:
        """Parse Anthropic SSE stream into StreamChunk events."""
        async for raw in provider_stream:
            for line in raw.split(b"\n"):
                if not line.startswith(b"data:"):
                    continue
                payload = line[5:].strip()
                if not payload or payload == b"[DONE]":
                    continue
                try:
                    event = json.loads(payload.decode("utf-8"))
                except json.JSONDecodeError:
                    continue
                etype = event.get("type")
                if etype == "content_block_delta":
                    delta = event.get("delta", {}) or {}
                    text = delta.get("text") if delta.get("type") == "text_delta" else None
                    if text:
                        yield StreamChunk(text=text, raw=event)
                elif etype == "message_stop":
                    yield StreamChunk(text="", is_final=True, raw=event)

    # ---- health ---------------------------------------------------------

    def health_check(self) -> ProviderHealth:
        # The adapter doesn't make live HTTP calls from here; the proxy's
        # health subsystem owns synthetic probes. This default reports
        # unknown-but-available so routing doesn't blacklist Anthropic.
        return ProviderHealth(
            available=True,
            latency_p50_ms=0.0,
            latency_p95_ms=0.0,
            error_rate=0.0,
            last_checked_at=0.0,
        )
