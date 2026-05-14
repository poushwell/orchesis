"""Compression-decode phase.

Decompresses the inbound request body when the client signals a known
compression format. v1 supports `gzip`, `deflate`, and `zstd` (when the
`zstandard` package is installed). Unknown or absent formats are a no-op
"pass".

Decompressed bytes replace `ctx.processed.params["raw_body_decompressed"]`
and the messages list is left to the canonicalize phase to rebuild from
the decoded JSON (callers typically run parse → compression_decode →
canonicalize).
"""

from __future__ import annotations

import gzip
import json
import zlib

from orchesis.pipeline import Phase, PhaseResult, RequestContext


_MAX_DECOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MiB safety cap


class CompressionDecodePhase(Phase):
    name = "compression_decode"
    version = "0.1.0"
    appends_tracking = frozenset({"metrics"})
    timeout_seconds = 1.0
    PRODUCES_HAZARDS = frozenset({"decode_failed", "format_unknown"})

    async def execute(self, ctx: RequestContext) -> PhaseResult:
        fmt = ctx.input.compression_format
        if fmt is None or fmt == "":
            return PhaseResult(status="skip", reason="no compression header")
        raw = ctx.input.raw_body
        if not raw:
            return PhaseResult(status="skip", reason="empty body")
        try:
            decompressed = self._decompress(fmt, raw)
        except _UnknownFormat:
            return PhaseResult(
                status="block",
                reason=f"unknown compression format {fmt!r}",
            )
        except Exception as e:
            return PhaseResult(
                status="block",
                reason=f"decompression failed: {type(e).__name__}: {e}",
            )
        if len(decompressed) > _MAX_DECOMPRESSED_BYTES:
            return PhaseResult(
                status="block",
                reason=(
                    f"decompressed body exceeds limit "
                    f"({len(decompressed)} > {_MAX_DECOMPRESSED_BYTES})"
                ),
            )
        # Stash decoded bytes. If they're JSON, parse and pipe into messages.
        ctx.processed.params["raw_body_decompressed"] = decompressed
        try:
            body = json.loads(decompressed.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return PhaseResult(
                status="pass",
                details={"bytes_decoded": len(decompressed), "json_parsed": False},
            )
        if isinstance(body, dict):
            msgs = body.get("messages")
            if isinstance(msgs, list):
                ctx.processed.messages = list(msgs)
            tools = body.get("tools")
            if isinstance(tools, list):
                ctx.processed.tools = list(tools)
            model = body.get("model")
            if isinstance(model, str) and model:
                ctx.processed.model = model
        ctx.processed.messages_decompressed = True
        return PhaseResult(
            status="pass",
            details={"bytes_decoded": len(decompressed), "json_parsed": True},
        )

    @staticmethod
    def _decompress(fmt: str, raw: bytes) -> bytes:
        f = fmt.lower().strip()
        if f == "gzip":
            return gzip.decompress(raw)
        if f == "deflate":
            return zlib.decompress(raw)
        if f == "zstd":
            try:
                import zstandard  # type: ignore[import-not-found]
            except ImportError:
                raise _UnknownFormat("zstd")
            d = zstandard.ZstdDecompressor()
            return d.decompress(raw)
        raise _UnknownFormat(f)


class _UnknownFormat(Exception):
    pass
