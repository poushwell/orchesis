"""Tests for CanonicalizePhase + CompressionDecodePhase."""

from __future__ import annotations

import asyncio
import gzip
import json
import zlib

import pytest

from orchesis.phases import CanonicalizePhase, CompressionDecodePhase
from orchesis.pipeline import (
    Identity,
    InputSnapshot,
    Processed,
    RecordingHandle,
    RequestContext,
    Tracking,
)


def _ctx(*, raw_body=b"", original_messages=(), original_tools=(),
         compression_format=None, model="m"):
    return RequestContext(
        id=Identity("r", "s", "a", "c", "lite"),
        input=InputSnapshot(
            raw_body=raw_body,
            original_messages=tuple(original_messages),
            original_tools=tuple(original_tools),
            requested_model=model,
            requested_params={},
            provider_hint=None,
            headers={},
            compression_format=compression_format,
        ),
        processed=Processed(),
        tracking=Tracking(),
        recording=RecordingHandle(),
    )


# ---------------------------------------------------------------------------
# CanonicalizePhase
# ---------------------------------------------------------------------------


class TestCanonicalizePhase:
    def test_no_op_when_already_canonicalized(self):
        ctx = _ctx()
        ctx.processed.messages_canonicalized = True
        result = asyncio.run(CanonicalizePhase().execute(ctx))
        assert result.status == "skip"

    def test_canonicalizes_input(self):
        msgs = (
            {"role": "system", "content": "be terse"},
            {"role": "user", "content": "hi"},
        )
        ctx = _ctx(original_messages=msgs, raw_body=b'{"messages":[]}')
        result = asyncio.run(CanonicalizePhase().execute(ctx))
        assert result.status == "pass"
        assert "canonical_bytes" in ctx.processed.params
        assert ctx.processed.messages_canonicalized is True
        out = ctx.processed.params["canonical_bytes"]
        assert b"==SYSTEM==" in out
        assert b"==MESSAGES==" in out

    def test_extracts_system_text(self):
        # raw_body must reflect realistic request size so the amplification
        # guard doesn't reject the small synthetic canonical output.
        ctx = _ctx(
            original_messages=(
                {"role": "system", "content": "be helpful"},
                {"role": "user", "content": "hi"},
            ),
            raw_body=b'{"messages":[{"role":"system","content":"be helpful"},'
                     b'{"role":"user","content":"hi"}]}',
        )
        asyncio.run(CanonicalizePhase().execute(ctx))
        out = ctx.processed.params["canonical_bytes"]
        assert b"be helpful" in out

    def test_no_system_when_absent(self):
        ctx = _ctx(
            original_messages=({"role": "user", "content": "hi"},),
            raw_body=b'{"messages":[{"role":"user","content":"hi"}]}',
        )
        asyncio.run(CanonicalizePhase().execute(ctx))
        out = ctx.processed.params["canonical_bytes"]
        assert b"==SYSTEM==" not in out

    def test_blocks_on_canonical_error(self):
        # Size hint of 1 forces the amplification guard to fire on any
        # non-trivial output.
        ctx = _ctx(
            original_messages=({"role": "user", "content": "x" * 1000},),
            raw_body=b"x",  # size_hint = 1
        )
        result = asyncio.run(CanonicalizePhase().execute(ctx))
        assert result.status == "block"
        assert "canonicalization failed" in result.reason


# ---------------------------------------------------------------------------
# CompressionDecodePhase
# ---------------------------------------------------------------------------


class TestCompressionDecodePhase:
    def test_skips_when_no_format(self):
        ctx = _ctx()
        result = asyncio.run(CompressionDecodePhase().execute(ctx))
        assert result.status == "skip"

    def test_skips_when_empty_body(self):
        ctx = _ctx(raw_body=b"", compression_format="gzip")
        result = asyncio.run(CompressionDecodePhase().execute(ctx))
        assert result.status == "skip"

    def test_gzip_roundtrip(self):
        body = {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}],
                "tools": [{"name": "search"}]}
        raw = gzip.compress(json.dumps(body).encode("utf-8"))
        ctx = _ctx(raw_body=raw, compression_format="gzip")
        result = asyncio.run(CompressionDecodePhase().execute(ctx))
        assert result.status == "pass"
        assert ctx.processed.messages_decompressed is True
        assert ctx.processed.model == "gpt-4o"
        assert ctx.processed.messages == [{"role": "user", "content": "hi"}]
        assert ctx.processed.tools == [{"name": "search"}]

    def test_deflate_roundtrip(self):
        body = {"model": "claude-3", "messages": []}
        raw = zlib.compress(json.dumps(body).encode("utf-8"))
        ctx = _ctx(raw_body=raw, compression_format="deflate")
        result = asyncio.run(CompressionDecodePhase().execute(ctx))
        assert result.status == "pass"

    def test_unknown_format_blocks(self):
        ctx = _ctx(raw_body=b"\x00\x01\x02", compression_format="brotli")
        result = asyncio.run(CompressionDecodePhase().execute(ctx))
        assert result.status == "block"
        assert "unknown" in result.reason.lower()

    def test_corrupted_body_blocks(self):
        ctx = _ctx(raw_body=b"not gzip", compression_format="gzip")
        result = asyncio.run(CompressionDecodePhase().execute(ctx))
        assert result.status == "block"
        assert "decompression failed" in result.reason

    def test_non_json_payload_still_passes(self):
        raw = gzip.compress(b"this is not json")
        ctx = _ctx(raw_body=raw, compression_format="gzip")
        result = asyncio.run(CompressionDecodePhase().execute(ctx))
        assert result.status == "pass"
        assert result.details["json_parsed"] is False

    def test_size_limit_enforced(self):
        # Synthesize a payload that decompresses to a giant string.
        # Gzip compresses repeated bytes very well; create a "zip bomb"-ish.
        big = b"A" * (51 * 1024 * 1024)
        raw = gzip.compress(big)
        ctx = _ctx(raw_body=raw, compression_format="gzip")
        result = asyncio.run(CompressionDecodePhase().execute(ctx))
        assert result.status == "block"
        assert "exceeds limit" in result.reason
