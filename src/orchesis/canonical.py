"""Canonical form generator for provider-agnostic request bodies.

Produces a byte-deterministic representation of system prompts, tool
definitions, documents, and messages. Used as a cache key by the upstream
phase and as the basis for differential testing across Python versions.

Normalizations are layered:

  N1 — Whitespace (code-fence-aware text normalization)
  N2 — Unicode NFC
  N3 — JCS (RFC 8785 JSON Canonicalization Scheme)
  N4 — Tool canonical record + lexicographic sort by name
  N5 — Message canonical record
  N6 — Document chunk record (id = sha256 of N1 content)
  N7 — Footer-bounded section assembly

Determinism contract: bytes_out is a pure function of the logical input.
Same input on any platform / Python version produces the same bytes.

Public API:
    canonicalize(*, system, tools, documents, messages) -> bytes
    canonicalize_with_offsets(...) -> (bytes, section_offsets)
    jcs_encode(obj) -> bytes
    normalize_text(text) -> str   (N1+N2)
    nfc(text) -> str              (N2 only)
    CanonicalError                 raised for any structural / size failure
    MAX_OUTPUT_AMPLIFICATION       hard cap relative to input bytes (§1.9.5)
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Any, Iterable, Mapping, Sequence


# Hard cap: canonical output bytes ≤ amplification × input bytes.
# Defends against NFKC-style length amplification attacks per SPEC §1.9.5.
MAX_OUTPUT_AMPLIFICATION = 10

# Section sentinels — fixed bytes. Footer-bounded so decoder counts via the
# closing sentinel rather than a length header.
_SECTION_OPEN = {
    "system": b"==SYSTEM==\n",
    "tools": b"==TOOLS==\n",
    "documents": b"==DOCUMENTS==\n",
    "messages": b"==MESSAGES==\n",
}
_SECTION_CLOSE = {
    "system": b"==/SYSTEM==\n",
    "tools": b"==/TOOLS==\n",
    "documents": b"==/DOCUMENTS==\n",
    "messages": b"==/MESSAGES==\n",
}

_VALID_ROLES = frozenset({"user", "assistant", "system", "tool"})


class CanonicalError(Exception):
    """Raised on structural error or hard limit violation."""


# ---------------------------------------------------------------------------
# N2: Unicode NFC
# ---------------------------------------------------------------------------


def nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


# ---------------------------------------------------------------------------
# N1: Whitespace canonicalization, code-fence-aware.
# ---------------------------------------------------------------------------


# Fence opener: line starting with optional leading whitespace, then 3+ backticks,
# optionally followed by language tag (alphanumerics, dashes, underscores, dots).
_FENCE_OPEN_RE = re.compile(r"^([ \t]*)(`{3,})([\w\-.+]*)\s*$")


def normalize_text(text: str) -> str:
    """Apply N2 (NFC) then N1 (whitespace).

    Inside fenced code blocks, content is preserved verbatim except line
    endings are normalized to LF. Outside fences:
        - Run of internal whitespace (space, tab, post-NFC NBSP U+00A0)
          collapse to one ASCII space.
        - Trailing whitespace per line stripped.
        - Run of 2+ blank lines collapse to one blank line.
    Final pass: all line endings normalize to LF. Leading/trailing whitespace
    of the whole text is stripped.
    """
    if not isinstance(text, str):
        raise CanonicalError(f"text must be str, got {type(text).__name__}")
    text = nfc(text)
    # Normalize all line endings before fence detection.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")

    out_lines: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _FENCE_OPEN_RE.match(line)
        if m:
            indent, ticks, _lang = m.groups()
            # Preserve opener verbatim except strip trailing whitespace.
            out_lines.append(line.rstrip(" \t"))
            i += 1
            # Capture body up to closing fence with ≥ same number of ticks.
            min_close = len(ticks)
            while i < len(lines):
                inner = lines[i]
                close_match = re.match(r"^[ \t]*(`{%d,})\s*$" % min_close, inner)
                if close_match:
                    out_lines.append(inner.rstrip(" \t"))
                    i += 1
                    break
                out_lines.append(inner)  # verbatim inside fence
                i += 1
            else:
                # Unterminated fence — leave body verbatim (already appended).
                pass
            continue
        # Outside fence: collapse internal whitespace, strip trailing.
        collapsed = re.sub(r"[ \t ]+", " ", line).rstrip(" \t ")
        out_lines.append(collapsed)
        i += 1

    # Collapse 2+ blank lines to a single blank line.
    compact: list[str] = []
    prev_blank = False
    for ln in out_lines:
        if ln == "":
            if not prev_blank:
                compact.append(ln)
            prev_blank = True
        else:
            compact.append(ln)
            prev_blank = False

    return "\n".join(compact).strip()


# ---------------------------------------------------------------------------
# N3: JCS (RFC 8785) — stdlib implementation.
# ---------------------------------------------------------------------------


def jcs_encode(obj: Any) -> bytes:
    """Serialize a JSON-compatible value as RFC 8785 canonical bytes."""
    parts: list[str] = []
    _jcs_encode_into(obj, parts, depth=0)
    return "".join(parts).encode("utf-8")


_JCS_MAX_DEPTH = 200


def _jcs_encode_into(obj: Any, parts: list[str], depth: int) -> None:
    if depth > _JCS_MAX_DEPTH:
        raise CanonicalError("JSON nesting exceeds JCS depth limit")
    if obj is None:
        parts.append("null")
        return
    if isinstance(obj, bool):  # must come before int
        parts.append("true" if obj else "false")
        return
    if isinstance(obj, (int, float)):
        parts.append(_jcs_format_number(obj))
        return
    if isinstance(obj, str):
        parts.append(_jcs_encode_string(obj))
        return
    if isinstance(obj, Mapping):
        items = list(obj.items())
        # Reject non-string keys to avoid silent stringification differences.
        for k, _ in items:
            if not isinstance(k, str):
                raise CanonicalError(f"object key must be str, got {type(k).__name__}")
        # UTF-16 BE code unit order
        items.sort(key=lambda kv: kv[0].encode("utf-16-be"))
        parts.append("{")
        first = True
        for k, v in items:
            if not first:
                parts.append(",")
            first = False
            parts.append(_jcs_encode_string(k))
            parts.append(":")
            _jcs_encode_into(v, parts, depth + 1)
        parts.append("}")
        return
    if isinstance(obj, (list, tuple)):
        parts.append("[")
        first = True
        for v in obj:
            if not first:
                parts.append(",")
            first = False
            _jcs_encode_into(v, parts, depth + 1)
        parts.append("]")
        return
    raise CanonicalError(f"unsupported type {type(obj).__name__} in JCS encoder")


# ECMA-262 §7.1.12.1 NumberToString, per RFC 8785 §3.2.2.3.

def _jcs_format_number(x: int | float) -> str:
    if isinstance(x, bool):  # defensive
        raise CanonicalError("bool reached number formatter")
    if isinstance(x, int):
        if abs(x) > 2 ** 53 - 1:
            # JSON interop limit per RFC 7159 / RFC 8785 guidance.
            # Reject silently-lossy ints; caller must encode as string if needed.
            raise CanonicalError(f"integer {x} exceeds IEEE-754 safe range")
        return str(x)
    # float
    if x != x:
        raise CanonicalError("NaN not allowed in JCS")
    if x == float("inf") or x == float("-inf"):
        raise CanonicalError("Infinity not allowed in JCS")
    if x == 0.0:
        return "0"
    sign = "-" if x < 0 else ""
    x_abs = abs(x)
    sig, n = _decompose_float(x_abs)
    if not sig:
        return "0"
    k = len(sig)

    if k <= n <= 21:
        return sign + sig + "0" * (n - k)
    if 0 < n <= 21:
        return sign + sig[:n] + "." + sig[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + sig
    # Scientific
    exp = n - 1
    if exp >= 0:
        exp_str = "e+" + str(exp)
    else:
        exp_str = "e-" + str(-exp)
    if k == 1:
        return sign + sig + exp_str
    return sign + sig[0] + "." + sig[1:] + exp_str


def _decompose_float(x: float) -> tuple[str, int]:
    """Return (significand_digits, n) where n satisfies 10**(n-1) ≤ x < 10**n.

    Significand has no leading or trailing zeros.
    """
    if x == 0.0:
        return "", 0
    s = repr(x)  # Python uses Grisu/Ryu → shortest round-trip
    if "e" in s or "E" in s:
        m_str, exp_str = s.lower().split("e")
        e = int(exp_str)
    else:
        m_str = s
        e = 0
    if "." in m_str:
        int_part, frac_part = m_str.split(".")
    else:
        int_part, frac_part = m_str, ""

    all_digits = int_part + frac_part
    stripped_leading = all_digits.lstrip("0")
    sig = stripped_leading.rstrip("0")
    if not sig:
        return "", 0
    # n = (digits in significant prefix) + (decimal-shift exponent)
    # where decimal-shift = e - len(frac_part), and significant prefix length
    # is len(stripped_leading). After stripping trailing zeros, the position of
    # the implied decimal point relative to first sig digit is unchanged.
    n = len(stripped_leading) + e - len(frac_part)
    return sig, n


def _jcs_encode_string(s: str) -> str:
    """RFC 8785 §3.2.2.2 string serialization with NFC normalization."""
    s = nfc(s)
    out: list[str] = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif cp < 0x20:
            if cp == 0x08:
                out.append("\\b")
            elif cp == 0x09:
                out.append("\\t")
            elif cp == 0x0A:
                out.append("\\n")
            elif cp == 0x0C:
                out.append("\\f")
            elif cp == 0x0D:
                out.append("\\r")
            else:
                out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


# ---------------------------------------------------------------------------
# N4: Tool canonical record.
# ---------------------------------------------------------------------------


def _canonicalize_tool(tool: Mapping[str, Any]) -> bytes:
    if "name" not in tool:
        raise CanonicalError("tool missing 'name'")
    name = tool["name"]
    if not isinstance(name, str):
        raise CanonicalError("tool 'name' must be a string")
    description = tool.get("description", "")
    if not isinstance(description, str):
        raise CanonicalError("tool 'description' must be a string")
    parameters = tool.get("parameters", {})
    if not isinstance(parameters, Mapping):
        raise CanonicalError("tool 'parameters' must be an object")
    record = {
        "name": name,
        "description": normalize_text(description),
        "parameters": _canonicalize_json_schema(parameters),
    }
    return jcs_encode(record)


def _canonicalize_json_schema(schema: Mapping[str, Any]) -> Any:
    """Pass-through for JSON Schema dicts. JCS encoder handles sorting + types."""
    return _coerce_json_compatible(schema)


def _coerce_json_compatible(obj: Any) -> Any:
    """Recursively walk a Mapping/list tree, leaving JSON-native types intact.

    Rejects values that JCS cannot encode (sets, bytes, custom classes).
    """
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, Mapping):
        return {str(k): _coerce_json_compatible(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_coerce_json_compatible(v) for v in obj]
    raise CanonicalError(f"value of type {type(obj).__name__} is not JSON-compatible")


def canonicalize_tools(tools: Sequence[Mapping[str, Any]]) -> list[bytes]:
    """Return per-tool JCS bytes, sorted lex by tool name."""
    seen: set[str] = set()
    records: list[tuple[str, bytes]] = []
    for tool in tools:
        if "name" not in tool or not isinstance(tool["name"], str):
            raise CanonicalError("tool requires string 'name'")
        name = tool["name"]
        if name in seen:
            raise CanonicalError(f"duplicate tool name {name!r}")
        seen.add(name)
        records.append((name, _canonicalize_tool(tool)))
    records.sort(key=lambda kv: kv[0].encode("utf-8"))
    return [r for _, r in records]


# ---------------------------------------------------------------------------
# N5: Message canonical record.
# ---------------------------------------------------------------------------


def _canonicalize_message(msg: Mapping[str, Any]) -> bytes:
    role_raw = msg.get("role")
    if not isinstance(role_raw, str):
        raise CanonicalError("message 'role' must be a string")
    role = role_raw.lower()
    if role not in _VALID_ROLES:
        raise CanonicalError(f"message role {role!r} not in {sorted(_VALID_ROLES)}")
    record: dict[str, Any] = {"role": role}
    content = msg.get("content")
    if isinstance(content, str):
        record["content"] = normalize_text(content)
    elif isinstance(content, (list, tuple)):
        # Content parts — list of dicts. Each part goes through JCS as-is
        # except string fields get N1-normalized.
        record["content"] = [_canonicalize_message_part(p) for p in content]
    elif content is None:
        record["content"] = ""
    else:
        raise CanonicalError(f"message content must be str or list, got {type(content).__name__}")
    if "tool_calls" in msg:
        if role != "assistant":
            raise CanonicalError("tool_calls only allowed on assistant messages")
        tcs = msg["tool_calls"]
        if not isinstance(tcs, (list, tuple)):
            raise CanonicalError("tool_calls must be a list")
        record["tool_calls"] = [_coerce_json_compatible(tc) for tc in tcs]
    if "tool_call_id" in msg:
        if role != "tool":
            raise CanonicalError("tool_call_id only allowed on tool messages")
        tcid = msg["tool_call_id"]
        if not isinstance(tcid, str):
            raise CanonicalError("tool_call_id must be a string")
        record["tool_call_id"] = tcid
    if "name" in msg:
        nm = msg["name"]
        if not isinstance(nm, str):
            raise CanonicalError("message name must be a string")
        record["name"] = nm
    return jcs_encode(record)


def _canonicalize_message_part(part: Any) -> Any:
    if isinstance(part, str):
        return normalize_text(part)
    if isinstance(part, Mapping):
        out: dict[str, Any] = {}
        for k, v in part.items():
            if isinstance(v, str):
                out[str(k)] = normalize_text(v)
            else:
                out[str(k)] = _coerce_json_compatible(v)
        return out
    return _coerce_json_compatible(part)


def canonicalize_messages(messages: Sequence[Mapping[str, Any]]) -> list[bytes]:
    return [_canonicalize_message(m) for m in messages]


# ---------------------------------------------------------------------------
# N6: Document chunk canonical record.
# ---------------------------------------------------------------------------


def _canonicalize_document(doc: Mapping[str, Any]) -> bytes:
    content_raw = doc.get("content", "")
    if not isinstance(content_raw, str):
        raise CanonicalError("document 'content' must be a string")
    content = normalize_text(content_raw)
    doc_id = doc.get("id")
    if doc_id is None:
        doc_id = hashlib.sha256(content.encode("utf-8")).hexdigest()
    elif not isinstance(doc_id, str):
        raise CanonicalError("document 'id' must be a string")
    record: dict[str, Any] = {"id": doc_id, "content": content}
    if "metadata" in doc:
        md = doc["metadata"]
        if not isinstance(md, Mapping):
            raise CanonicalError("document 'metadata' must be an object")
        record["metadata"] = _coerce_json_compatible(md)
    return jcs_encode(record)


def canonicalize_documents(documents: Sequence[Mapping[str, Any]]) -> list[bytes]:
    # Order preserved — RAG ranking semantic.
    return [_canonicalize_document(d) for d in documents]


# ---------------------------------------------------------------------------
# N7: Section assembly with footer-bounded sentinels.
# ---------------------------------------------------------------------------


def canonicalize(
    *,
    system: str | None = None,
    tools: Sequence[Mapping[str, Any]] | None = None,
    documents: Sequence[Mapping[str, Any]] | None = None,
    messages: Sequence[Mapping[str, Any]] | None = None,
    input_size_hint: int | None = None,
) -> bytes:
    """Assemble the full canonical form.

    Sections are emitted in fixed order: SYSTEM, TOOLS, DOCUMENTS, MESSAGES.
    Empty sections are omitted entirely (including their sentinels) so adding
    e.g. tools later does not invalidate the cached prefix.

    Args:
        system: system prompt text (or None to omit).
        tools: list of tool dicts (or None/empty to omit).
        documents: list of document chunks (or None/empty to omit).
        messages: list of message dicts (or None/empty to omit).
        input_size_hint: optional total input bytes count for amplification
            check per SPEC §1.9.5. If provided, output is rejected when it
            exceeds MAX_OUTPUT_AMPLIFICATION × hint.
    """
    out, _ = canonicalize_with_offsets(
        system=system,
        tools=tools,
        documents=documents,
        messages=messages,
        input_size_hint=input_size_hint,
    )
    return out


def canonicalize_with_offsets(
    *,
    system: str | None = None,
    tools: Sequence[Mapping[str, Any]] | None = None,
    documents: Sequence[Mapping[str, Any]] | None = None,
    messages: Sequence[Mapping[str, Any]] | None = None,
    input_size_hint: int | None = None,
) -> tuple[bytes, dict[str, tuple[int, int]]]:
    """Same as canonicalize() but also returns half-open byte offsets for
    each emitted section, keyed by section name (lowercase). Useful for
    placing provider cache anchors at section boundaries.
    """
    chunks: list[bytes] = []
    offsets: dict[str, tuple[int, int]] = {}

    cursor = 0

    if system:
        body = normalize_text(system)
        section = _SECTION_OPEN["system"] + body.encode("utf-8") + b"\n" + _SECTION_CLOSE["system"]
        offsets["system"] = (cursor, cursor + len(section))
        chunks.append(section)
        cursor += len(section)

    if tools:
        records = canonicalize_tools(tools)
        body = b"\n".join(records) + b"\n" if records else b""
        section = _SECTION_OPEN["tools"] + body + _SECTION_CLOSE["tools"]
        offsets["tools"] = (cursor, cursor + len(section))
        chunks.append(section)
        cursor += len(section)

    if documents:
        records = canonicalize_documents(documents)
        body = b"\n".join(records) + b"\n" if records else b""
        section = _SECTION_OPEN["documents"] + body + _SECTION_CLOSE["documents"]
        offsets["documents"] = (cursor, cursor + len(section))
        chunks.append(section)
        cursor += len(section)

    if messages:
        records = canonicalize_messages(messages)
        body = b"\n".join(records) + b"\n" if records else b""
        section = _SECTION_OPEN["messages"] + body + _SECTION_CLOSE["messages"]
        offsets["messages"] = (cursor, cursor + len(section))
        chunks.append(section)
        cursor += len(section)

    result = b"".join(chunks)
    if input_size_hint is not None and input_size_hint > 0:
        if len(result) > MAX_OUTPUT_AMPLIFICATION * input_size_hint:
            raise CanonicalError(
                f"canonical output ({len(result)} bytes) exceeds amplification "
                f"limit ({MAX_OUTPUT_AMPLIFICATION}× of {input_size_hint})"
            )
    return result, offsets


def parse_sections(data: bytes) -> dict[str, bytes]:
    """Inverse of canonicalize for testing: split a canonical buffer back
    into its section bodies. Useful for differential test harnesses.
    """
    result: dict[str, bytes] = {}
    cursor = 0
    while cursor < len(data):
        # Find next opener.
        matched: tuple[str, int] | None = None
        for name, opener in _SECTION_OPEN.items():
            if data[cursor:cursor + len(opener)] == opener:
                matched = (name, cursor + len(opener))
                break
        if matched is None:
            raise CanonicalError(f"expected section opener at byte {cursor}")
        name, body_start = matched
        closer = _SECTION_CLOSE[name]
        close_idx = data.find(closer, body_start)
        if close_idx < 0:
            raise CanonicalError(f"section {name!r} missing closer")
        result[name] = data[body_start:close_idx]
        cursor = close_idx + len(closer)
    return result


# ---------------------------------------------------------------------------
# Convenience: chunked record splitter for messages/tools/documents body.
# ---------------------------------------------------------------------------


def split_records(body: bytes) -> list[bytes]:
    """Split a section body (where each record ends in '\\n') into records."""
    if not body:
        return []
    if not body.endswith(b"\n"):
        raise CanonicalError("section body must end with newline")
    return body[:-1].split(b"\n") if body[:-1] else []
