"""Fuzz HTTP request parsing in Orchesis proxy."""

from __future__ import annotations

import asyncio
import sys

try:
    import atheris
except ImportError:
    print("Atheris not installed. Install with: pip install atheris")
    print("Recommended: use Linux or WSL2")
    sys.exit(1)

with atheris.instrument_imports():
    from orchesis.engine import PolicyEngine
    from orchesis.proxy import OrchesisProxy, ProxyConfig


def _build_request_bytes(fdp: atheris.FuzzedDataProvider) -> bytes:
    method = fdp.PickValueInList(["GET", "POST", "PUT", "DELETE", "OPTIONS", "GARBAGE"])
    path = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 256)).replace("\n", "").replace("\r", "")
    if not path.startswith("/"):
        path = "/" + path
    version = fdp.PickValueInList(["HTTP/1.1", "HTTP/1.0", "HTTP/9.9", "HTTX/1.1"])
    request_line = f"{method} {path} {version}\r\n"

    header_count = fdp.ConsumeIntInRange(0, 50)
    headers: list[str] = []
    for _ in range(header_count):
        key = fdp.ConsumeUnicodeNoSurrogates(32).replace("\r", "").replace("\n", "") or "X-Fuzz"
        value_len = fdp.ConsumeIntInRange(0, 70_000)
        value = fdp.ConsumeUnicodeNoSurrogates(value_len).replace("\r", "\\r").replace("\n", "\\n")
        headers.append(f"{key}: {value}\r\n")

    body = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 2048))
    if fdp.ConsumeBool():
        headers.append(f"Content-Length: {fdp.ConsumeIntInRange(-10, 80_000)}\r\n")
    else:
        headers.append(f"Content-Length: {len(body)}\r\n")
    if fdp.ConsumeBool():
        headers.append("Transfer-Encoding: chunked\r\n")
    if fdp.ConsumeBool():
        headers.append("X-Injection: value\r\nX-Second: evil\r\n")

    raw = request_line + "".join(headers) + "\r\n"
    return raw.encode("iso-8859-1", errors="ignore") + body


async def _run_parse(raw: bytes) -> None:
    engine = PolicyEngine({"rules": []})
    proxy = OrchesisProxy(engine=engine, config=ProxyConfig(max_body_size=10_000_000), policy={"rules": []})
    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()
    _ = await proxy._read_http_request(reader)  # noqa: SLF001


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    raw = _build_request_bytes(fdp)
    try:
        asyncio.run(_run_parse(raw))
    except (ValueError, TypeError, UnicodeError, asyncio.TimeoutError):
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
