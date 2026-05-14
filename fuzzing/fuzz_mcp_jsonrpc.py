"""Fuzz MCP JSON-RPC message handling."""

from __future__ import annotations

import json
import sys

try:
    import atheris
except ImportError:
    print("Atheris not installed. Install with: pip install atheris")
    print("Recommended: use Linux or WSL2")
    sys.exit(1)

with atheris.instrument_imports():
    from orchesis.engine import PolicyEngine
    from orchesis.interceptors.mcp import McpInterceptor


def _random_message(fdp: atheris.FuzzedDataProvider) -> dict[str, object]:
    method = fdp.PickValueInList(
        ["tools/call", "tools/list", "initialize", "not/method", "../etc/passwd", "tool\u202ename"]
    )
    msg: dict[str, object] = {
        "jsonrpc": fdp.PickValueInList(["2.0", "1.0", "3.0", None]),
        "method": method,
    }
    if fdp.ConsumeBool():
        msg["id"] = fdp.PickValueInList(
            [fdp.ConsumeIntInRange(-1000, 1000), fdp.ConsumeUnicodeNoSurrogates(24), None]
        )
    params: dict[str, object] = {}
    if method == "tools/call":
        params["name"] = fdp.ConsumeUnicodeNoSurrogates(80)
        params["arguments"] = {
            "k": fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 512)),
            "nested": {"a": fdp.ConsumeUnicodeNoSurrogates(32)},
        }
    else:
        params["value"] = fdp.ConsumeUnicodeNoSurrogates(128)
    if fdp.ConsumeBool():
        params["bidi"] = "\u202e" + fdp.ConsumeUnicodeNoSurrogates(8)
    msg["params"] = params
    return msg


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    interceptor = McpInterceptor(PolicyEngine({"rules": []}))
    try:
        # Try raw input as JSON first.
        parsed = json.loads(data.decode("utf-8", errors="ignore"))
    except Exception:
        parsed = _random_message(fdp)

    def _handle_message(msg: dict[str, object]) -> None:
        if not isinstance(msg, dict):
            return
        _ = interceptor.intercept_request(msg, agent_id="fuzz-agent")
        _ = interceptor.intercept_response({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"content": []}}, msg)
        _ = interceptor.intercept_tool_list(
            {
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "result": {"tools": [{"name": "fuzz", "description": str(msg.get("method", ""))}]},
            }
        )

    try:
        if isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict):
                    _handle_message(item)
        elif isinstance(parsed, dict):
            _handle_message(parsed)
        else:
            _handle_message(_random_message(fdp))
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
