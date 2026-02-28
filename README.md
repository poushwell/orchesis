# Orchesis

[![CI](https://img.shields.io/badge/CI-pending-lightgrey)](#)
[![PyPI](https://img.shields.io/badge/PyPI-pending-lightgrey)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#license)

Verification kernel for AI agent tool calls.

## Architecture

```text
Client -> Orchesis -> MCP Server
```

Orchesis evaluates each tool call against YAML policy rules before execution:
- ALLOW: call is forwarded
- DENY: call is blocked with reasons

## Quick Start

```bash
pip install orchesis
orchesis init
orchesis verify request.json --policy policy.yaml
```

## MCP Proxy (Interceptor Mode)

Orchesis can run as MCP stdio interceptor between an MCP client and a real MCP server.

### Environment

- `DOWNSTREAM_COMMAND` - executable for real MCP server (example: `python`)
- `DOWNSTREAM_ARGS` - command arguments (example: `examples/demo_mcp_server.py`)
- `POLICY_PATH` - path to policy YAML
- `DEFAULT_TOOL_COST` - fallback cost if tool call has no cost field

### Run

```bash
set DOWNSTREAM_COMMAND=python
set DOWNSTREAM_ARGS=examples/demo_mcp_server.py
set POLICY_PATH=examples/policy.yaml
python -m orchesis.mcp_proxy
```

Alternative entry point:

```bash
orchesis-mcp-proxy
```

## Docker

Build and run backend + proxy:

```bash
docker compose up --build
```

Proxy uses:
- `POLICY_PATH=/app/policy.yaml`
- `BACKEND_URL=http://backend:8081`

## Signed Audit Trail

Generate keys, sign decisions, then verify signatures:

```bash
orchesis keygen
orchesis verify request.json --policy policy.yaml --sign
orchesis audit --verify
```

Expected verification labels:
- `OK`
- `TAMPERED`
- `UNSIGNED`

## Demo

HTTP proxy demo:

```bash
python run_demo.py
```

MCP interceptor demo:

```bash
python run_mcp_demo.py
```

## License

MIT
