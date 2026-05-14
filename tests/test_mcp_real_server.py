from __future__ import annotations

import os
import shutil
import shlex
import sys
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

pytestmark = pytest.mark.skipif(
    shutil.which("orchesis") is None,
    reason="requires orchesis CLI installed",
)


def _sqlite_server_command() -> tuple[str, list[str]]:
    python_dir = Path(sys.executable).resolve().parent
    exe = python_dir / "Scripts" / "mcp-server-sqlite.exe"
    if not exe.exists():
        exe = python_dir.with_name("Scripts") / "mcp-server-sqlite.exe"
    if not exe.exists():
        pytest.skip("mcp-server-sqlite executable is not available")
    return str(exe), []


def _write_policy(path: Path) -> None:
    path.write_text(
        """
rules:
  - name: sql_restriction
    denied_operations:
      - DROP
      - DELETE
      - TRUNCATE
      - ALTER
  - name: file_access
    allowed_paths:
      - "/data"
      - "/tmp"
    denied_paths:
      - "/etc"
      - "/root"
""".strip(),
        encoding="utf-8",
    )


@asynccontextmanager
async def _proxy_session(
    *,
    policy_path: Path,
    downstream_command: str,
    downstream_args: list[str],
    timeout_seconds: float | None = None,
):
    env = os.environ.copy()
    env["POLICY_PATH"] = str(policy_path)
    env["DOWNSTREAM_COMMAND"] = downstream_command
    env["DOWNSTREAM_ARGS"] = " ".join(shlex.quote(arg) for arg in downstream_args)
    if timeout_seconds is not None:
        env["DOWNSTREAM_TIMEOUT_SECONDS"] = str(timeout_seconds)

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "orchesis.mcp_proxy"],
        env=env,
        cwd=Path(__file__).resolve().parents[1],
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


@pytest.mark.asyncio
async def test_real_sqlite_tools_passthrough(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    db_path = tmp_path / "demo.db"
    _write_policy(policy_path)
    command, base_args = _sqlite_server_command()

    async with _proxy_session(
        policy_path=policy_path,
        downstream_command=command,
        downstream_args=[*base_args, "--db-path", str(db_path)],
    ) as session:
        tools = await session.list_tools()
        names = {tool.name for tool in tools.tools}

    assert "read_query" in names
    assert "write_query" in names


@pytest.mark.asyncio
async def test_real_sqlite_allow_safe_read_operation(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    db_path = tmp_path / "demo.db"
    _write_policy(policy_path)
    command, base_args = _sqlite_server_command()

    async with _proxy_session(
        policy_path=policy_path,
        downstream_command=command,
        downstream_args=[*base_args, "--db-path", str(db_path)],
    ) as session:
        result = await session.call_tool("read_query", {"query": "SELECT 1 AS n"})

    assert result.isError is False


@pytest.mark.asyncio
async def test_real_sqlite_deny_delete_operation(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    db_path = tmp_path / "demo.db"
    _write_policy(policy_path)
    command, base_args = _sqlite_server_command()

    async with _proxy_session(
        policy_path=policy_path,
        downstream_command=command,
        downstream_args=[*base_args, "--db-path", str(db_path)],
    ) as session:
        result = await session.call_tool("write_query", {"query": "DELETE FROM users"})

    assert result.isError is True
    assert "DELETE is denied" in result.content[0].text


@pytest.mark.asyncio
async def test_real_sqlite_malformed_arguments_are_graceful(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    db_path = tmp_path / "demo.db"
    _write_policy(policy_path)
    command, base_args = _sqlite_server_command()

    async with _proxy_session(
        policy_path=policy_path,
        downstream_command=command,
        downstream_args=[*base_args, "--db-path", str(db_path)],
    ) as session:
        result = await session.call_tool("read_query", {"query": 123})

    assert result.isError is True


@pytest.mark.asyncio
async def test_proxy_handles_downstream_timeout(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    slow_server = tmp_path / "slow_server.py"
    _write_policy(policy_path)
    slow_server.write_text(
        """
import asyncio
import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("slow-server")

@server.list_tools()
async def list_tools():
    return [types.Tool(name="slow_tool", inputSchema={"type":"object","properties":{}})]

@server.call_tool()
async def call_tool(name, arguments):
    _ = (name, arguments)
    await asyncio.sleep(5)
    return [types.TextContent(type="text", text="done")]

async def run():
    async with mcp.server.stdio.stdio_server() as (r, w):
        await server.run(
            r,
            w,
            InitializationOptions(
                server_name="slow-server",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={}
                ),
            ),
        )

asyncio.run(run())
""".strip(),
        encoding="utf-8",
    )

    async with _proxy_session(
        policy_path=policy_path,
        downstream_command=sys.executable,
        downstream_args=[str(slow_server)],
        timeout_seconds=0.5,
    ) as session:
        result = await session.call_tool(
            "slow_tool",
            {},
            read_timeout_seconds=timedelta(seconds=3),
        )

    assert result.isError is True
    assert "timeout" in result.content[0].text.lower()


@pytest.mark.asyncio
async def test_proxy_handles_downstream_crash(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    crash_server = tmp_path / "crash_server.py"
    _write_policy(policy_path)
    crash_server.write_text(
        """
import os
import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("crash-server")

@server.list_tools()
async def list_tools():
    return [types.Tool(name="crash_tool", inputSchema={"type":"object","properties":{}})]

@server.call_tool()
async def call_tool(name, arguments):
    _ = (name, arguments)
    os._exit(1)

async def run():
    async with mcp.server.stdio.stdio_server() as (r, w):
        await server.run(
            r,
            w,
            InitializationOptions(
                server_name="crash-server",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={}
                ),
            ),
        )

import asyncio
asyncio.run(run())
""".strip(),
        encoding="utf-8",
    )

    async with _proxy_session(
        policy_path=policy_path,
        downstream_command=sys.executable,
        downstream_args=[str(crash_server)],
    ) as session:
        result = await session.call_tool(
            "crash_tool",
            {},
            read_timeout_seconds=timedelta(seconds=3),
        )

    assert result.isError is True
