"""Run MCP e2e demo through Orchesis stdio proxy."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import TextContent


def _extract_text(result) -> str:
    texts: list[str] = []
    for item in result.content:
        if isinstance(item, TextContent):
            texts.append(item.text)
    return " | ".join(texts) if texts else "<no text content>"


async def run_demo() -> None:
    project_root = Path(__file__).resolve().parent
    env = os.environ.copy()
    env.update(
        {
            "DOWNSTREAM_COMMAND": "python",
            "DOWNSTREAM_ARGS": "examples/demo_mcp_server.py",
            "POLICY_PATH": "examples/policy.yaml",
        }
    )

    server_params = StdioServerParameters(
        command="python",
        args=["-m", "orchesis.mcp_proxy"],
        env=env,
        cwd=str(project_root),
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            allow_result = await session.call_tool("read_file", arguments={"path": "/data/report.csv"})
            print("read_file('/data/report.csv'):")
            print(f"  isError={allow_result.isError}")
            print(f"  content={_extract_text(allow_result)}")

            deny_delete = await session.call_tool(
                "delete_file", arguments={"path": "/etc/passwd"}
            )
            print("delete_file('/etc/passwd'):")
            print(f"  isError={deny_delete.isError}")
            print(f"  content={_extract_text(deny_delete)}")

            deny_sql = await session.call_tool(
                "run_sql", arguments={"query": "DROP TABLE users"}
            )
            print("run_sql('DROP TABLE users'):")
            print(f"  isError={deny_sql.isError}")
            print(f"  content={_extract_text(deny_sql)}")


def main() -> None:
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
