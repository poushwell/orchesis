"""MCP JSON-RPC interceptors and stdio proxy."""

from __future__ import annotations

import asyncio
from copy import deepcopy
import json
import re
import sys
from typing import Any

from orchesis.contrib.ioc_database import IoCMatcher
from orchesis.contrib.secret_scanner import SecretScanner
from orchesis.redaction import AuditRedactor


class McpInterceptor:
    """Intercept and enforce policy on MCP JSON-RPC messages."""

    def __init__(self, engine, event_bus=None, policy: dict[str, Any] | None = None, redactor=None):
        self._engine = engine
        self._event_bus = event_bus
        self._policy = policy if isinstance(policy, dict) else {}
        self._secret_scanner = SecretScanner()
        self._ioc_matcher = IoCMatcher()
        self._redactor = redactor if redactor is not None else AuditRedactor()

    def intercept_request(
        self,
        message: dict[str, Any],
        agent_id: str = "mcp_agent",
        session_type: str = "cli",
    ) -> dict[str, Any] | None:
        if not self.is_tool_call(message):
            return None
        extracted = self.extract_tool_info(message)
        if extracted is None:
            return None
        tool_name, arguments = extracted
        payload = {
            "tool": tool_name,
            "params": arguments,
            "cost": 0.0,
            "context": {"agent": agent_id, "transport": "mcp"},
        }
        decision = self._evaluate(payload, session_type=session_type)
        if bool(getattr(decision, "allowed", True)):
            return None
        reason, rule, severity = self._extract_reason_rule_severity(decision)
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {
                "code": -32001,
                "message": f"Blocked by policy: {reason}",
                "data": {"rule": rule, "severity": severity},
            },
        }

    def intercept_response(
        self,
        message: dict[str, Any],
        original_request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        _ = original_request
        result = deepcopy(message)
        try:
            result_payload = result.get("result")
            if not isinstance(result_payload, dict):
                return result
            content = result_payload.get("content")
            if not isinstance(content, list):
                return result
            updated: list[Any] = []
            findings: list[dict[str, Any]] = []
            for item in content:
                if not isinstance(item, dict):
                    updated.append(item)
                    continue
                if item.get("type") == "text" and isinstance(item.get("text"), str):
                    text = item["text"]
                    findings.extend(self._secret_scanner.scan_text(text))
                    redacted = self._redactor.redact_string(text) if self._redactor is not None else text
                    new_item = dict(item)
                    new_item["text"] = redacted
                    updated.append(new_item)
                else:
                    updated.append(item)
            result_payload["content"] = updated
            if findings:
                result["orchesis_scan"] = {"secrets_found": len(findings)}
            return result
        except Exception:
            return result

    def intercept_tool_list(self, message: dict[str, Any]) -> dict[str, Any]:
        result = dict(message)
        payload = result.get("result")
        if not isinstance(payload, dict):
            return result
        tools = payload.get("tools")
        if not isinstance(tools, list):
            return result

        filtered_tools = list(tools)
        tool_access = self._policy.get("tool_access")
        if isinstance(tool_access, dict):
            mode = str(tool_access.get("mode", "")).lower()
            allowed = tool_access.get("allowed")
            if mode == "allowlist" and isinstance(allowed, list):
                allowset = {str(item) for item in allowed if isinstance(item, str)}
                filtered_tools = [
                    item
                    for item in filtered_tools
                    if isinstance(item, dict) and str(item.get("name", "")) in allowset
                ]

        ioc_findings: list[dict[str, Any]] = []
        for tool in filtered_tools:
            if not isinstance(tool, dict):
                continue
            description = tool.get("description")
            if isinstance(description, str):
                matches = self._ioc_matcher.scan_text(description)
                if not matches and re.search(r"https?://(?:\d{1,3}\.){3}\d{1,3}", description):
                    matches = [
                        {
                            "ioc_id": "SUSP-URL-IP",
                            "ioc_name": "Suspicious URL with IP host",
                            "category": "tool_poisoning",
                            "severity": "high",
                            "matched_pattern": "http(s)://<ip>",
                            "position": 0,
                            "match": description,
                        }
                    ]
                if matches:
                    ioc_findings.extend(matches)

        payload["tools"] = filtered_tools
        if ioc_findings:
            result["orchesis_ioc_findings"] = ioc_findings[:10]
        return result

    @staticmethod
    def is_tool_call(message: dict[str, Any]) -> bool:
        return message.get("method") == "tools/call" and "id" in message

    @staticmethod
    def extract_tool_info(message: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
        params = message.get("params", {})
        if not isinstance(params, dict):
            return None
        name = params.get("name")
        args = params.get("arguments", {})
        if isinstance(name, str):
            return name, args if isinstance(args, dict) else {}
        return None

    def _evaluate(self, payload: dict[str, Any], session_type: str):
        if hasattr(self._engine, "evaluate"):
            return self._engine.evaluate(payload, session_type=session_type)
        if callable(self._engine):
            return self._engine(payload, session_type=session_type)
        raise TypeError("Engine must be callable or expose evaluate().")

    def _extract_reason_rule_severity(self, decision) -> tuple[str, str, str]:
        reasons = getattr(decision, "reasons", [])
        reason = reasons[0] if isinstance(reasons, list) and reasons else "blocked_by_policy"
        rule = reason.split(":", 1)[0] if ":" in reason else "policy"
        severity = "high" if "daily token budget" in reason.lower() else "medium"
        return reason, rule, severity


class McpStdioProxy:
    """Proxy for MCP stdio transport with policy interception."""

    def __init__(self, engine, server_command: list[str], agent_id: str = "mcp_agent", event_bus=None):
        self._engine = engine
        self._server_command = list(server_command)
        self._agent_id = agent_id
        self._event_bus = event_bus
        self._interceptor = McpInterceptor(engine, event_bus)
        self._process: asyncio.subprocess.Process | None = None
        self._tasks: list[asyncio.Task[Any]] = []

    async def start(self):
        if not self._server_command:
            raise ValueError("server_command is required")
        self._process = await asyncio.create_subprocess_exec(
            *self._server_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._tasks = [
            asyncio.create_task(self._proxy_client_to_server()),
            asyncio.create_task(self._proxy_server_to_client()),
        ]
        await asyncio.gather(*self._tasks)

    async def stop(self):
        if self._process is None:
            return
        if self._process.returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
        for task in self._tasks:
            if not task.done():
                task.cancel()

    async def _read_jsonrpc(self, reader) -> dict[str, Any] | None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=30.0)
        except Exception:
            return None
        if not line:
            return None
        try:
            parsed = json.loads(line.decode("utf-8"))
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            return None

    async def _write_jsonrpc(self, writer, message: dict[str, Any]):
        raw = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
        writer.write(raw)
        await writer.drain()

    async def _proxy_client_to_server(self):
        if self._process is None or self._process.stdin is None:
            return
        client_reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(client_reader)
        await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, sys.stdin)
        server_writer = self._process.stdin
        while True:
            message = await self._read_jsonrpc(client_reader)
            if message is None:
                break
            deny = self._interceptor.intercept_request(message, agent_id=self._agent_id)
            if deny is not None:
                out = (json.dumps(deny, ensure_ascii=False) + "\n").encode("utf-8")
                sys.stdout.buffer.write(out)
                sys.stdout.buffer.flush()
                continue
            server_writer.write((json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8"))
            await server_writer.drain()

    async def _proxy_server_to_client(self):
        if self._process is None or self._process.stdout is None:
            return
        while True:
            message = await self._read_jsonrpc(self._process.stdout)
            if message is None:
                break
            out = self._interceptor.intercept_response(message)
            sys.stdout.buffer.write((json.dumps(out, ensure_ascii=False) + "\n").encode("utf-8"))
            sys.stdout.buffer.flush()
