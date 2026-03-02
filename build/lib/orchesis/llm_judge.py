"""LLM-as-a-judge scanners using OpenAI-compatible chat completions API."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class LLMJudge:
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        base_url: str = "https://api.openai.com/v1",
        timeout: int = 30,
        max_retries: int = 1,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = int(timeout)
        self._max_retries = int(max_retries)

    def _call_chat(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        url = f"{self._base_url}/chat/completions"
        payload = {
            "model": self._model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            url=url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
        )
        attempts = self._max_retries + 1
        last_error: Exception | None = None
        for _ in range(attempts):
            try:
                with urllib.request.urlopen(request, timeout=self._timeout) as response:
                    raw = response.read().decode("utf-8")
                    parsed = json.loads(raw)
                    return parsed if isinstance(parsed, dict) else {}
            except urllib.error.HTTPError as error:
                if error.code >= 500:
                    last_error = error
                    continue
                return {}
            except (urllib.error.URLError, TimeoutError) as error:
                last_error = error
                continue
            except Exception:
                return {}
        _ = last_error
        return {}

    @staticmethod
    def _extract_findings(response_payload: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            choices = response_payload.get("choices")
            if not isinstance(choices, list) or not choices:
                return []
            message = choices[0].get("message")
            if not isinstance(message, dict):
                return []
            content = message.get("content")
            if not isinstance(content, str) or not content.strip():
                return []
            parsed = json.loads(content)
            findings = parsed.get("findings") if isinstance(parsed, dict) else None
            if not isinstance(findings, list):
                return []
            output: list[dict[str, Any]] = []
            for item in findings:
                if not isinstance(item, dict):
                    continue
                severity = item.get("severity")
                category = item.get("category")
                description = item.get("description")
                recommendation = item.get("recommendation", "")
                if isinstance(severity, str) and isinstance(category, str) and isinstance(description, str):
                    output.append(
                        {
                            "severity": severity.upper(),
                            "category": category,
                            "description": description,
                            "recommendation": recommendation if isinstance(recommendation, str) else "",
                            "source": "llm-judge",
                        }
                    )
            return output
        except Exception:
            return []

    def analyze_tool(self, tool_name: str, tool_description: str, tool_parameters: dict[str, Any]) -> list[dict[str, Any]]:
        system_prompt = (
            "You are a security auditor. Return strict JSON: "
            '{"findings":[{"severity":"HIGH|MEDIUM|LOW","category":"...","description":"...","recommendation":"..."}]}.'
        )
        user_prompt = (
            f"Analyze tool for security risks.\n"
            f"Name: {tool_name}\n"
            f"Description: {tool_description}\n"
            f"Parameters JSON: {json.dumps(tool_parameters, ensure_ascii=False)}\n"
            "Focus on prompt injection, overly broad permissions, exfiltration, hidden behavior, supply-chain indicators."
        )
        response = self._call_chat(system_prompt, user_prompt)
        return self._extract_findings(response)

    def analyze_skill(self, skill_content: str) -> list[dict[str, Any]]:
        system_prompt = (
            "You are a security auditor. Return strict JSON: "
            '{"findings":[{"severity":"HIGH|MEDIUM|LOW","category":"...","description":"...","recommendation":"..."}]}.'
        )
        user_prompt = (
            "Analyze skill content for hidden commands, obfuscation, social engineering, and privilege escalation.\n"
            f"Skill content:\n{skill_content}"
        )
        response = self._call_chat(system_prompt, user_prompt)
        return self._extract_findings(response)

    def analyze_policy(self, policy_yaml: str) -> list[dict[str, Any]]:
        system_prompt = (
            "You are a security auditor. Return strict JSON: "
            '{"findings":[{"severity":"HIGH|MEDIUM|LOW","category":"...","description":"...","recommendation":"..."}]}.'
        )
        user_prompt = (
            "Analyze policy YAML for contradictions, permissive defaults, missing restrictions, and bypass vectors.\n"
            f"Policy:\n{policy_yaml}"
        )
        response = self._call_chat(system_prompt, user_prompt)
        return self._extract_findings(response)

    def batch_analyze_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for start in range(0, len(tools), 10):
            batch = tools[start : start + 10]
            system_prompt = (
                "You are a security auditor. Return strict JSON: "
                '{"findings":[{"severity":"HIGH|MEDIUM|LOW","category":"...","description":"...","recommendation":"..."}]}.'
            )
            user_prompt = (
                "Analyze these tools for security risk. "
                "Focus on prompt injection, broad permissions, exfiltration and deception.\n"
                f"Tools JSON:\n{json.dumps(batch, ensure_ascii=False)}"
            )
            response = self._call_chat(system_prompt, user_prompt)
            findings.extend(self._extract_findings(response))
        return findings
