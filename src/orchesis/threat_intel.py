"""Threat Intelligence: built-in knowledge base of AI agent threats and known-bad patterns."""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ThreatCategory(Enum):
    """Categories of AI agent threats."""

    PROMPT_INJECTION = "prompt_injection"
    TOOL_ABUSE = "tool_abuse"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RESOURCE_ABUSE = "resource_abuse"
    SUPPLY_CHAIN = "supply_chain"
    CASCADE_FAILURE = "cascade_failure"
    MODEL_MANIPULATION = "model_manipulation"
    MEMORY_POISONING = "memory_poisoning"
    MULTI_AGENT_EXPLOIT = "multi_agent_exploit"


class ThreatSeverity(Enum):
    """Threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MatchAction(Enum):
    """What to do when a threat is matched."""

    BLOCK = "block"
    WARN = "warn"
    LOG = "log"
    QUARANTINE = "quarantine"


@dataclass(frozen=True)
class ThreatSignature:
    """A single threat pattern in the knowledge base."""

    threat_id: str
    name: str
    category: ThreatCategory
    severity: ThreatSeverity
    description: str
    detection: str
    mitigation: str
    references: tuple[str, ...] = ()
    default_action: MatchAction = MatchAction.WARN
    tool_patterns: tuple[str, ...] = ()
    content_patterns: tuple[str, ...] = ()
    chain_patterns: tuple[tuple[str, ...], ...] = ()
    header_patterns: tuple[str, ...] = ()
    model_patterns: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    owasp_ref: str = ""
    mitre_ref: str = ""
    first_seen: str = ""
    confidence: float = 0.9


@dataclass
class ThreatMatch:
    """Result of matching a request against threat signatures."""

    threat_id: str
    name: str
    category: str
    severity: str
    action: str
    confidence: float
    description: str
    mitigation: str
    matched_pattern: str
    matched_value: str
    references: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "action": self.action,
            "confidence": self.confidence,
            "description": self.description,
            "mitigation": self.mitigation,
            "matched_pattern": self.matched_pattern,
            "matched_value": self.matched_value[:200],
            "references": self.references,
        }


def _severity_actions_default() -> dict[str, str]:
    return {
        "critical": "block",
        "high": "warn",
        "medium": "log",
        "low": "log",
        "info": "log",
    }


@dataclass
class ThreatIntelConfig:
    """Configuration for threat intelligence."""

    enabled: bool = True
    default_action: str = "warn"
    severity_actions: dict[str, str] = field(default_factory=_severity_actions_default)
    custom_signatures: list[dict[str, Any]] = field(default_factory=list)
    disabled_threats: list[str] = field(default_factory=list)
    max_matches_per_request: int = 10


BUILT_IN_THREATS: tuple[ThreatSignature, ...] = (
    ThreatSignature(
        threat_id="ORCH-PI-001",
        name="System Prompt Override",
        category=ThreatCategory.PROMPT_INJECTION,
        severity=ThreatSeverity.CRITICAL,
        description="Attempts to override system prompt via user/tool message injection",
        detection="Content patterns matching prompt override attempts",
        mitigation="Enable input scanning, use system prompt isolation",
        references=("OWASP ASI-07", "AML-T0051"),
        content_patterns=(
            r"(?i)ignore\s+(all\s+)?previous\s+instructions",
            r"(?i)you\s+are\s+now\s+(?:a|an)\s+\w+\s+that",
            r"(?i)forget\s+(all\s+)?your\s+(previous\s+)?instructions",
            r"(?i)system\s*:\s*you\s+are",
            r"(?i)new\s+instruction\s*:",
        ),
        owasp_ref="ASI-07",
        mitre_ref="AML-T0051",
        default_action=MatchAction.BLOCK,
    ),
    ThreatSignature(
        threat_id="ORCH-PI-002",
        name="Indirect Prompt Injection via Tool Result",
        category=ThreatCategory.PROMPT_INJECTION,
        severity=ThreatSeverity.HIGH,
        description="Malicious instructions embedded in tool results that redirect agent behavior",
        detection="Tool result content containing instruction-like patterns",
        mitigation="Scan tool results, implement output validation",
        references=("OWASP ASI-07", "Microsoft XPIA research"),
        content_patterns=(
            r"(?i)<!--\s*ignore\s+previous",
            r"(?i)\[INST\]",
            r"(?i)<\|system\|>",
            r"(?i)IMPORTANT:\s*disregard",
        ),
        owasp_ref="ASI-07",
        default_action=MatchAction.WARN,
    ),
    ThreatSignature(
        threat_id="ORCH-PI-003",
        name="Delimiter Injection",
        category=ThreatCategory.PROMPT_INJECTION,
        severity=ThreatSeverity.HIGH,
        description="Uses special delimiters to break out of context",
        detection="Content with delimiter escape patterns",
        mitigation="Sanitize user input, validate message boundaries",
        references=("OWASP ASI-07",),
        content_patterns=(
            r"(?i)<\|end\|>",
            r"(?i)\[\/INST\]",
            r"(?i)\[\/SYSTEM\]",
        ),
        owasp_ref="ASI-07",
        default_action=MatchAction.WARN,
    ),
    ThreatSignature(
        threat_id="ORCH-TA-001",
        name="Sensitive File Access",
        category=ThreatCategory.TOOL_ABUSE,
        severity=ThreatSeverity.HIGH,
        description="Agent attempts to read sensitive system files",
        detection="Tool calls targeting known sensitive paths",
        mitigation="Configure file_access denied_paths in policy",
        references=("OWASP ASI-02",),
        tool_patterns=(r"read_file", r"cat", r"open"),
        content_patterns=(
            r"(?:/etc/passwd|/etc/shadow|\.env|\.ssh/|id_rsa|\.aws/credentials)",
            r"(?i)(?:api[_-]?key|secret[_-]?key|password)\s*[=:]",
        ),
        owasp_ref="ASI-02",
        default_action=MatchAction.BLOCK,
    ),
    ThreatSignature(
        threat_id="ORCH-TA-002",
        name="Command Injection via Tool",
        category=ThreatCategory.TOOL_ABUSE,
        severity=ThreatSeverity.CRITICAL,
        description="Agent injects shell commands through tool parameters",
        detection="Shell metacharacters in tool arguments",
        mitigation="Sanitize tool inputs, use allowlist for commands",
        references=("OWASP ASI-02", "CWE-78"),
        content_patterns=(
            r"[;&|$]\s*(rm|curl|wget|nc|bash|sh|python|perl|ruby)\b",
            r"\$\([^)]*\)",
            r"`(?:rm|curl|wget|nc|bash|sh|python|perl|ruby)\b[^`]*`",
        ),
        owasp_ref="ASI-02",
        default_action=MatchAction.BLOCK,
    ),
    ThreatSignature(
        threat_id="ORCH-TA-003",
        name="Excessive Permission Tool",
        category=ThreatCategory.TOOL_ABUSE,
        severity=ThreatSeverity.MEDIUM,
        description="Agent uses tools that grant broad system access",
        detection="Tool names matching known dangerous tools",
        mitigation="Restrict tool access to allowlist",
        references=("OWASP ASI-03",),
        tool_patterns=(r"(?i)^(exec|execute|run_command|shell|bash|eval|sudo)$",),
        owasp_ref="ASI-03",
        default_action=MatchAction.BLOCK,
    ),
    ThreatSignature(
        threat_id="ORCH-TA-004",
        name="Database DROP/DELETE",
        category=ThreatCategory.TOOL_ABUSE,
        severity=ThreatSeverity.CRITICAL,
        description="Agent attempts destructive database operations",
        detection="Tool content with DROP/DELETE/TRUNCATE",
        mitigation="Use allowed_operations allowlist",
        references=("OWASP ASI-02",),
        content_patterns=(
            r"(?i)\b(?:DROP\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM\s+\w+\s*$)",
        ),
        owasp_ref="ASI-02",
        default_action=MatchAction.BLOCK,
    ),
    ThreatSignature(
        threat_id="ORCH-DE-001",
        name="Data Exfiltration via HTTP",
        category=ThreatCategory.DATA_EXFILTRATION,
        severity=ThreatSeverity.CRITICAL,
        description="Agent reads sensitive data then sends it to external URL",
        detection="Tool chain: read/query → http_request/fetch",
        mitigation="Block external HTTP after sensitive reads, enable denied_domains",
        references=("OWASP ASI-06", "AML-T0048"),
        chain_patterns=(
            ("read_file", "http_request"),
            ("read_file", "fetch_url"),
            ("database_query", "http_request"),
            ("get_secret", "http_request"),
            ("get_secret", "fetch_url"),
        ),
        owasp_ref="ASI-06",
        mitre_ref="AML-T0048",
        default_action=MatchAction.BLOCK,
    ),
    ThreatSignature(
        threat_id="ORCH-DE-002",
        name="Encoded Data Exfiltration",
        category=ThreatCategory.DATA_EXFILTRATION,
        severity=ThreatSeverity.HIGH,
        description="Agent encodes sensitive data (base64/hex) before sending externally",
        detection="Base64/hex encoded content in outbound tool calls",
        mitigation="Scan for encoded payloads in tool parameters",
        references=("OWASP ASI-06",),
        content_patterns=(
            r"(?:base64|btoa|atob)\s*\(",
            r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{60,}={0,2}(?![A-Za-z0-9+/])",
        ),
        owasp_ref="ASI-06",
        default_action=MatchAction.WARN,
    ),
    ThreatSignature(
        threat_id="ORCH-DE-003",
        name="DNS Exfiltration",
        category=ThreatCategory.DATA_EXFILTRATION,
        severity=ThreatSeverity.MEDIUM,
        description="Data exfiltration via DNS queries",
        detection="DNS lookup with encoded subdomains",
        mitigation="Restrict DNS resolution, monitor DNS traffic",
        references=("OWASP ASI-06",),
        content_patterns=(r"(?i)dns_lookup|nslookup|resolve\s+.*\.exfil\.",),
        owasp_ref="ASI-06",
        default_action=MatchAction.WARN,
    ),
    ThreatSignature(
        threat_id="ORCH-PE-001",
        name="Trust Tier Bypass",
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        severity=ThreatSeverity.HIGH,
        description="Agent attempts to access tools beyond its trust tier",
        detection="Tool chain showing progressive permission increase",
        mitigation="Enforce strict trust tier boundaries",
        references=("OWASP ASI-03",),
        chain_patterns=(
            ("list_tools", "use_admin_tool"),
            ("get_permissions", "modify_permissions"),
        ),
        owasp_ref="ASI-03",
        default_action=MatchAction.BLOCK,
    ),
    ThreatSignature(
        threat_id="ORCH-PE-002",
        name="Role Impersonation",
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        severity=ThreatSeverity.HIGH,
        description="Request attempts to impersonate higher-privilege role",
        detection="Header or content claiming elevated role",
        mitigation="Validate identity, ignore role claims in content",
        references=("OWASP ASI-03",),
        content_patterns=(
            r"(?i)I\s+am\s+(?:admin|root|superuser|system)",
            r"(?i)acting\s+as\s+(?:admin|root)",
        ),
        owasp_ref="ASI-03",
        default_action=MatchAction.WARN,
    ),
    ThreatSignature(
        threat_id="ORCH-RA-001",
        name="Token Bomb",
        category=ThreatCategory.RESOURCE_ABUSE,
        severity=ThreatSeverity.MEDIUM,
        description="Extremely large prompt designed to exhaust token budget",
        detection="Single message exceeding reasonable token threshold",
        mitigation="Enable token_limits and context_engine token_budget",
        references=("OWASP ASI-08",),
        owasp_ref="ASI-08",
        default_action=MatchAction.WARN,
        tags=("resource", "dos"),
    ),
    ThreatSignature(
        threat_id="ORCH-RA-002",
        name="Recursive Tool Loop",
        category=ThreatCategory.RESOURCE_ABUSE,
        severity=ThreatSeverity.HIGH,
        description="Agent caught in infinite tool call loop burning resources",
        detection="Same tool called repeatedly with identical/similar args",
        mitigation="Enable loop_detection with block action",
        references=("OWASP ASI-08",),
        owasp_ref="ASI-08",
        default_action=MatchAction.WARN,
        tags=("resource", "loop"),
    ),
    ThreatSignature(
        threat_id="ORCH-RA-003",
        name="Context Window Stuffing",
        category=ThreatCategory.RESOURCE_ABUSE,
        severity=ThreatSeverity.MEDIUM,
        description="Excessive messages to overflow context window",
        detection="Very high message count in single request",
        mitigation="Enable context_engine sliding_window, set message limits",
        references=("OWASP ASI-08",),
        owasp_ref="ASI-08",
        default_action=MatchAction.LOG,
        tags=("resource", "context"),
    ),
    ThreatSignature(
        threat_id="ORCH-SC-001",
        name="Malicious MCP Server",
        category=ThreatCategory.SUPPLY_CHAIN,
        severity=ThreatSeverity.CRITICAL,
        description="Connection to known-malicious or typosquatted MCP server",
        detection="MCP server URL matching known-bad patterns",
        mitigation="Verify MCP servers before connecting, use MCP scanner",
        references=("OWASP ASI-05",),
        content_patterns=(r"(?i)npx\s+-y\s+@[a-z]+-mcp/",),
        owasp_ref="ASI-05",
        default_action=MatchAction.BLOCK,
    ),
    ThreatSignature(
        threat_id="ORCH-SC-002",
        name="Dependency Confusion",
        category=ThreatCategory.SUPPLY_CHAIN,
        severity=ThreatSeverity.HIGH,
        description="Malicious package name confusion attack",
        detection="Suspicious package install patterns",
        mitigation="Use private registry, verify package integrity",
        references=("OWASP ASI-05",),
        content_patterns=(r"(?i)npm\s+install\s+@(?:internal|private)-",),
        owasp_ref="ASI-05",
        default_action=MatchAction.WARN,
    ),
    ThreatSignature(
        threat_id="ORCH-CF-001",
        name="Error Amplification Chain",
        category=ThreatCategory.CASCADE_FAILURE,
        severity=ThreatSeverity.HIGH,
        description="Agent error triggers retry storm across multiple tools",
        detection="Multiple consecutive errors with escalating retry attempts",
        mitigation="Enable circuit_breaker and loop_detection",
        references=("OWASP ASI-08", "ASI-10"),
        owasp_ref="ASI-08",
        default_action=MatchAction.WARN,
        tags=("cascade", "reliability"),
    ),
    ThreatSignature(
        threat_id="ORCH-CF-002",
        name="Feedback Loop Between Agents",
        category=ThreatCategory.CASCADE_FAILURE,
        severity=ThreatSeverity.MEDIUM,
        description="Agents triggering each other in infinite loop",
        detection="Circular tool call patterns across agents",
        mitigation="Implement agent isolation, rate limits",
        references=("OWASP ASI-08",),
        owasp_ref="ASI-08",
        default_action=MatchAction.WARN,
    ),
    ThreatSignature(
        threat_id="ORCH-MM-001",
        name="Model Downgrade Attack",
        category=ThreatCategory.MODEL_MANIPULATION,
        severity=ThreatSeverity.MEDIUM,
        description="Request attempts to force use of weaker model for exploitation",
        detection="Model parameter set to known-weak model for security-sensitive task",
        mitigation="Enforce minimum model tier for sensitive operations",
        references=("OWASP ASI-01",),
        owasp_ref="ASI-01",
        default_action=MatchAction.LOG,
    ),
    ThreatSignature(
        threat_id="ORCH-MM-002",
        name="Jailbreak via Model Switching",
        category=ThreatCategory.MODEL_MANIPULATION,
        severity=ThreatSeverity.HIGH,
        description="Switching to less secure model to bypass safeguards",
        detection="Model override in request for sensitive task",
        mitigation="Lock model for sensitive operations",
        references=("OWASP ASI-01",),
        model_patterns=(r"(?i)gpt-3\.5|claude-instant|haiku",),
        owasp_ref="ASI-01",
        default_action=MatchAction.WARN,
    ),
    ThreatSignature(
        threat_id="ORCH-MP-001",
        name="Memory Injection via Tool Result",
        category=ThreatCategory.MEMORY_POISONING,
        severity=ThreatSeverity.HIGH,
        description="Malicious payload in tool result designed to persist in agent memory",
        detection="Tool results containing memory/instruction injection patterns",
        mitigation="Scan tool results, implement memory validation",
        references=("OWASP ASI-04", "Microsoft memory poisoning PoC"),
        content_patterns=(
            r"(?i)remember\s+this\s+for\s+(?:all\s+)?future",
            r"(?i)always\s+(?:do|use|prefer|recommend)\s+",
            r"(?i)from\s+now\s+on\s+you\s+(?:must|should|will)",
        ),
        owasp_ref="ASI-04",
        default_action=MatchAction.WARN,
    ),
    ThreatSignature(
        threat_id="ORCH-MP-002",
        name="Persistent Instruction Override",
        category=ThreatCategory.MEMORY_POISONING,
        severity=ThreatSeverity.HIGH,
        description="Attempt to permanently change agent behavior",
        detection="Content instructing permanent behavior change",
        mitigation="Validate tool outputs, limit memory scope",
        references=("OWASP ASI-04",),
        content_patterns=(
            r"(?i)store\s+this\s+(?:in\s+)?(?:memory|context)",
            r"(?i)never\s+(?:forget|change)\s+",
        ),
        owasp_ref="ASI-04",
        default_action=MatchAction.WARN,
    ),
    ThreatSignature(
        threat_id="ORCH-MA-001",
        name="Agent Impersonation in Multi-Agent",
        category=ThreatCategory.MULTI_AGENT_EXPLOIT,
        severity=ThreatSeverity.HIGH,
        description="Request claims to be from different agent to bypass policy",
        detection="Agent ID spoofing in headers or content",
        mitigation="Validate agent identity, use signed tokens",
        references=("OWASP ASI-03",),
        content_patterns=(
            r"(?i)X-Orchesis-Agent\s*:\s*\w+",
            r"(?i)acting\s+on\s+behalf\s+of\s+",
        ),
        owasp_ref="ASI-03",
        default_action=MatchAction.WARN,
    ),
    ThreatSignature(
        threat_id="ORCH-PI-004",
        name="Jailbreak via Roleplay",
        category=ThreatCategory.PROMPT_INJECTION,
        severity=ThreatSeverity.MEDIUM,
        description="Uses roleplay scenario to bypass safety guidelines",
        detection="Content requesting roleplay to bypass restrictions",
        mitigation="Validate roleplay requests, enforce content policy",
        references=("OWASP ASI-07",),
        content_patterns=(
            r"(?i)pretend\s+you\s+(?:are|have)\s+no\s+(?:restrictions|limits)",
            r"(?i)in\s+this\s+scenario\s+you\s+can\s+",
        ),
        owasp_ref="ASI-07",
        default_action=MatchAction.WARN,
    ),
)


class ThreatMatcher:
    """
    Matches requests/responses against threat intelligence database.
    Thread-safe. Compiled regex for performance.
    """

    def __init__(self, config: Optional[ThreatIntelConfig] = None) -> None:
        self._config = config or ThreatIntelConfig()
        self._lock = threading.Lock()
        self._threats: dict[str, ThreatSignature] = {}
        self._compiled_content: list[tuple[str, re.Pattern[str]]] = []
        self._compiled_tools: list[tuple[str, re.Pattern[str]]] = []
        self._chain_index: list[tuple[str, tuple[str, ...]]] = []
        self._total_scans: int = 0
        self._total_matches: int = 0
        self._matches_by_category: dict[str, int] = {}
        self._matches_by_severity: dict[str, int] = {}
        self._matches_by_threat: dict[str, int] = {}
        self._blocks: int = 0
        self._warns: int = 0
        self._load_threats()

    def _load_threats(self) -> None:
        disabled = set(self._config.disabled_threats)
        for sig in BUILT_IN_THREATS:
            if sig.threat_id in disabled:
                continue
            self._threats[sig.threat_id] = sig
            for pattern in sig.content_patterns:
                try:
                    self._compiled_content.append((sig.threat_id, re.compile(pattern)))
                except re.error:
                    pass
            for pattern in sig.tool_patterns:
                try:
                    self._compiled_tools.append((sig.threat_id, re.compile(pattern)))
                except re.error:
                    pass
            for chain in sig.chain_patterns:
                self._chain_index.append((sig.threat_id, chain))
        for custom in self._config.custom_signatures:
            if isinstance(custom, dict):
                self._load_custom_signature(custom)

    def _load_custom_signature(self, data: dict[str, Any]) -> None:
        threat_id = str(data.get("threat_id", "CUSTOM-001"))
        name = str(data.get("name", "Custom Threat"))
        cat_raw = str(data.get("category", "tool_abuse"))
        try:
            category = ThreatCategory(cat_raw)
        except ValueError:
            category = ThreatCategory.TOOL_ABUSE
        sev_raw = str(data.get("severity", "medium"))
        try:
            severity = ThreatSeverity(sev_raw)
        except ValueError:
            severity = ThreatSeverity.MEDIUM
        content_pats = tuple(
            str(p) for p in data.get("content_patterns", []) if isinstance(p, str)
        )
        tool_pats = tuple(
            str(p) for p in data.get("tool_patterns", []) if isinstance(p, str)
        )
        chain_pats = ()
        raw_chains = data.get("chain_patterns", [])
        if isinstance(raw_chains, list):
            chains = []
            for c in raw_chains:
                if isinstance(c, (list, tuple)):
                    chains.append(tuple(str(x) for x in c))
            chain_pats = tuple(chains)
        sig = ThreatSignature(
            threat_id=threat_id,
            name=name,
            category=category,
            severity=severity,
            description=str(data.get("description", "")),
            detection=str(data.get("detection", "")),
            mitigation=str(data.get("mitigation", "")),
            references=tuple(str(r) for r in data.get("references", [])),
            content_patterns=content_pats,
            tool_patterns=tool_pats,
            chain_patterns=chain_pats,
        )
        self._threats[threat_id] = sig
        for p in content_pats:
            try:
                self._compiled_content.append((threat_id, re.compile(p)))
            except re.error:
                pass
        for p in tool_pats:
            try:
                self._compiled_tools.append((threat_id, re.compile(p)))
            except re.error:
                pass
        for chain in chain_pats:
            self._chain_index.append((threat_id, chain))

    def _extract_all_text(self, messages: list[dict[str, Any]]) -> str:
        parts: list[str] = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
                continue
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        text = block.get("text", "") or block.get("content", "")
                        if isinstance(text, str):
                            parts.append(text)
                        inp = block.get("input", {})
                        if isinstance(inp, dict):
                            parts.append(json.dumps(inp))
        return "\n".join(parts)

    def _resolve_action(self, sig: ThreatSignature) -> str:
        action = self._config.severity_actions.get(
            sig.severity.value, self._config.default_action
        )
        return str(action)

    def scan_request(
        self,
        messages: list[dict[str, Any]],
        tools: list[str],
        tool_calls: list[dict[str, Any]],
        model: str = "",
        headers: dict[str, str] | None = None,
    ) -> list[ThreatMatch]:
        if not self._config.enabled:
            return []
        with self._lock:
            self._total_scans += 1
        matches: list[ThreatMatch] = []
        seen: set[str] = set()
        text = self._extract_all_text(messages)
        headers_str = ""
        if headers:
            headers_str = json.dumps(headers, sort_keys=True)

        for threat_id, pat in self._compiled_content:
            if threat_id in seen:
                continue
            m = pat.search(text)
            if m:
                sig = self._threats.get(threat_id)
                if sig:
                    action = self._resolve_action(sig)
                    matches.append(
                        ThreatMatch(
                            threat_id=sig.threat_id,
                            name=sig.name,
                            category=sig.category.value,
                            severity=sig.severity.value,
                            action=action,
                            confidence=sig.confidence,
                            description=sig.description,
                            mitigation=sig.mitigation,
                            matched_pattern=pat.pattern[:80],
                            matched_value=m.group(0)[:200],
                            references=list(sig.references),
                        )
                    )
                    seen.add(threat_id)

        tool_names = [str(t) for t in tools if t]
        for tc in tool_calls:
            name = tc.get("name", "") if isinstance(tc, dict) else ""
            if name:
                tool_names.append(str(name))
            inp = tc.get("input", tc.get("params", {})) if isinstance(tc, dict) else {}
            if isinstance(inp, dict):
                text += "\n" + json.dumps(inp)
            elif isinstance(inp, str):
                text += "\n" + inp

        for threat_id, pat in self._compiled_tools:
            if threat_id in seen:
                continue
            for tn in tool_names:
                if pat.search(tn):
                    sig = self._threats.get(threat_id)
                    if sig:
                        action = self._resolve_action(sig)
                        matches.append(
                            ThreatMatch(
                                threat_id=sig.threat_id,
                                name=sig.name,
                                category=sig.category.value,
                                severity=sig.severity.value,
                                action=action,
                                confidence=sig.confidence,
                                description=sig.description,
                                mitigation=sig.mitigation,
                                matched_pattern=pat.pattern[:80],
                                matched_value=tn[:200],
                                references=list(sig.references),
                            )
                        )
                        seen.add(threat_id)
                    break

        tool_sequence = [
            str(tc.get("name", ""))
            for tc in tool_calls
            if isinstance(tc, dict) and tc.get("name")
        ]

        def _chain_matches(seq: list[str], expected_chain: tuple[str, ...]) -> tuple[bool, str]:
            """Subsequence match: chain can have gaps."""
            if len(expected_chain) < 2 or len(seq) < len(expected_chain):
                return False, ""
            idx = 0
            matched: list[str] = []
            for exp in expected_chain:
                while idx < len(seq):
                    if re.search(re.escape(exp), seq[idx], re.IGNORECASE):
                        matched.append(seq[idx])
                        idx += 1
                        break
                    idx += 1
                else:
                    return False, ""
            return True, ",".join(matched)

        for threat_id, chain in self._chain_index:
            if threat_id in seen:
                continue
            if len(chain) < 2:
                continue
            ok, matched_val = _chain_matches(tool_sequence, chain)
            if ok:
                sig = self._threats.get(threat_id)
                if sig:
                    action = self._resolve_action(sig)
                    matches.append(
                        ThreatMatch(
                            threat_id=sig.threat_id,
                            name=sig.name,
                            category=sig.category.value,
                            severity=sig.severity.value,
                            action=action,
                            confidence=sig.confidence,
                            description=sig.description,
                            mitigation=sig.mitigation,
                            matched_pattern="chain:" + ",".join(chain),
                            matched_value=matched_val,
                            references=list(sig.references),
                        )
                    )
                    seen.add(threat_id)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        matches.sort(key=lambda x: (severity_order.get(x.severity, 5), x.threat_id))
        limited = matches[: self._config.max_matches_per_request]

        with self._lock:
            self._total_matches += len(limited)
            for m in limited:
                self._matches_by_category[m.category] = (
                    self._matches_by_category.get(m.category, 0) + 1
                )
                self._matches_by_severity[m.severity] = (
                    self._matches_by_severity.get(m.severity, 0) + 1
                )
                self._matches_by_threat[m.threat_id] = (
                    self._matches_by_threat.get(m.threat_id, 0) + 1
                )
                if m.action == "block":
                    self._blocks += 1
                elif m.action == "warn":
                    self._warns += 1

        return limited

    def scan_response(
        self,
        content: str,
        tool_results: list[dict[str, Any]],
    ) -> list[ThreatMatch]:
        if not self._config.enabled:
            return []
        text = content or ""
        for tr in tool_results or []:
            if isinstance(tr, dict):
                c = tr.get("content", tr.get("text", ""))
                if isinstance(c, str):
                    text += "\n" + c
        return self.scan_request(
            messages=[{"role": "user", "content": text}],
            tools=[],
            tool_calls=[],
        )

    def get_threat(self, threat_id: str) -> ThreatSignature | None:
        return self._threats.get(threat_id)

    def list_threats(
        self, category: str = "", severity: str = ""
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for sig in self._threats.values():
            if category and sig.category.value != category:
                continue
            if severity and sig.severity.value != severity:
                continue
            result.append(
                {
                    "threat_id": sig.threat_id,
                    "name": sig.name,
                    "category": sig.category.value,
                    "severity": sig.severity.value,
                    "description": sig.description,
                    "mitigation": sig.mitigation,
                    "owasp_ref": sig.owasp_ref,
                    "references": list(sig.references),
                }
            )
        return result

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self._config.enabled,
                "total_signatures": len(self._threats),
                "total_scans": self._total_scans,
                "total_matches": self._total_matches,
                "blocks": self._blocks,
                "warns": self._warns,
                "matches_by_category": dict(self._matches_by_category),
                "matches_by_severity": dict(self._matches_by_severity),
                "top_threats": sorted(
                    self._matches_by_threat.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[:10],
            }
