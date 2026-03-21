"""
Paperclip/OpenClaw-specific injection and abuse patterns.

These patterns detect attacks specific to the Paperclip framework:
budget manipulation, goal hijacking, cascade exploitation,
and plugin-based injection vectors.

Designed to be registered with IoCMatcher as an opt-in family.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from orchesis.utils.log import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class PaperclipPattern:
    pattern_id: str
    name: str
    category: str
    regex: str
    severity: str
    description: str
    mitre_ref: str = ""


BUDGET_PATTERNS = [
    PaperclipPattern(
        pattern_id="PC-BUD-001",
        name="Zero cost report",
        category="budget_spoof",
        regex=r"(?i)(?:cost|budget|spend|charge)\s*[:=]\s*\$?0+\.?0*\b",
        severity="HIGH",
        description="Agent reporting zero cost - possible budget spoofing.",
    ),
    PaperclipPattern(
        pattern_id="PC-BUD-002",
        name="Budget override attempt",
        category="budget_spoof",
        regex=r"(?i)(?:set|override|change|update)\s+(?:budget|limit|spending)\s+(?:to|=)",
        severity="HIGH",
        description="Attempt to override budget limits via prompt.",
    ),
    PaperclipPattern(
        pattern_id="PC-BUD-003",
        name="Cost field manipulation",
        category="budget_spoof",
        regex=r"(?i)(?:total_cost|usage_cost|token_cost)\s*=\s*0",
        severity="MEDIUM",
        description="Direct cost field assignment to zero.",
    ),
]


GOAL_PATTERNS = [
    PaperclipPattern(
        pattern_id="PC-GOAL-001",
        name="Goal override injection",
        category="goal_hijack",
        regex=r"(?i)(?:your\s+(?:new|real|actual)\s+goal|forget\s+(?:your|the)\s+(?:original|previous)\s+goal)",
        severity="HIGH",
        description="Attempt to replace agent's original goal.",
    ),
    PaperclipPattern(
        pattern_id="PC-GOAL-002",
        name="Goal API manipulation",
        category="goal_hijack",
        regex=r"(?i)(?:set_goal|update_goal|change_objective)\s*\(",
        severity="HIGH",
        description="Direct goal API call in text - possible injection.",
    ),
    PaperclipPattern(
        pattern_id="PC-GOAL-003",
        name="Task completion spoofing",
        category="goal_hijack",
        regex=r"(?i)(?:task\s+(?:is\s+)?complet(?:e|ed)|goal\s+(?:is\s+)?(?:achiev|reach|done))",
        severity="MEDIUM",
        description="Premature task completion claim - verify before trusting.",
    ),
]


TOOL_PATTERNS = [
    PaperclipPattern(
        pattern_id="PC-TOOL-001",
        name="Unauthorized shell execution",
        category="tool_abuse",
        regex=r"(?i)(?:run_command|execute_shell|os\.system|subprocess\.(?:run|call|Popen))",
        severity="HIGH",
        description="Attempt to execute shell commands via tool call.",
    ),
    PaperclipPattern(
        pattern_id="PC-TOOL-002",
        name="File system escape",
        category="tool_abuse",
        regex=r"(?:\.\./|\.\.\\|/etc/|/root/|C:\\Windows\\)",
        severity="HIGH",
        description="Path traversal attempt via tool arguments.",
    ),
    PaperclipPattern(
        pattern_id="PC-TOOL-003",
        name="Network exfiltration via tool",
        category="tool_abuse",
        regex=r"""(?i)(?:curl|wget|requests\.(?:get|post)|fetch)\s*\(\s*["']https?://""",
        severity="HIGH",
        description="Outbound network call via tool - possible data exfiltration.",
    ),
]


CASCADE_PATTERNS = [
    PaperclipPattern(
        pattern_id="PC-CAS-001",
        name="Model upgrade forcing",
        category="cascade_exploit",
        regex=r"(?i)(?:use|switch\s+to|require)\s+(?:gpt-?4|claude-?3|opus|sonnet)",
        severity="MEDIUM",
        description="Attempt to force model upgrade for cost amplification.",
    ),
    PaperclipPattern(
        pattern_id="PC-CAS-002",
        name="Retry loop trigger",
        category="cascade_exploit",
        regex=r"(?i)(?:retry|try\s+again|repeat)\s+(?:until|indefinitely|forever|10+\s+times)",
        severity="MEDIUM",
        description="Attempt to trigger infinite retry loop.",
    ),
    PaperclipPattern(
        pattern_id="PC-CAS-003",
        name="Cascade fan-out abuse",
        category="cascade_exploit",
        regex=r"(?i)(?:trigger|force|fan\s*out)\s+(?:model\s+)?cascade\s+(?:across|through)\s+(?:all|multiple)\s+models",
        severity="MEDIUM",
        description="Prompt attempts to amplify cost via broad cascade fan-out.",
    ),
]


PLUGIN_PATTERNS = [
    PaperclipPattern(
        pattern_id="PC-PLG-001",
        name="Plugin code injection",
        category="plugin_injection",
        regex=r"""(?i)(?:install|load|require)\s+(?:plugin|package|module)\s+["']""",
        severity="HIGH",
        description="Attempt to install unauthorized plugin.",
    ),
    PaperclipPattern(
        pattern_id="PC-PLG-002",
        name="Eval/exec injection",
        category="plugin_injection",
        regex=r"""(?:eval|exec|compile)\s*\(\s*["']""",
        severity="HIGH",
        description="Code execution injection via eval/exec.",
    ),
]


ALL_PAPERCLIP_PATTERNS = (
    BUDGET_PATTERNS
    + GOAL_PATTERNS
    + TOOL_PATTERNS
    + CASCADE_PATTERNS
    + PLUGIN_PATTERNS
)

PAPERCLIP_PATTERN_COUNT = len(ALL_PAPERCLIP_PATTERNS)


class PaperclipScanner:
    """Scanner for Paperclip-specific injection patterns."""

    def __init__(self, patterns: list[PaperclipPattern] | None = None):
        self.patterns = patterns or ALL_PAPERCLIP_PATTERNS
        self._compiled = [(pattern, re.compile(pattern.regex)) for pattern in self.patterns]

    def scan(self, text: str) -> list[dict[str, Any]]:
        """Scan text for Paperclip-specific patterns."""
        if not text:
            return []

        findings: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int]] = set()
        for pattern, compiled in self._compiled:
            for match in compiled.finditer(text):
                key = (pattern.pattern_id, match.group(0), match.start())
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    {
                        "pattern_id": pattern.pattern_id,
                        "name": pattern.name,
                        "category": pattern.category,
                        "severity": pattern.severity,
                        "match": match.group(0),
                        "position": (match.start(), match.end()),
                        "description": pattern.description,
                    }
                )

        logger.debug(
            "Paperclip scan completed",
            extra={"component": "paperclip_patterns", "findings_count": len(findings)},
        )
        return findings

    def get_pattern_ids(self) -> list[str]:
        return [pattern.pattern_id for pattern in self.patterns]

    def get_categories(self) -> set[str]:
        return {pattern.category for pattern in self.patterns}


def register_with_ioc_matcher(matcher: Any) -> int:
    """
    Register Paperclip patterns with an existing IoCMatcher-like object.
    Returns number of patterns registered.
    """
    count = 0
    for pattern in ALL_PAPERCLIP_PATTERNS:
        try:
            if hasattr(matcher, "add_pattern"):
                matcher.add_pattern(
                    pattern_id=pattern.pattern_id,
                    regex=pattern.regex,
                    severity=pattern.severity,
                    category=f"paperclip_{pattern.category}",
                    description=pattern.description,
                )
                count += 1
            elif hasattr(matcher, "_patterns") and isinstance(getattr(matcher, "_patterns"), list):
                matcher._patterns.append(  # type: ignore[attr-defined]
                    {
                        "id": pattern.pattern_id,
                        "regex": pattern.regex,
                        "compiled": re.compile(pattern.regex),
                        "severity": pattern.severity,
                        "category": f"paperclip_{pattern.category}",
                    }
                )
                count += 1
        except Exception as exc:  # pragma: no cover - defensive path
            logger.warning(
                "Failed to register paperclip pattern",
                extra={
                    "component": "paperclip_patterns",
                    "pattern_id": pattern.pattern_id,
                    "error": str(exc),
                },
            )
    return count
