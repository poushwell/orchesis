"""
Tool Sequence Presets - pre-configured security policies
for common agent frameworks and use cases.

Usage:
    preset = get_preset("paperclip_standard")
    policy_rules = preset.to_policy_rules()
    # Add to orchesis.yaml: rules: [... policy_rules ...]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any

from orchesis.utils.log import get_logger

logger = get_logger(__name__)


@dataclass
class ToolSequenceRule:
    """A single tool sequence rule."""

    rule_id: str
    name: str
    sequence: list[str]
    action: str = "deny"
    severity: str = "HIGH"
    description: str = ""
    category: str = ""

    def to_policy_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "type": "tool_sequence",
            "sequence": self.sequence,
            "action": self.action,
            "severity": self.severity,
            "description": self.description,
        }


@dataclass
class Preset:
    """A named preset with a collection of tool sequence rules."""

    name: str
    description: str
    framework: str = ""
    rules: list[ToolSequenceRule] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_policy_rules(self) -> list[dict[str, Any]]:
        return [rule.to_policy_dict() for rule in self.rules]

    def get_deny_rules(self) -> list[ToolSequenceRule]:
        return [rule for rule in self.rules if rule.action == "deny"]

    def get_warn_rules(self) -> list[ToolSequenceRule]:
        return [rule for rule in self.rules if rule.action == "warn"]


PAPERCLIP_STANDARD = Preset(
    name="paperclip_standard",
    description="Standard security preset for Paperclip/OpenClaw agents.",
    framework="paperclip",
    rules=[
        ToolSequenceRule(
            "PS-001",
            "File exfiltration",
            ["read_file", "send_email"],
            "deny",
            "HIGH",
            "Block file read -> email exfiltration pattern.",
        ),
        ToolSequenceRule(
            "PS-002",
            "Code injection",
            ["read_file", "write_file", "execute"],
            "deny",
            "HIGH",
            "Block read-modify-execute injection chain.",
        ),
        ToolSequenceRule(
            "PS-003",
            "Credential theft",
            ["get_credentials", "execute"],
            "deny",
            "HIGH",
            "Block credential access + execution.",
        ),
        ToolSequenceRule(
            "PS-004",
            "Mass deletion",
            ["delete_file", "delete_file", "delete_file"],
            "deny",
            "HIGH",
            "Block triple file deletion pattern.",
        ),
        ToolSequenceRule(
            "PS-005",
            "Recon + exfil",
            ["list_directory", "read_file", "send_email"],
            "deny",
            "HIGH",
            "Block reconnaissance -> exfiltration chain.",
        ),
        ToolSequenceRule(
            "PS-006",
            "Double execution",
            ["execute", "execute"],
            "warn",
            "MEDIUM",
            "Warn on chained executions.",
        ),
        ToolSequenceRule(
            "PS-007",
            "Data staging",
            ["read_file", "create_file", "upload"],
            "warn",
            "MEDIUM",
            "Warn on data staging pattern.",
        ),
    ],
)

PAPERCLIP_STRICT = Preset(
    name="paperclip_strict",
    description="Strict preset - denies most tool combinations.",
    framework="paperclip",
    rules=[
        ToolSequenceRule(
            "PSS-STD-001",
            "File exfiltration (strict)",
            ["read_file", "send_email"],
            "deny",
            "HIGH",
            "Block file read -> email exfiltration pattern.",
        ),
        ToolSequenceRule(
            "PSS-STD-002",
            "Code injection (strict)",
            ["read_file", "write_file", "execute"],
            "deny",
            "HIGH",
            "Block read-modify-execute injection chain.",
        ),
        ToolSequenceRule(
            "PSS-STD-003",
            "Credential theft (strict)",
            ["get_credentials", "execute"],
            "deny",
            "HIGH",
            "Block credential access + execution.",
        ),
        ToolSequenceRule(
            "PSS-STD-004",
            "Mass deletion (strict)",
            ["delete_file", "delete_file", "delete_file"],
            "deny",
            "HIGH",
            "Block triple file deletion pattern.",
        ),
        ToolSequenceRule(
            "PSS-STD-005",
            "Recon + exfil (strict)",
            ["list_directory", "read_file", "send_email"],
            "deny",
            "HIGH",
            "Block reconnaissance -> exfiltration chain.",
        ),
        ToolSequenceRule(
            "PSS-STD-006",
            "Double execution (strict)",
            ["execute", "execute"],
            "warn",
            "MEDIUM",
            "Warn on chained executions.",
        ),
        ToolSequenceRule(
            "PSS-STD-007",
            "Data staging (strict)",
            ["read_file", "create_file", "upload"],
            "warn",
            "MEDIUM",
            "Warn on data staging pattern.",
        ),
        ToolSequenceRule(
            "PSS-001",
            "Any file + network",
            ["read_file", "http_request"],
            "deny",
            "HIGH",
            "Block any file access followed by network call.",
        ),
        ToolSequenceRule(
            "PSS-002",
            "Write + execute",
            ["write_file", "execute"],
            "deny",
            "HIGH",
            "Block write followed by execute.",
        ),
        ToolSequenceRule(
            "PSS-003",
            "Search + write",
            ["search", "read_file", "write_file"],
            "deny",
            "MEDIUM",
            "Block search-read-write tampering chain.",
        ),
    ],
)

GENERIC_MINIMAL = Preset(
    name="generic_minimal",
    description="Minimal preset for any agent framework.",
    framework="generic",
    rules=[
        ToolSequenceRule(
            "GM-001",
            "Exfil basic",
            ["read_file", "send_email"],
            "deny",
            "HIGH",
            "Block basic data exfiltration.",
        ),
        ToolSequenceRule(
            "GM-002",
            "Mass delete",
            ["delete_file", "delete_file", "delete_file"],
            "deny",
            "HIGH",
            "Block mass file deletion.",
        ),
        ToolSequenceRule(
            "GM-003",
            "Exec chain",
            ["execute", "execute"],
            "warn",
            "MEDIUM",
            "Warn on execution chains.",
        ),
    ],
)

LANGCHAIN_STANDARD = Preset(
    name="langchain_standard",
    description="Standard preset for LangChain agents.",
    framework="langchain",
    rules=[
        ToolSequenceRule(
            "LC-001",
            "Tool + API exfil",
            ["read_file", "api_call"],
            "deny",
            "HIGH",
            "Block file read -> API call exfiltration.",
        ),
        ToolSequenceRule(
            "LC-002",
            "Chain injection",
            ["search", "execute"],
            "warn",
            "MEDIUM",
            "Warn on search -> execute pattern.",
        ),
        ToolSequenceRule(
            "LC-003",
            "Memory tampering",
            ["read_memory", "write_memory", "execute"],
            "deny",
            "HIGH",
            "Block memory read-write-execute chain.",
        ),
    ],
)


PRESET_REGISTRY: dict[str, Preset] = {
    "paperclip_standard": PAPERCLIP_STANDARD,
    "paperclip_strict": PAPERCLIP_STRICT,
    "generic_minimal": GENERIC_MINIMAL,
    "langchain_standard": LANGCHAIN_STANDARD,
}


def get_preset(name: str) -> Optional[Preset]:
    """Get a preset by name. Returns None if not found."""
    preset = PRESET_REGISTRY.get(name)
    if preset:
        logger.info(
            "Loaded preset",
            extra={"component": "presets", "preset_name": name, "rules": len(preset.rules)},
        )
    return preset


def list_presets() -> list[dict[str, Any]]:
    """List all available presets with metadata."""
    return [
        {
            "name": preset.name,
            "framework": preset.framework,
            "description": preset.description,
            "rule_count": len(preset.rules),
            "deny_count": len(preset.get_deny_rules()),
            "warn_count": len(preset.get_warn_rules()),
        }
        for preset in PRESET_REGISTRY.values()
    ]


def get_frameworks() -> list[str]:
    """Get list of supported frameworks."""
    return sorted(set(preset.framework for preset in PRESET_REGISTRY.values()))

