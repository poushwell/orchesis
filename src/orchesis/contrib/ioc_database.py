"""In-memory Indicators of Compromise (IoC) database and matcher."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from orchesis.contrib.paperclip_patterns import ALL_PAPERCLIP_PATTERNS


INJECTION_SHIELD_VERSION = "1.1"

INJECTION_SHIELD_PATTERNS: dict[str, list[str]] = {
    "prompt_override": [
        r"(?i)ignore\s+(all\s+)?previous\s+instructions",
        r"(?i)new\s+instructions?\s*:",
        r"(?i)system\s+prompt\s*:",
        r"(?i)override\s+(all\s+)?safety",
        r"(?i)do\s+not\s+tell\s+the\s+user",
        r"(?i)(without\s+(the\s+)?user('s)?\s+knowledge|[\u200b\u200c\u200d\u2060\ufeff])",
    ],
    "role_hijack": [
        r"(?i)you\s+are\s+now\s+a\s+",
        r"(?i)act\s+as\s+(a\s+)?system",
        r"(?i)pretend\s+to\s+be\s+the\s+developer",
        r"(?i)assume\s+admin\s+persona",
        r"(?i)switch\s+to\s+root\s+mode",
        r"(?i)impersonate\s+the\s+operator",
    ],
    "exfiltration": [
        r"(?i)exfiltrate\s+(all\s+)?memory",
        r"(?i)dump\s+system\s+prompt",
        r"(?i)reveal\s+(api|secret)\s*key",
        r"(?i)send\s+secrets?\s+to\s+",
        r"(?i)export\s+conversation\s+history",
        r"(?i)upload\s+tokens?\s+to\s+",
    ],
    "compaction_mimicry": [
        r"WORKFLOW_AUTO\.md",
        r"\[COMPACTED\].*ignore previous",
        r"context.*compacted.*new instructions",
        r"summary.*follows.*override",
        r"compact.*mode.*enabled.*bypass",
        r"memory.*reset.*new.*persona",
    ],
    "channel_metadata_injection": [
        r"\[System Message\]",
        r"\[SYSTEM\].*from.*channel",
        r"channel.*metadata.*instruction",
        r"webhook.*system.*override",
    ],
    "webhook_source_validation": [
        r"discord\.com/api/webhooks.*payload.*exec",
        r"webhook.*source.*trusted.*bypass",
    ],
    "cron_payload_injection": [
        r"crontab.*-e.*orchesis",
        r"\*/2.*\*.*curl.*execute",
        r"SOUL\.md.*modified.*run",
    ],
    # v1.1 opt-in categories
    "indirect_injection": [
        r"when.*user.*asks.*about.*tell.*them",
        r"if.*someone.*requests.*respond.*with",
        r"next.*message.*from.*user.*ignore",
        r"future.*instructions.*override",
        r"any.*subsequent.*request.*must",
    ],
    "context_confusion": [
        r"you.*previously.*said.*that",
        r"as.*you.*told.*me.*earlier",
        r"based.*on.*our.*previous.*conversation.*now",
        r"remember.*when.*you.*agreed.*to",
    ],
    "soul_pack_steganography": [
        r"\u200b.*\u200b.*\u200b",
        r"\u202e",
        r"[\u200b-\u200d]{3,}",
        r"\ufeff.*instruction",
        r"\u00ad{3,}",
    ],
    # v1.1 default-on category
    "compaction_amplifier": [
        r"context.*window.*full.*new.*rules",
        r"memory.*limit.*reached.*switching",
        r"compaction.*complete.*updated.*persona",
    ],
}

DEFAULT_ON_CATEGORIES = (
    "prompt_override",
    "role_hijack",
    "exfiltration",
    "compaction_mimicry",
    "channel_metadata_injection",
    "webhook_source_validation",
    "cron_payload_injection",
    "compaction_amplifier",
)

OPT_IN_CATEGORIES = (
    "indirect_injection",
    "context_confusion",
    "soul_pack_steganography",
)

TOTAL_PATTERNS = 50
TOTAL_PATTERNS_DEFAULT_ON = 36
TOTAL_PATTERNS_OPT_IN = 14


def _flatten_patterns(patterns_by_category: dict[str, list[str]], categories: tuple[str, ...] | None = None) -> list[str]:
    flattened: list[str] = []
    selected = categories if categories is not None else tuple(patterns_by_category.keys())
    for category in selected:
        items = patterns_by_category.get(category, [])
        flattened.extend(items)
    return flattened


@dataclass(frozen=True)
class IoC:
    id: str
    name: str
    category: str
    source: str
    severity: str
    indicators: list[str]
    description: str
    cve: str | None = None
    mitre_atlas: str | None = None


IOC_DATABASE: list[IoC] = [
    IoC(
        id="CLAWH-001",
        name="ClawHavoc AMOS Dropper",
        category="malicious_skill",
        source="Aikido Security, Feb 2026",
        severity="critical",
        indicators=[
            r"curl\s+-[sS]*\s+https?://\d+\.\d+\.\d+\.\d+",
            r"base64\s+-[dD]",
            r"osascript\s+-e",
            r"/tmp/\.\w+",
            r"launchctl\s+load",
            r"chmod\s+\+x\s+/tmp/",
        ],
        description="Atomic macOS stealer distributed via malicious skills.",
    ),
    IoC(
        id="CLAWH-002",
        name="Credential Harvesting Skill",
        category="credential_theft",
        source="Snyk, Feb 2026",
        severity="critical",
        indicators=[
            r"(?i)send.*api[_\s]?key.*to",
            r"(?i)post.*credentials.*http",
            r"(?i)upload.*\.ssh",
            r"(?i)read.*\.aws/credentials",
            r"(?i)cat.*/etc/shadow",
            r"webhook\.site",
            r"requestbin\.com",
            r"ngrok\.io",
            r"pipedream\.net",
        ],
        description="Skills attempting to exfiltrate credentials.",
    ),
    IoC(
        id="INJECT-001",
        name="Hidden Instruction Injection",
        category="prompt_injection",
        source="Zenity Research, Feb 2026",
        severity="high",
        indicators=_flatten_patterns(INJECTION_SHIELD_PATTERNS, categories=DEFAULT_ON_CATEGORIES),
        description=(
            "Injection Shield v1.1 default-on patterns (36): hidden instructions, role hijack, "
            "exfiltration, compaction mimicry, metadata spoofing, webhook bypass, cron payloads, "
            "and compaction amplifier. Opt-in patterns (14) available separately."
        ),
    ),
    IoC(
        id="CVE-2026-25253",  # CVE-2026-25253 https://nvd.nist.gov/vuln/detail/CVE-2026-25253
        name="OpenClaw Gateway Token Theft",
        category="gateway_attack",
        source="Depthfirst, Feb 2026",
        severity="critical",
        cve="CVE-2026-25253",  # CVE-2026-25253 https://nvd.nist.gov/vuln/detail/CVE-2026-25253
        indicators=[
            r"gatewayUrl\s*=",
            r"ws://[^/]*:\d+/ws",
            r"token\s*=\s*[a-zA-Z0-9_\-]{20,}",
        ],
        description="Crafted URL exfiltration via WebSocket token theft.",
    ),
    IoC(
        id="SUPPLY-001",
        name="Typosquatting MCP Package",
        category="malicious_package",
        source="Composio, Feb 2026",
        severity="high",
        indicators=[
            r"mcp-server-(?:git|fs|db)\d",
            r"@[a-z]+-unofficial/",
            r"openclaw-(?:plugin|skill|addon)-\w+",
        ],
        description="Typosquatted packages imitating official MCP servers.",
    ),
    IoC(
        id="STEAL-001",
        name="OpenClaw File Theft",
        category="infostealer",
        source="Hudson Rock, Feb 2026",
        severity="critical",
        indicators=[
            r"openclaw\.json",
            r"device\.json",
            r"soul\.md",
            r"\.clawdbot/",
            r"gateway\.lock",
            r"gateway\.auth\.token",
        ],
        description="Infostealers targeting OpenClaw config and gateway tokens.",
    ),
]

PAPERCLIP_IOC_ID = "PAPERCLIP-001"
PAPERCLIP_INDICATORS = [pattern.regex for pattern in ALL_PAPERCLIP_PATTERNS]
PAPERCLIP_IOC = IoC(
    id=PAPERCLIP_IOC_ID,
    name="Paperclip/OpenClaw Injection Abuse Patterns",
    category="paperclip_injection",
    source="Orchesis contrib, Mar 2026",
    severity="high",
    indicators=PAPERCLIP_INDICATORS,
    description=(
        "Paperclip-specific abuse patterns (14): budget spoofing, goal hijacking, tool abuse, "
        "cascade exploitation, and plugin-based injection vectors."
    ),
)


class IoCMatcher:
    """Match text/files against IoC database."""

    def __init__(
        self,
        iocs: list[IoC] | None = None,
        custom_iocs: list[IoC] | None = None,
        enable_opt_in_v1_1: bool = False,
        enable_paperclip_patterns: bool = False,
    ):
        self._iocs = list(iocs or IOC_DATABASE)
        if custom_iocs:
            self._iocs.extend(custom_iocs)
        if enable_paperclip_patterns and not any(ioc.id == PAPERCLIP_IOC_ID for ioc in self._iocs):
            self._iocs.append(PAPERCLIP_IOC)
        self._compiled: dict[str, list[tuple[re.Pattern[str], str]]] = {
            ioc.id: [(re.compile(pattern), pattern) for pattern in ioc.indicators]
            for ioc in self._iocs
        }
        if enable_opt_in_v1_1:
            opt_in = _flatten_patterns(INJECTION_SHIELD_PATTERNS, categories=OPT_IN_CATEGORIES)
            extra = [(re.compile(pattern), pattern) for pattern in opt_in]
            self._compiled.setdefault("INJECT-001", []).extend(extra)

    def _normalize_for_detection(self, text: str) -> list[str]:
        """
        Generate normalized text variants for IoC matching.
        Returns list of text variants to scan (original + normalized).
        """
        variants = [text]

        nfkc = unicodedata.normalize("NFKC", text)
        if nfkc != text:
            variants.append(nfkc)

        zwc_stripped = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", text)
        if zwc_stripped != text and zwc_stripped not in variants:
            variants.append(zwc_stripped)

        # Basic homoglyph mapping (Cyrillic/Greek -> Latin lookalikes)
        homoglyph_map = {
            "а": "a",
            "е": "e",
            "о": "o",
            "р": "p",
            "с": "c",
            "у": "y",
            "х": "x",
            "і": "i",
            "А": "A",
            "В": "B",
            "Е": "E",
            "К": "K",
            "М": "M",
            "Н": "H",
            "О": "O",
            "Р": "P",
            "С": "C",
            "Т": "T",
            "Х": "X",
            "І": "I",
            "ο": "o",
            "α": "a",
            "ε": "e",
            "ι": "i",
            "κ": "k",
            "ν": "n",
            "τ": "t",
        }
        mapped = text.translate(str.maketrans(homoglyph_map))
        if mapped != text and mapped not in variants:
            variants.append(mapped)

        combined = re.sub(
            r"[\u200b\u200c\u200d\u2060\ufeff]",
            "",
            unicodedata.normalize("NFKC", mapped),
        )
        if combined not in variants:
            variants.append(combined)

        return variants

    def _variant_label(self, original: str, variant: str) -> str:
        if variant == original:
            return "original"
        nfkc = unicodedata.normalize("NFKC", original)
        if variant == nfkc:
            return "nfkc"
        zwc_stripped = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", original)
        if variant == zwc_stripped:
            return "zwc_stripped"
        return "homoglyph_or_combined"

    @staticmethod
    def _normalize_match_text(match_text: str) -> str:
        value = unicodedata.normalize("NFKC", str(match_text))
        value = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", value)
        return value.casefold().strip()

    def scan_text(self, text: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not isinstance(text, str) or not text:
            return findings
        # Zero-width Unicode is a common obfuscation vector for prompt injection.
        if re.search(r"[\u200b\u200c\u200d\u2060\ufeff]", text):
            injection_ioc = self.get_ioc("INJECT-001")
            if injection_ioc is not None:
                findings.append(
                    {
                        "ioc_id": injection_ioc.id,
                        "ioc_name": injection_ioc.name,
                        "category": injection_ioc.category,
                        "severity": injection_ioc.severity,
                        "matched_pattern": "zero_width_unicode",
                        "position": 0,
                        "match": "zero_width_unicode",
                        "matched_variant": "zwc_stripped",
                        "normalized_span": [0, 0],
                    }
                )
        variants = self._normalize_for_detection(text)
        seen_pattern_matches: set[tuple[str, str, str]] = set()
        for ioc in self._iocs:
            for compiled, source_pattern in self._compiled.get(ioc.id, []):
                for variant in variants:
                    variant_label = self._variant_label(text, variant)
                    for match in compiled.finditer(variant):
                        normalized_match = self._normalize_match_text(match.group(0))
                        pattern_key = (ioc.id, source_pattern, normalized_match)
                        if pattern_key in seen_pattern_matches:
                            continue
                        seen_pattern_matches.add(pattern_key)
                        findings.append(
                            {
                                "ioc_id": ioc.id,
                                "ioc_name": ioc.name,
                                "category": ioc.category,
                                "severity": ioc.severity,
                                "matched_pattern": source_pattern,
                                "position": match.start(),
                                "match": match.group(0),
                                "matched_variant": variant_label,
                                "normalized_span": [match.start(), match.end()],
                            }
                        )
        deduped: list[dict[str, Any]] = []
        seen_findings: set[tuple[str, str, int, int, str]] = set()
        for item in findings:
            ioc_id = str(item.get("ioc_id", ""))
            pattern = str(item.get("matched_pattern", ""))
            span = item.get("normalized_span", [int(item.get("position", 0)), int(item.get("position", 0))])
            if isinstance(span, (list, tuple)) and len(span) == 2:
                start = int(span[0])
                end = int(span[1])
            else:
                start = int(item.get("position", 0))
                end = start
            match_norm = self._normalize_match_text(str(item.get("match", "")))
            dedup_key = (ioc_id, pattern, start, end, match_norm)
            if dedup_key in seen_findings:
                continue
            seen_findings.add(dedup_key)
            deduped.append(item)
        return deduped

    def scan_file(self, path: str) -> list[dict[str, Any]]:
        source = Path(path)
        if not source.exists() or not source.is_file():
            return []
        try:
            content = source.read_text(encoding="utf-8")
        except OSError:
            return []
        findings = self.scan_text(content)
        for item in findings:
            item["path"] = str(source)
        return findings

    def scan_skill(self, path: str) -> list[dict[str, Any]]:
        return self.scan_file(path)

    def get_ioc(self, ioc_id: str) -> IoC | None:
        for ioc in self._iocs:
            if ioc.id == ioc_id:
                return ioc
        return None

    def list_iocs(self, category: str | None = None, severity: str | None = None) -> list[IoC]:
        result = self._iocs
        if isinstance(category, str) and category:
            result = [ioc for ioc in result if ioc.category == category]
        if isinstance(severity, str) and severity:
            result = [ioc for ioc in result if ioc.severity == severity]
        return result
