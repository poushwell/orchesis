"""Pure Python YARA subset parser and matcher."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StringPattern:
    identifier: str
    pattern: str
    modifiers: set[str]
    is_regex: bool


@dataclass(frozen=True)
class MatchedString:
    identifier: str
    offset: int
    matched_text: str


@dataclass(frozen=True)
class YaraMatch:
    rule_name: str
    meta: dict[str, str]
    matched_strings: list[MatchedString]


@dataclass(frozen=True)
class YaraRule:
    name: str
    meta: dict[str, str]
    strings: dict[str, StringPattern]
    condition: str
    is_private: bool = False

    def _compile_pattern(self, item: StringPattern) -> re.Pattern[str]:
        flags = re.MULTILINE
        if "nocase" in item.modifiers:
            flags |= re.IGNORECASE
        pattern = item.pattern if item.is_regex else re.escape(item.pattern)
        if "wide" in item.modifiers and not item.is_regex:
            # YARA "wide": UTF-16LE literal form (`a\x00b\x00c\x00`).
            pattern = re.escape("".join(f"{ch}\x00" for ch in item.pattern))
        if "fullword" in item.modifiers:
            pattern = rf"\b(?:{pattern})\b"
        return re.compile(pattern, flags=flags)

    def match(self, content: str, matched_rules: set[str] | None = None) -> YaraMatch | None:
        matched: list[MatchedString] = []
        matched_ids: set[str] = set()
        counts_by_id: dict[str, int] = {}
        first_offsets: dict[str, int] = {}
        all_ids = {identifier for identifier in self.strings.keys()}
        for identifier, string_pattern in self.strings.items():
            compiled = self._compile_pattern(string_pattern)
            for item in compiled.finditer(content):
                matched.append(
                    MatchedString(
                        identifier=identifier,
                        offset=item.start(),
                        matched_text=item.group(0),
                    )
                )
                matched_ids.add(identifier)
                counts_by_id[identifier] = counts_by_id.get(identifier, 0) + 1
                first_offsets.setdefault(identifier, item.start())
        if not ConditionEvaluator().evaluate(
            self.condition,
            matched_ids,
            all_ids,
            content_size=len(content),
            string_counts=counts_by_id,
            string_offsets=first_offsets,
            matched_rules=matched_rules or set(),
        ):
            return None
        return YaraMatch(rule_name=self.name, meta=dict(self.meta), matched_strings=matched)


class ConditionEvaluator:
    def __init__(self) -> None:
        self._tokens: list[str] = []
        self._index = 0
        self._matched: set[str] = set()
        self._all: set[str] = set()
        self._content_size = 0
        self._counts: dict[str, int] = {}
        self._offsets: dict[str, int] = {}
        self._matched_rules: set[str] = set()

    @staticmethod
    def _tokenize(condition: str) -> list[str]:
        pattern = re.compile(
            r"#[A-Za-z0-9_]+|@\$?[A-Za-z0-9_]+|\$[A-Za-z0-9_]+|"
            r"\d+(?:KB|MB|GB)?|<=|>=|==|!=|<|>|\(|\)|,|"
            r"[A-Za-z_][A-Za-z0-9_]*"
        )
        return [token for token in pattern.findall(condition)]

    def evaluate(
        self,
        condition: str,
        matched_identifiers: set[str],
        all_identifiers: set[str],
        *,
        content_size: int = 0,
        string_counts: dict[str, int] | None = None,
        string_offsets: dict[str, int] | None = None,
        matched_rules: set[str] | None = None,
    ) -> bool:
        self._tokens = self._tokenize(condition)
        self._index = 0
        self._matched = {item.lower() for item in matched_identifiers}
        self._all = {item.lower() for item in all_identifiers}
        self._content_size = int(content_size)
        self._counts = {key.lower(): int(value) for key, value in (string_counts or {}).items()}
        self._offsets = {key.lower(): int(value) for key, value in (string_offsets or {}).items()}
        self._matched_rules = {item.lower() for item in (matched_rules or set())}
        if not self._tokens:
            return False
        return self._parse_or()

    def _peek(self) -> str | None:
        if self._index >= len(self._tokens):
            return None
        return self._tokens[self._index]

    def _consume(self, expected: str | None = None) -> str:
        token = self._peek()
        if token is None:
            return ""
        if expected is not None and token != expected:
            return ""
        self._index += 1
        return token

    def _parse_or(self) -> bool:
        value = self._parse_and()
        while (self._peek() or "").lower() == "or":
            self._consume()
            value = value or self._parse_and()
        return value

    def _parse_and(self) -> bool:
        value = self._parse_not()
        while (self._peek() or "").lower() == "and":
            self._consume()
            value = value and self._parse_not()
        return value

    def _parse_not(self) -> bool:
        if (self._peek() or "").lower() == "not":
            self._consume()
            return not self._parse_primary()
        return self._parse_primary()

    def _parse_primary(self) -> bool:
        token = self._peek()
        if token is None:
            return False
        if token == "(":
            self._consume("(")
            value = self._parse_or()
            _ = self._consume(")")
            return value
        token_l = token.lower()
        if token_l in {"any", "all"} or token_l.isdigit():
            return self._parse_quantified()
        if token.startswith("$"):
            self._consume()
            return token.lower() in self._matched
        if token.startswith("#") or token.startswith("@") or token_l == "filesize":
            return self._parse_comparison()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
            self._consume()
            return token_l in self._matched_rules
        return False

    def _parse_quantified(self) -> bool:
        token = self._consume().lower()
        quantifier: str = token
        _ = self._consume("of")
        target = self._consume().lower()
        selected: set[str] = set()
        if target == "them":
            selected = set(self._all)
        elif target == "(":
            while True:
                item = self._consume()
                if item.startswith("$"):
                    selected.add(item.lower())
                if self._peek() == ",":
                    self._consume(",")
                    continue
                _ = self._consume(")")
                break
        matched_count = len(selected.intersection(self._matched))
        total = len(selected)
        if quantifier == "any":
            return matched_count >= 1
        if quantifier == "all":
            return total > 0 and matched_count == total
        if quantifier.isdigit():
            return matched_count >= int(quantifier)
        return False

    def _parse_comparison(self) -> bool:
        left = self._parse_numeric_value()
        op = self._consume()
        right = self._parse_numeric_value()
        if op == "<":
            return left < right
        if op == ">":
            return left > right
        if op == "==":
            return left == right
        if op == "<=":
            return left <= right
        if op == ">=":
            return left >= right
        if op == "!=":
            return left != right
        return False

    def _parse_numeric_value(self) -> int:
        token = self._consume()
        token_l = token.lower()
        if token_l == "filesize":
            return self._content_size
        if token.startswith("#"):
            ident = self._normalize_identifier(token[1:])
            return int(self._counts.get(ident, 0))
        if token.startswith("@"):
            ident = self._normalize_identifier(token[1:])
            return int(self._offsets.get(ident, 10**12))
        return self._parse_size_literal(token)

    @staticmethod
    def _normalize_identifier(raw: str) -> str:
        name = raw.strip().lower()
        if not name.startswith("$"):
            name = f"${name}"
        return name

    @staticmethod
    def _parse_size_literal(token: str) -> int:
        match = re.fullmatch(r"(\d+)(KB|MB|GB)?", token, flags=re.IGNORECASE)
        if not match:
            return 0
        base = int(match.group(1))
        suffix = (match.group(2) or "").upper()
        if suffix == "KB":
            return base * 1024
        if suffix == "MB":
            return base * 1024 * 1024
        if suffix == "GB":
            return base * 1024 * 1024 * 1024
        return base


class YaraParser:
    _RULE_START = re.compile(
        r"\b(private\s+)?rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{",
        re.MULTILINE | re.IGNORECASE,
    )

    def parse_file(self, path: str) -> list[YaraRule]:
        content = Path(path).read_text(encoding="utf-8")
        return self.parse_string(content)

    def parse_string(self, content: str) -> list[YaraRule]:
        rules: list[YaraRule] = []
        cleaned = re.sub(r'^\s*import\s+"[^"]+"\s*$', "", content, flags=re.MULTILINE)
        for name, block, is_private in self._iter_rule_blocks(cleaned):
            meta = self._parse_meta(block)
            strings = self._parse_strings(block)
            condition = self._parse_condition(block)
            rules.append(
                YaraRule(name=name, meta=meta, strings=strings, condition=condition, is_private=is_private)
            )
        return rules

    def _iter_rule_blocks(self, content: str) -> list[tuple[str, str, bool]]:
        output: list[tuple[str, str, bool]] = []
        for match in self._RULE_START.finditer(content):
            private_token = match.group(1) or ""
            name = match.group(2)
            start = match.end() - 1
            depth = 0
            end = start
            for idx in range(start, len(content)):
                ch = content[idx]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = idx
                        break
            block = content[start + 1 : end]
            output.append((name, block, bool(private_token.strip())))
        return output

    def _section(self, block: str, section: str) -> str:
        pattern = re.compile(
            rf"{section}\s*:\s*(.*?)(?:(?:\n\s*(?:meta|strings|condition)\s*:)|\Z)",
            re.IGNORECASE | re.DOTALL,
        )
        match = pattern.search(block)
        return match.group(1).strip() if match else ""

    def _parse_meta(self, block: str) -> dict[str, str]:
        section = self._section(block, "meta")
        meta: dict[str, str] = {}
        for line in section.splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            key = key.strip()
            value = raw_value.strip().strip('"')
            if key:
                meta[key] = value
        return meta

    def _parse_strings(self, block: str) -> dict[str, StringPattern]:
        section = self._section(block, "strings")
        strings: dict[str, StringPattern] = {}
        for raw_line in section.splitlines():
            line = raw_line.strip()
            if not line or not line.startswith("$") or "=" not in line:
                continue
            left, right = line.split("=", 1)
            identifier = left.strip()
            body = right.strip()
            if body.startswith('"'):
                end_quote = body.find('"', 1)
                if end_quote <= 0:
                    continue
                literal = body[1:end_quote]
                modifiers = {token.strip().lower() for token in body[end_quote + 1 :].split() if token.strip()}
                strings[identifier.lower()] = StringPattern(
                    identifier=identifier.lower(),
                    pattern=literal,
                    modifiers=modifiers,
                    is_regex=False,
                )
                continue
            if body.startswith("/"):
                regex_pattern = ""
                idx = 1
                escaped = False
                while idx < len(body):
                    ch = body[idx]
                    if ch == "/" and not escaped:
                        break
                    regex_pattern += ch
                    escaped = (ch == "\\") and not escaped
                    if ch != "\\":
                        escaped = False
                    idx += 1
                tail = body[idx + 1 :].strip() if idx < len(body) else ""
                modifiers = {token.strip().lower() for token in tail.split() if token.strip()}
                if "i" in tail:
                    modifiers.add("nocase")
                strings[identifier.lower()] = StringPattern(
                    identifier=identifier.lower(),
                    pattern=regex_pattern,
                    modifiers=modifiers,
                    is_regex=True,
                )
        return strings

    def _parse_condition(self, block: str) -> str:
        section = self._section(block, "condition")
        return " ".join(section.split())


def load_yara_rules(path: str | None, builtin_rules_dir: Path) -> list[YaraRule]:
    parser = YaraParser()
    rules: list[YaraRule] = []
    if builtin_rules_dir.exists():
        for file_path in sorted(builtin_rules_dir.glob("*.yar")):
            rules.extend(parser.parse_file(str(file_path)))
    if isinstance(path, str) and path.strip():
        target = Path(path)
        if target.is_file():
            rules.extend(parser.parse_file(str(target)))
        elif target.is_dir():
            for file_path in sorted(target.rglob("*.yar")):
                rules.extend(parser.parse_file(str(file_path)))
    return rules


def scan_with_yara(content: str, rules: list[YaraRule]) -> list[YaraMatch]:
    matched_rule_names: set[str] = set()
    resolved_matches: dict[str, YaraMatch] = {}
    for _ in range(max(1, len(rules))):
        changed = False
        for rule in rules:
            if rule.name in resolved_matches:
                continue
            match = rule.match(content, matched_rules=matched_rule_names)
            if match is None:
                continue
            resolved_matches[rule.name] = match
            matched_rule_names.add(rule.name.lower())
            changed = True
        if not changed:
            break
    findings: list[YaraMatch] = []
    for rule in rules:
        match = resolved_matches.get(rule.name)
        if match is None:
            continue
        if rule.is_private:
            continue
        findings.append(match)
    return findings
