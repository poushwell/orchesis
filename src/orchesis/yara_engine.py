"""Pure Python YARA subset parser and matcher."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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

    def _compile_pattern(self, item: StringPattern) -> re.Pattern[str]:
        flags = re.MULTILINE
        if "nocase" in item.modifiers:
            flags |= re.IGNORECASE
        pattern = item.pattern if item.is_regex else re.escape(item.pattern)
        if "fullword" in item.modifiers:
            pattern = rf"\b(?:{pattern})\b"
        return re.compile(pattern, flags=flags)

    def match(self, content: str) -> YaraMatch | None:
        matched: list[MatchedString] = []
        matched_ids: set[str] = set()
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
        if not ConditionEvaluator().evaluate(self.condition, matched_ids, all_ids):
            return None
        return YaraMatch(rule_name=self.name, meta=dict(self.meta), matched_strings=matched)


class ConditionEvaluator:
    def __init__(self) -> None:
        self._tokens: list[str] = []
        self._index = 0
        self._matched: set[str] = set()
        self._all: set[str] = set()

    @staticmethod
    def _tokenize(condition: str) -> list[str]:
        pattern = re.compile(r"\$[A-Za-z0-9_]+|\d+|any|all|of|them|and|or|not|\(|\)|,")
        return [token for token in pattern.findall(condition.lower())]

    def evaluate(self, condition: str, matched_identifiers: set[str], all_identifiers: set[str]) -> bool:
        self._tokens = self._tokenize(condition)
        self._index = 0
        self._matched = {item.lower() for item in matched_identifiers}
        self._all = {item.lower() for item in all_identifiers}
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
        while self._peek() == "or":
            self._consume("or")
            value = value or self._parse_and()
        return value

    def _parse_and(self) -> bool:
        value = self._parse_not()
        while self._peek() == "and":
            self._consume("and")
            value = value and self._parse_not()
        return value

    def _parse_not(self) -> bool:
        if self._peek() == "not":
            self._consume("not")
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
        if token in {"any", "all"} or token.isdigit():
            return self._parse_quantified()
        if token.startswith("$"):
            self._consume()
            return token in self._matched
        return False

    def _parse_quantified(self) -> bool:
        token = self._consume()
        quantifier: str = token
        _ = self._consume("of")
        target = self._consume()
        selected: set[str] = set()
        if target == "them":
            selected = set(self._all)
        elif target == "(":
            while True:
                item = self._consume()
                if item.startswith("$"):
                    selected.add(item)
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


class YaraParser:
    _RULE_START = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", re.MULTILINE)

    def parse_file(self, path: str) -> list[YaraRule]:
        content = Path(path).read_text(encoding="utf-8")
        return self.parse_string(content)

    def parse_string(self, content: str) -> list[YaraRule]:
        rules: list[YaraRule] = []
        for name, block in self._iter_rule_blocks(content):
            meta = self._parse_meta(block)
            strings = self._parse_strings(block)
            condition = self._parse_condition(block)
            rules.append(YaraRule(name=name, meta=meta, strings=strings, condition=condition))
        return rules

    def _iter_rule_blocks(self, content: str) -> list[tuple[str, str]]:
        output: list[tuple[str, str]] = []
        for match in self._RULE_START.finditer(content):
            name = match.group(1)
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
            output.append((name, block))
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
    findings: list[YaraMatch] = []
    for rule in rules:
        match = rule.match(content)
        if match is not None:
            findings.append(match)
    return findings
