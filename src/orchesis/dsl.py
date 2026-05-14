"""Configuration DSL for threshold resolution.

A small typed expression language for declarative threshold rules in YAML
configuration. The parser validates against a strict whitelist of fields and
functions, enforces AST depth limits, and rejects unknown identifiers at load
time. Hot-reload is atomic: the full new configuration is parsed and
validated before any existing rules are replaced.

Public API:
    ThresholdResolver  — load rules from YAML/dict, resolve(name, ctx)
    parse_expression   — parse a single expression string to an AST
    validate_ast       — whitelist + depth check on a parsed AST
    Expr               — AST node base (Literal/Identifier/UnaryOp/BinaryOp/FunctionCall)
    ResolverContext    — typed input passed to .resolve()
    DslError           — raised on any parse, validation, or evaluation failure
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence


# ---------------------------------------------------------------------------
# Whitelists. Changing these expands the surface evaluator can touch.
# ---------------------------------------------------------------------------

WHITELIST_FIELDS: frozenset[str] = frozenset({
    "tier",
    "chain_length",
    "task_type",
    "request_size",
    "agent_class",
    "reliability_profile",
})

WHITELIST_FUNCTIONS: frozenset[str] = frozenset({
    "min",
    "max",
    "clip",
    "lookup",
})

RESERVED_KEYWORDS: frozenset[str] = frozenset({
    "if", "value", "default", "and", "or", "not", "true", "false", "ctx",
})

# Hard limit on AST depth. Defends against pathological nesting in user config.
MAX_AST_DEPTH = 20

# Hard limit on numeric magnitude. Defends against overflow surprises.
MAX_NUMERIC_MAGNITUDE = 1e15


class DslError(Exception):
    """Raised for any DSL parse, validation, or evaluation failure."""


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Literal:
    value: int | float | str | bool


@dataclass(frozen=True, slots=True)
class Identifier:
    field: str  # validated against WHITELIST_FIELDS


@dataclass(frozen=True, slots=True)
class UnaryOp:
    op: str  # 'not' | '-'
    operand: "Expr"


@dataclass(frozen=True, slots=True)
class BinaryOp:
    op: str  # '==' '!=' '<' '<=' '>' '>=' '+' '-' '*' '/' 'and' 'or'
    left: "Expr"
    right: "Expr"


@dataclass(frozen=True, slots=True)
class FunctionCall:
    func: str  # validated against WHITELIST_FUNCTIONS
    args: tuple["Expr", ...]


Expr = Literal | Identifier | UnaryOp | BinaryOp | FunctionCall


@dataclass(frozen=True, slots=True)
class Rule:
    """One rule in an ordered list. `condition is None` marks the default."""
    condition: Expr | None
    value: Expr


@dataclass(frozen=True, slots=True)
class ResolverContext:
    """Typed input for .resolve(). Only whitelisted fields are accessible."""
    tier: str | None = None
    chain_length: int = 0
    task_type: str | None = None
    request_size: int = 0
    agent_class: str | None = None
    reliability_profile: str | None = None

    def get(self, name: str) -> Any:
        if name not in WHITELIST_FIELDS:
            raise DslError(f"identifier 'ctx.{name}' not in whitelist")
        return getattr(self, name)


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Token:
    kind: str       # NUMBER, STRING, NAME, OP, LPAREN, RPAREN, COMMA, EOF
    text: str
    pos: int        # column in source, for error reporting


_TWO_CHAR_OPS = {"==", "!=", "<=", ">="}
_SINGLE_CHAR_OPS = {"<", ">", "+", "-", "*", "/"}


def _tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(source)
    while i < n:
        c = source[i]
        if c.isspace():
            i += 1
            continue
        # Punctuation
        if c == "(":
            tokens.append(Token("LPAREN", c, i))
            i += 1
            continue
        if c == ")":
            tokens.append(Token("RPAREN", c, i))
            i += 1
            continue
        if c == ",":
            tokens.append(Token("COMMA", c, i))
            i += 1
            continue
        # Two-char operators
        if i + 1 < n and source[i:i+2] in _TWO_CHAR_OPS:
            tokens.append(Token("OP", source[i:i+2], i))
            i += 2
            continue
        # Single-char operators
        if c in _SINGLE_CHAR_OPS:
            tokens.append(Token("OP", c, i))
            i += 1
            continue
        # String literal: double-quoted, supports \\ \" \n \t escapes
        if c == '"':
            start = i
            i += 1
            buf: list[str] = []
            while i < n and source[i] != '"':
                if source[i] == "\\" and i + 1 < n:
                    esc = source[i+1]
                    if esc == "n":
                        buf.append("\n")
                    elif esc == "t":
                        buf.append("\t")
                    elif esc == "\\":
                        buf.append("\\")
                    elif esc == '"':
                        buf.append('"')
                    else:
                        raise DslError(
                            f"unknown string escape '\\{esc}' at column {i}"
                        )
                    i += 2
                else:
                    buf.append(source[i])
                    i += 1
            if i >= n:
                raise DslError(f"unterminated string literal starting at column {start}")
            i += 1  # skip closing quote
            tokens.append(Token("STRING", "".join(buf), start))
            continue
        # Number literal
        if c.isdigit() or (c == "." and i + 1 < n and source[i+1].isdigit()):
            start = i
            saw_dot = False
            saw_exp = False
            while i < n:
                ch = source[i]
                if ch.isdigit():
                    i += 1
                elif ch == "." and not saw_dot and not saw_exp:
                    saw_dot = True
                    i += 1
                elif ch in ("e", "E") and not saw_exp:
                    saw_exp = True
                    i += 1
                    if i < n and source[i] in ("+", "-"):
                        i += 1
                else:
                    break
            tokens.append(Token("NUMBER", source[start:i], start))
            continue
        # Name / keyword: alpha + alphanumeric/underscore/dot
        if c.isalpha() or c == "_":
            start = i
            while i < n and (source[i].isalnum() or source[i] in ("_", ".")):
                i += 1
            tokens.append(Token("NAME", source[start:i], start))
            continue
        raise DslError(f"unexpected character {c!r} at column {i}")
    tokens.append(Token("EOF", "", n))
    return tokens


# ---------------------------------------------------------------------------
# Parser (recursive descent, Pratt-like precedence)
# ---------------------------------------------------------------------------


class _Parser:
    """Recursive descent with explicit precedence climbing.

    Precedence (lowest to highest):
        or
        and
        not (right-assoc unary)
        comparison (==, !=, <, <=, >, >=)  — non-chaining
        +, -          (left-assoc)
        *, /          (left-assoc)
        unary -       (right-assoc)
        primary       (literal | identifier | call | parens)
    """

    def __init__(self, tokens: Sequence[Token]):
        self._tokens = list(tokens)
        self._i = 0

    def _peek(self) -> Token:
        return self._tokens[self._i]

    def _advance(self) -> Token:
        tok = self._tokens[self._i]
        self._i += 1
        return tok

    def _expect(self, kind: str, text: str | None = None) -> Token:
        tok = self._peek()
        if tok.kind != kind or (text is not None and tok.text != text):
            want = text if text is not None else kind
            raise DslError(f"expected {want!r}, got {tok.text!r} at column {tok.pos}")
        return self._advance()

    def parse_top(self) -> Expr:
        expr = self._parse_or()
        if self._peek().kind != "EOF":
            tok = self._peek()
            raise DslError(f"unexpected trailing token {tok.text!r} at column {tok.pos}")
        return expr

    def _parse_or(self) -> Expr:
        left = self._parse_and()
        while self._peek().kind == "NAME" and self._peek().text == "or":
            self._advance()
            right = self._parse_and()
            left = BinaryOp("or", left, right)
        return left

    def _parse_and(self) -> Expr:
        left = self._parse_not()
        while self._peek().kind == "NAME" and self._peek().text == "and":
            self._advance()
            right = self._parse_not()
            left = BinaryOp("and", left, right)
        return left

    def _parse_not(self) -> Expr:
        if self._peek().kind == "NAME" and self._peek().text == "not":
            self._advance()
            return UnaryOp("not", self._parse_not())
        return self._parse_comparison()

    def _parse_comparison(self) -> Expr:
        left = self._parse_additive()
        tok = self._peek()
        if tok.kind == "OP" and tok.text in ("==", "!=", "<", "<=", ">", ">="):
            self._advance()
            right = self._parse_additive()
            # Comparison is non-chaining: a < b < c is a syntax error.
            nxt = self._peek()
            if nxt.kind == "OP" and nxt.text in ("==", "!=", "<", "<=", ">", ">="):
                raise DslError(
                    f"chained comparison not allowed; insert parentheses or 'and' at column {nxt.pos}"
                )
            return BinaryOp(tok.text, left, right)
        return left

    def _parse_additive(self) -> Expr:
        left = self._parse_multiplicative()
        while self._peek().kind == "OP" and self._peek().text in ("+", "-"):
            op = self._advance().text
            right = self._parse_multiplicative()
            left = BinaryOp(op, left, right)
        return left

    def _parse_multiplicative(self) -> Expr:
        left = self._parse_unary_minus()
        while self._peek().kind == "OP" and self._peek().text in ("*", "/"):
            op = self._advance().text
            right = self._parse_unary_minus()
            left = BinaryOp(op, left, right)
        return left

    def _parse_unary_minus(self) -> Expr:
        if self._peek().kind == "OP" and self._peek().text == "-":
            self._advance()
            return UnaryOp("-", self._parse_unary_minus())
        return self._parse_primary()

    def _parse_primary(self) -> Expr:
        tok = self._peek()
        if tok.kind == "NUMBER":
            self._advance()
            return _parse_number_literal(tok)
        if tok.kind == "STRING":
            self._advance()
            return Literal(tok.text)
        if tok.kind == "LPAREN":
            self._advance()
            inner = self._parse_or()
            self._expect("RPAREN")
            return inner
        if tok.kind == "NAME":
            return self._parse_name()
        raise DslError(f"unexpected token {tok.text!r} at column {tok.pos}")

    def _parse_name(self) -> Expr:
        tok = self._advance()
        name = tok.text
        # Boolean literals
        if name == "true":
            return Literal(True)
        if name == "false":
            return Literal(False)
        # Identifier ctx.field — must be dotted with exactly one dot
        if name.startswith("ctx."):
            field_name = name[4:]
            if "." in field_name or not field_name:
                raise DslError(f"invalid identifier {name!r} at column {tok.pos}")
            if field_name not in WHITELIST_FIELDS:
                raise DslError(
                    f"identifier 'ctx.{field_name}' not in whitelist at column {tok.pos}"
                )
            return Identifier(field_name)
        # Bare 'ctx' is not valid
        if name == "ctx":
            raise DslError(f"bare 'ctx' is not a value (use 'ctx.<field>') at column {tok.pos}")
        # Function call — must be followed by (
        if self._peek().kind != "LPAREN":
            raise DslError(
                f"unknown name {name!r} (expected function call or 'ctx.<field>') at column {tok.pos}"
            )
        if name not in WHITELIST_FUNCTIONS:
            raise DslError(f"function {name!r} not in whitelist at column {tok.pos}")
        self._advance()  # consume LPAREN
        args: list[Expr] = []
        if self._peek().kind != "RPAREN":
            args.append(self._parse_or())
            while self._peek().kind == "COMMA":
                self._advance()
                args.append(self._parse_or())
        self._expect("RPAREN")
        return FunctionCall(name, tuple(args))


def _parse_number_literal(tok: Token) -> Literal:
    text = tok.text
    try:
        if any(ch in text for ch in (".", "e", "E")):
            value: int | float = float(text)
        else:
            value = int(text)
    except ValueError:
        raise DslError(f"malformed number {text!r} at column {tok.pos}")
    if isinstance(value, float) and (value != value or abs(value) == float("inf")):
        raise DslError(f"non-finite numeric literal at column {tok.pos}")
    if abs(value) > MAX_NUMERIC_MAGNITUDE:
        raise DslError(
            f"numeric literal {text!r} exceeds magnitude limit {MAX_NUMERIC_MAGNITUDE}"
        )
    return Literal(value)


def parse_expression(source: str) -> Expr:
    """Tokenize and parse a single expression. Whitelist-checked here too."""
    tokens = _tokenize(source)
    return _Parser(tokens).parse_top()


# ---------------------------------------------------------------------------
# AST validation: depth limit + post-parse whitelist verification.
# ---------------------------------------------------------------------------


def _ast_depth(node: Expr) -> int:
    if isinstance(node, (Literal, Identifier)):
        return 1
    if isinstance(node, UnaryOp):
        return 1 + _ast_depth(node.operand)
    if isinstance(node, BinaryOp):
        return 1 + max(_ast_depth(node.left), _ast_depth(node.right))
    if isinstance(node, FunctionCall):
        return 1 + max((_ast_depth(a) for a in node.args), default=0)
    raise DslError(f"unknown AST node {type(node).__name__}")


def validate_ast(node: Expr, max_depth: int = MAX_AST_DEPTH) -> None:
    """Raise DslError if the AST violates whitelist or depth constraints.

    The parser also enforces whitelists, but this function is intended to be
    callable on any AST handed in from elsewhere (caches, hot-reload, tests).
    """
    depth = _ast_depth(node)
    if depth > max_depth:
        raise DslError(f"AST depth {depth} exceeds limit {max_depth}")
    _walk_validate(node)


def _walk_validate(node: Expr) -> None:
    if isinstance(node, Identifier):
        if node.field not in WHITELIST_FIELDS:
            raise DslError(f"identifier 'ctx.{node.field}' not in whitelist")
        return
    if isinstance(node, FunctionCall):
        if node.func not in WHITELIST_FUNCTIONS:
            raise DslError(f"function {node.func!r} not in whitelist")
        # Per-function arity check
        _check_arity(node)
        for a in node.args:
            _walk_validate(a)
        return
    if isinstance(node, UnaryOp):
        if node.op not in ("not", "-"):
            raise DslError(f"unknown unary op {node.op!r}")
        _walk_validate(node.operand)
        return
    if isinstance(node, BinaryOp):
        if node.op not in {"==", "!=", "<", "<=", ">", ">=",
                           "+", "-", "*", "/", "and", "or"}:
            raise DslError(f"unknown binary op {node.op!r}")
        _walk_validate(node.left)
        _walk_validate(node.right)
        return
    if isinstance(node, Literal):
        if isinstance(node.value, (int, float)) and abs(node.value) > MAX_NUMERIC_MAGNITUDE:
            raise DslError(f"numeric literal exceeds magnitude limit")
        return
    raise DslError(f"unknown AST node {type(node).__name__}")


def _check_arity(call: FunctionCall) -> None:
    fn = call.func
    n = len(call.args)
    if fn == "min" or fn == "max":
        if n < 2:
            raise DslError(f"{fn} requires at least 2 arguments, got {n}")
    elif fn == "clip":
        if n != 3:
            raise DslError(f"clip(value, lo, hi) requires 3 arguments, got {n}")
    elif fn == "lookup":
        if n != 2:
            raise DslError(f"lookup(table, key) requires 2 arguments, got {n}")


# ---------------------------------------------------------------------------
# Evaluator. No side effects, no I/O, total over the validated AST.
# ---------------------------------------------------------------------------


def evaluate(
    node: Expr,
    ctx: ResolverContext,
    lookups: Mapping[str, Mapping[Any, Any]],
) -> Any:
    if isinstance(node, Literal):
        return node.value
    if isinstance(node, Identifier):
        return ctx.get(node.field)
    if isinstance(node, UnaryOp):
        v = evaluate(node.operand, ctx, lookups)
        if node.op == "not":
            return not _truthy(v)
        if node.op == "-":
            if not isinstance(v, (int, float)) or isinstance(v, bool):
                raise DslError(f"unary '-' requires numeric operand, got {type(v).__name__}")
            r = -v
            if isinstance(r, float) and (r != r or abs(r) == float("inf")):
                raise DslError("non-finite intermediate value")
            return r
    if isinstance(node, BinaryOp):
        op = node.op
        # Short-circuit logical
        if op == "and":
            l = evaluate(node.left, ctx, lookups)
            if not _truthy(l):
                return False
            return _truthy(evaluate(node.right, ctx, lookups))
        if op == "or":
            l = evaluate(node.left, ctx, lookups)
            if _truthy(l):
                return True
            return _truthy(evaluate(node.right, ctx, lookups))
        a = evaluate(node.left, ctx, lookups)
        b = evaluate(node.right, ctx, lookups)
        if op in ("==", "!="):
            return (a == b) if op == "==" else (a != b)
        if op in ("<", "<=", ">", ">="):
            return _compare(op, a, b)
        if op in ("+", "-", "*", "/"):
            return _arith(op, a, b)
        raise DslError(f"unknown binary op {op!r}")
    if isinstance(node, FunctionCall):
        args = [evaluate(a, ctx, lookups) for a in node.args]
        return _builtin_call(node.func, args, lookups)
    raise DslError(f"unknown AST node {type(node).__name__}")


def _truthy(v: Any) -> bool:
    return bool(v)


def _compare(op: str, a: Any, b: Any) -> bool:
    # Mixed-type comparison is rejected to avoid Python truthiness surprises.
    if isinstance(a, bool) or isinstance(b, bool):
        raise DslError(f"comparison {op!r} not defined on booleans")
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        pass
    elif isinstance(a, str) and isinstance(b, str):
        pass
    else:
        raise DslError(
            f"comparison {op!r} requires same-typed numeric or string operands"
        )
    if op == "<":
        return a < b
    if op == "<=":
        return a <= b
    if op == ">":
        return a > b
    if op == ">=":
        return a >= b
    raise DslError(f"unknown comparison {op!r}")


def _arith(op: str, a: Any, b: Any) -> int | float:
    if isinstance(a, bool) or isinstance(b, bool):
        raise DslError(f"arithmetic {op!r} not defined on booleans")
    if not (isinstance(a, (int, float)) and isinstance(b, (int, float))):
        raise DslError(f"arithmetic {op!r} requires numeric operands")
    if op == "+":
        r = a + b
    elif op == "-":
        r = a - b
    elif op == "*":
        r = a * b
    elif op == "/":
        if b == 0:
            raise DslError("division by zero")
        r = a / b
    else:
        raise DslError(f"unknown arithmetic op {op!r}")
    if isinstance(r, float) and (r != r or abs(r) == float("inf")):
        raise DslError("non-finite intermediate value")
    if isinstance(r, (int, float)) and abs(r) > MAX_NUMERIC_MAGNITUDE:
        raise DslError("intermediate value exceeds magnitude limit")
    return r


def _builtin_call(
    name: str,
    args: list[Any],
    lookups: Mapping[str, Mapping[Any, Any]],
) -> Any:
    if name == "min":
        return _builtin_min_max(min, args)
    if name == "max":
        return _builtin_min_max(max, args)
    if name == "clip":
        val, lo, hi = args
        for v in (val, lo, hi):
            if not isinstance(v, (int, float)) or isinstance(v, bool):
                raise DslError("clip requires numeric arguments")
        if lo > hi:
            raise DslError("clip lo must be <= hi")
        return max(lo, min(hi, val))
    if name == "lookup":
        table_name, key = args
        if not isinstance(table_name, str):
            raise DslError("lookup table name must be a string literal")
        table = lookups.get(table_name)
        if table is None:
            raise DslError(f"lookup table {table_name!r} not registered")
        if key not in table:
            raise DslError(f"lookup key {key!r} not in table {table_name!r}")
        return table[key]
    raise DslError(f"unknown builtin {name!r}")


def _builtin_min_max(fn: Callable[..., Any], args: list[Any]) -> int | float:
    for v in args:
        if not isinstance(v, (int, float)) or isinstance(v, bool):
            raise DslError(f"{fn.__name__} requires numeric arguments")
    return fn(*args)


# ---------------------------------------------------------------------------
# ThresholdResolver — composes rules and supports atomic hot-reload.
# ---------------------------------------------------------------------------


def _parse_rule(raw: Mapping[str, Any]) -> Rule:
    keys = set(raw.keys())
    if "default" in keys:
        if keys - {"default"}:
            raise DslError(f"default rule must have only 'default' key, got {keys}")
        return Rule(condition=None, value=_value_to_expr(raw["default"]))
    if "if" in keys and "value" in keys:
        if keys - {"if", "value"}:
            raise DslError(f"conditional rule has unexpected keys: {keys}")
        cond_text = raw["if"]
        if not isinstance(cond_text, str):
            raise DslError("'if' must be a string expression")
        cond = parse_expression(cond_text)
        validate_ast(cond)
        return Rule(condition=cond, value=_value_to_expr(raw["value"]))
    raise DslError(f"rule must have keys ('if', 'value') or ('default',), got {keys}")


def _value_to_expr(raw: Any) -> Expr:
    """YAML scalars stay literal; strings parse as DSL expressions."""
    if isinstance(raw, bool):
        return Literal(raw)
    if isinstance(raw, int):
        if abs(raw) > MAX_NUMERIC_MAGNITUDE:
            raise DslError("integer literal exceeds magnitude limit")
        return Literal(raw)
    if isinstance(raw, float):
        if raw != raw or abs(raw) == float("inf"):
            raise DslError("non-finite numeric literal")
        if abs(raw) > MAX_NUMERIC_MAGNITUDE:
            raise DslError("float literal exceeds magnitude limit")
        return Literal(raw)
    if isinstance(raw, str):
        expr = parse_expression(raw)
        validate_ast(expr)
        return expr
    raise DslError(f"unsupported value type {type(raw).__name__}")


class ThresholdResolver:
    """Evaluates ordered rule lists against a ResolverContext.

    Rules are applied in declaration order; the first rule whose condition
    evaluates truthy wins. A `default` rule (condition None) is required to
    appear last and is used when no conditional rule matches.

    The resolver is thread-safe: .resolve() and .reload() take a lock; reads
    snapshot the rules table reference atomically.
    """

    def __init__(
        self,
        rules: Mapping[str, Sequence[Rule]],
        lookups: Mapping[str, Mapping[Any, Any]] | None = None,
    ):
        self._validate_table(rules)
        self._rules: Mapping[str, tuple[Rule, ...]] = {
            k: tuple(v) for k, v in rules.items()
        }
        self._lookups: Mapping[str, Mapping[Any, Any]] = dict(lookups or {})
        self._lock = threading.Lock()

    @staticmethod
    def _validate_table(rules: Mapping[str, Sequence[Rule]]) -> None:
        for name, rule_list in rules.items():
            if not rule_list:
                raise DslError(f"threshold {name!r} has no rules")
            for rule in rule_list[:-1]:
                if rule.condition is None:
                    raise DslError(
                        f"threshold {name!r}: 'default' must be last rule"
                    )
            last = rule_list[-1]
            if last.condition is not None:
                raise DslError(
                    f"threshold {name!r}: rule list must end with a 'default' rule"
                )

    @classmethod
    def from_config(
        cls,
        config: Mapping[str, Sequence[Mapping[str, Any]]],
        lookups: Mapping[str, Mapping[Any, Any]] | None = None,
    ) -> "ThresholdResolver":
        """Parse a dict-of-rule-lists (typically loaded from YAML)."""
        parsed: dict[str, list[Rule]] = {}
        for name, raw_rules in config.items():
            if not isinstance(raw_rules, (list, tuple)):
                raise DslError(f"threshold {name!r}: rules must be a list")
            parsed[name] = [_parse_rule(r) for r in raw_rules]
        return cls(parsed, lookups=lookups)

    def resolve(self, name: str, ctx: ResolverContext) -> Any:
        with self._lock:
            rules = self._rules
            lookups = self._lookups
        if name not in rules:
            raise DslError(f"threshold {name!r} not defined")
        for rule in rules[name]:
            if rule.condition is None:
                return evaluate(rule.value, ctx, lookups)
            if _truthy(evaluate(rule.condition, ctx, lookups)):
                return evaluate(rule.value, ctx, lookups)
        # Defensive: validate_table guarantees a default. Should be unreachable.
        raise DslError(f"threshold {name!r}: no rule matched and no default")

    def reload(
        self,
        config: Mapping[str, Sequence[Mapping[str, Any]]],
        lookups: Mapping[str, Mapping[Any, Any]] | None = None,
    ) -> None:
        """Atomic replacement: parse + validate before swap. On failure, the
        existing table is preserved unchanged.
        """
        new = self.from_config(config, lookups=lookups)
        with self._lock:
            self._rules = new._rules
            self._lookups = new._lookups
