"""Tests for orchesis.dsl — threshold DSL parser, validator, evaluator, resolver."""

from __future__ import annotations

import threading

import pytest

from orchesis.dsl import (
    BinaryOp,
    DslError,
    FunctionCall,
    Identifier,
    Literal,
    MAX_AST_DEPTH,
    MAX_NUMERIC_MAGNITUDE,
    ResolverContext,
    Rule,
    ThresholdResolver,
    UnaryOp,
    evaluate,
    parse_expression,
    validate_ast,
)


# ---------------------------------------------------------------------------
# Tokenizer / parser
# ---------------------------------------------------------------------------


class TestTokenizer:
    def test_string_with_escapes(self):
        expr = parse_expression('"a\\nb\\tc\\\\d\\"e"')
        assert isinstance(expr, Literal)
        assert expr.value == 'a\nb\tc\\d"e'

    def test_unterminated_string(self):
        with pytest.raises(DslError, match="unterminated"):
            parse_expression('"abc')

    def test_unknown_escape(self):
        with pytest.raises(DslError, match="unknown string escape"):
            parse_expression('"\\q"')

    def test_unexpected_character(self):
        with pytest.raises(DslError, match="unexpected character"):
            parse_expression("a # b")


class TestParseLiterals:
    def test_integer(self):
        assert parse_expression("42") == Literal(42)

    def test_negative_integer_parsed_as_unary(self):
        # Per grammar, leading '-' is a unary op, not part of literal.
        e = parse_expression("-5")
        assert e == UnaryOp("-", Literal(5))

    def test_float(self):
        e = parse_expression("0.55")
        assert isinstance(e, Literal)
        assert e.value == 0.55

    def test_scientific(self):
        e = parse_expression("1.5e-3")
        assert isinstance(e, Literal)
        assert e.value == pytest.approx(0.0015)

    def test_true_false(self):
        assert parse_expression("true") == Literal(True)
        assert parse_expression("false") == Literal(False)

    def test_string_literal(self):
        assert parse_expression('"paranoid"') == Literal("paranoid")

    def test_numeric_overflow_rejected(self):
        with pytest.raises(DslError, match="magnitude"):
            parse_expression("1e30")


class TestParseIdentifiers:
    def test_ctx_field(self):
        e = parse_expression("ctx.tier")
        assert e == Identifier("tier")

    def test_ctx_field_not_in_whitelist(self):
        with pytest.raises(DslError, match="not in whitelist"):
            parse_expression("ctx.secret")

    def test_bare_ctx_rejected(self):
        with pytest.raises(DslError, match="bare 'ctx'"):
            parse_expression("ctx")

    def test_invalid_dotted_identifier(self):
        with pytest.raises(DslError, match="invalid identifier"):
            parse_expression("ctx.tier.sub")


class TestParseFunctionCalls:
    def test_simple_call(self):
        e = parse_expression("min(1, 2)")
        assert e == FunctionCall("min", (Literal(1), Literal(2)))

    def test_function_not_in_whitelist(self):
        with pytest.raises(DslError, match="not in whitelist"):
            parse_expression("eval(1)")

    def test_lookup_call(self):
        e = parse_expression('lookup("table", ctx.reliability_profile)')
        assert e == FunctionCall("lookup", (Literal("table"), Identifier("reliability_profile")))

    def test_clip_arity(self):
        with pytest.raises(DslError, match="3 arguments"):
            ast = parse_expression("clip(1, 2)")  # parsed OK, validated downstream
            validate_ast(ast)

    def test_min_arity(self):
        with pytest.raises(DslError, match="at least 2 arguments"):
            ast = parse_expression("min(1)")
            validate_ast(ast)

    def test_lookup_arity(self):
        with pytest.raises(DslError, match="2 arguments"):
            ast = parse_expression('lookup("table")')
            validate_ast(ast)


class TestPrecedence:
    def test_and_binds_tighter_than_or(self):
        # a or b and c == a or (b and c)
        e = parse_expression("ctx.tier == \"a\" or ctx.tier == \"b\" and ctx.chain_length > 5")
        assert isinstance(e, BinaryOp) and e.op == "or"
        assert isinstance(e.right, BinaryOp) and e.right.op == "and"

    def test_not_binds_tighter_than_and(self):
        e = parse_expression("not ctx.tier == \"a\" and ctx.chain_length > 5")
        assert isinstance(e, BinaryOp) and e.op == "and"
        assert isinstance(e.left, UnaryOp) and e.left.op == "not"

    def test_comparison_not_chained(self):
        with pytest.raises(DslError, match="chained comparison"):
            parse_expression("1 < 2 < 3")

    def test_arithmetic_precedence(self):
        # 1 + 2 * 3 == 1 + (2 * 3)
        e = parse_expression("1 + 2 * 3")
        assert isinstance(e, BinaryOp) and e.op == "+"
        assert isinstance(e.right, BinaryOp) and e.right.op == "*"

    def test_parens_override(self):
        e = parse_expression("(1 + 2) * 3")
        assert isinstance(e, BinaryOp) and e.op == "*"
        assert isinstance(e.left, BinaryOp) and e.left.op == "+"

    def test_unary_minus_then_multiply(self):
        e = parse_expression("-2 * 3")
        assert isinstance(e, BinaryOp) and e.op == "*"
        assert isinstance(e.left, UnaryOp) and e.left.op == "-"


class TestParseErrors:
    def test_unmatched_paren(self):
        with pytest.raises(DslError):
            parse_expression("(1 + 2")

    def test_trailing_tokens(self):
        with pytest.raises(DslError, match="trailing"):
            parse_expression("1 + 2 3")

    def test_empty_string(self):
        with pytest.raises(DslError):
            parse_expression("")


# ---------------------------------------------------------------------------
# AST validation
# ---------------------------------------------------------------------------


class TestValidation:
    def test_depth_limit(self):
        # Left-associative '+' chain makes AST depth equal the number of terms.
        deep = " + ".join("1" for _ in range(MAX_AST_DEPTH + 5))
        ast = parse_expression(deep)
        with pytest.raises(DslError, match="depth"):
            validate_ast(ast)

    def test_depth_limit_nested_calls(self):
        # Nested function calls: min(min(min(...1, 2..., 2), 2), 2) builds depth.
        # Each min(x, 2) adds one level of BinaryOp-like nesting via FunctionCall.
        expr = "1"
        for _ in range(MAX_AST_DEPTH + 5):
            expr = f"min({expr}, 2)"
        ast = parse_expression(expr)
        with pytest.raises(DslError, match="depth"):
            validate_ast(ast)

    def test_within_depth(self):
        ast = parse_expression("1 + 2 + 3 + 4 + 5")
        validate_ast(ast)  # should not raise


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


def _eval(src: str, ctx: ResolverContext | None = None, lookups=None) -> object:
    ast = parse_expression(src)
    validate_ast(ast)
    return evaluate(ast, ctx or ResolverContext(), lookups or {})


class TestEvalLiterals:
    def test_int(self):
        assert _eval("42") == 42

    def test_float(self):
        assert _eval("3.14") == pytest.approx(3.14)

    def test_bool(self):
        assert _eval("true") is True
        assert _eval("false") is False

    def test_string(self):
        assert _eval('"hello"') == "hello"


class TestEvalIdentifiers:
    def test_string_field(self):
        ctx = ResolverContext(tier="paranoid")
        assert _eval("ctx.tier", ctx) == "paranoid"

    def test_numeric_field(self):
        ctx = ResolverContext(chain_length=42)
        assert _eval("ctx.chain_length", ctx) == 42


class TestEvalLogical:
    def test_and_short_circuit(self):
        # If right side would fail, short circuit must prevent it.
        ctx = ResolverContext(tier="permissive")
        # ctx.tier == "paranoid" is False, so right side (which uses unwhitelisted
        # logic via division-by-zero) must never be evaluated.
        assert _eval('ctx.tier == "paranoid" and (1 / 0)', ctx) is False

    def test_or_short_circuit(self):
        ctx = ResolverContext(tier="paranoid")
        assert _eval('ctx.tier == "paranoid" or (1 / 0)', ctx) is True

    def test_not(self):
        assert _eval("not true") is False
        assert _eval("not false") is True


class TestEvalComparison:
    def test_int_eq(self):
        assert _eval("3 == 3") is True
        assert _eval("3 == 4") is False

    def test_string_eq(self):
        assert _eval('"a" == "a"') is True

    def test_lt(self):
        assert _eval("3 < 4") is True
        assert _eval("4 < 3") is False

    def test_bool_comparison_rejected(self):
        with pytest.raises(DslError, match="booleans"):
            _eval("true < false")

    def test_mixed_type_rejected(self):
        with pytest.raises(DslError, match="same-typed"):
            _eval('"a" < 1')


class TestEvalArithmetic:
    def test_add(self):
        assert _eval("2 + 3") == 5

    def test_sub(self):
        assert _eval("5 - 2") == 3

    def test_mul(self):
        assert _eval("4 * 5") == 20

    def test_div(self):
        assert _eval("10 / 4") == pytest.approx(2.5)

    def test_div_by_zero(self):
        with pytest.raises(DslError, match="division by zero"):
            _eval("1 / 0")

    def test_unary_minus(self):
        assert _eval("-5") == -5

    def test_bool_arithmetic_rejected(self):
        with pytest.raises(DslError, match="booleans"):
            _eval("true + 1")


class TestEvalFunctions:
    def test_min(self):
        assert _eval("min(3, 1, 2)") == 1

    def test_max(self):
        assert _eval("max(3, 1, 2)") == 3

    def test_clip(self):
        assert _eval("clip(5, 0, 10)") == 5
        assert _eval("clip(-3, 0, 10)") == 0
        assert _eval("clip(15, 0, 10)") == 10

    def test_clip_invalid_range(self):
        with pytest.raises(DslError, match="lo must be"):
            _eval("clip(5, 10, 0)")

    def test_lookup(self):
        ctx = ResolverContext(reliability_profile="strict")
        lookups = {"sigma_by_profile": {"permissive": 0.7, "strict": 0.5}}
        assert _eval('lookup("sigma_by_profile", ctx.reliability_profile)', ctx, lookups) == 0.5

    def test_lookup_missing_table(self):
        with pytest.raises(DslError, match="not registered"):
            _eval('lookup("nope", "x")')

    def test_lookup_missing_key(self):
        lookups = {"t": {"a": 1}}
        with pytest.raises(DslError, match="not in table"):
            _eval('lookup("t", "b")', lookups=lookups)


class TestEvalOverflow:
    def test_intermediate_overflow_rejected(self):
        with pytest.raises(DslError, match="magnitude"):
            _eval(f"{int(MAX_NUMERIC_MAGNITUDE / 2)} * 100")


# ---------------------------------------------------------------------------
# ThresholdResolver
# ---------------------------------------------------------------------------


def _sample_config():
    return {
        "sigma_cascade": [
            {"if": 'ctx.tier == "paranoid" and ctx.task_type == "tool_calling"', "value": 0.55},
            {"if": 'ctx.tier == "paranoid"', "value": 0.70},
            {"if": "ctx.chain_length > 50", "value": 0.65},
            {"default": 'lookup("sigma_by_profile", ctx.reliability_profile)'},
        ],
    }


class TestThresholdResolver:
    def test_first_match_wins(self):
        r = ThresholdResolver.from_config(_sample_config(), lookups={
            "sigma_by_profile": {"balanced": 0.6},
        })
        ctx = ResolverContext(tier="paranoid", task_type="tool_calling", reliability_profile="balanced")
        assert r.resolve("sigma_cascade", ctx) == 0.55

    def test_second_rule(self):
        r = ThresholdResolver.from_config(_sample_config(), lookups={
            "sigma_by_profile": {"balanced": 0.6},
        })
        ctx = ResolverContext(tier="paranoid", task_type="generation", reliability_profile="balanced")
        assert r.resolve("sigma_cascade", ctx) == 0.70

    def test_third_rule(self):
        r = ThresholdResolver.from_config(_sample_config(), lookups={
            "sigma_by_profile": {"balanced": 0.6},
        })
        ctx = ResolverContext(tier="balanced", chain_length=100, reliability_profile="balanced")
        assert r.resolve("sigma_cascade", ctx) == 0.65

    def test_default_applies(self):
        r = ThresholdResolver.from_config(_sample_config(), lookups={
            "sigma_by_profile": {"balanced": 0.6},
        })
        ctx = ResolverContext(tier="balanced", chain_length=10, reliability_profile="balanced")
        assert r.resolve("sigma_cascade", ctx) == 0.6

    def test_unknown_threshold(self):
        r = ThresholdResolver.from_config(_sample_config(), lookups={
            "sigma_by_profile": {"balanced": 0.6},
        })
        with pytest.raises(DslError, match="not defined"):
            r.resolve("does_not_exist", ResolverContext())

    def test_default_must_be_last(self):
        bad = {
            "x": [
                {"default": 1},
                {"if": "ctx.chain_length > 0", "value": 2},
            ]
        }
        with pytest.raises(DslError, match="must be last"):
            ThresholdResolver.from_config(bad)

    def test_default_required(self):
        bad = {"x": [{"if": "ctx.chain_length > 0", "value": 2}]}
        with pytest.raises(DslError, match="must end with a 'default'"):
            ThresholdResolver.from_config(bad)

    def test_empty_rules_rejected(self):
        with pytest.raises(DslError, match="has no rules"):
            ThresholdResolver.from_config({"x": []})

    def test_invalid_yaml_value_type(self):
        with pytest.raises(DslError, match="unsupported value type"):
            ThresholdResolver.from_config({"x": [{"default": [1, 2]}]})

    def test_invalid_rule_keys(self):
        with pytest.raises(DslError, match="unexpected keys"):
            ThresholdResolver.from_config({"x": [{"if": "true", "value": 1, "extra": 2}]})


class TestHotReload:
    def test_atomic_replace(self):
        r = ThresholdResolver.from_config({"x": [{"default": 1}]})
        ctx = ResolverContext()
        assert r.resolve("x", ctx) == 1
        r.reload({"x": [{"default": 2}]})
        assert r.resolve("x", ctx) == 2

    def test_invalid_reload_preserves_existing(self):
        r = ThresholdResolver.from_config({"x": [{"default": 1}]})
        ctx = ResolverContext()
        assert r.resolve("x", ctx) == 1
        # Invalid config: missing default
        with pytest.raises(DslError):
            r.reload({"x": [{"if": "ctx.chain_length > 0", "value": 99}]})
        # Existing table preserved.
        assert r.resolve("x", ctx) == 1

    def test_concurrent_resolve_during_reload(self):
        """Reload should not corrupt concurrent reads."""
        r = ThresholdResolver.from_config({"x": [{"default": 1}]})
        ctx = ResolverContext()
        errors: list[Exception] = []
        results: list[object] = []

        def reader():
            for _ in range(1000):
                try:
                    results.append(r.resolve("x", ctx))
                except Exception as e:  # pragma: no cover
                    errors.append(e)

        def reloader():
            for i in range(500):
                r.reload({"x": [{"default": (i % 2) + 1}]})

        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=reader),
            threading.Thread(target=reloader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        # All results must be one of the values we ever set.
        assert set(results) <= {1, 2}


class TestSecurityBoundaries:
    def test_no_arbitrary_attribute_access(self):
        # __class__.__bases__ style escapes must not parse.
        with pytest.raises(DslError):
            parse_expression("ctx.__class__")

    def test_no_python_builtins(self):
        for name in ("len", "open", "exec", "eval", "getattr", "__import__"):
            with pytest.raises(DslError):
                parse_expression(f"{name}(1)")

    def test_no_string_concat_via_plus(self):
        # Arithmetic + on strings is rejected at evaluation time.
        with pytest.raises(DslError, match="numeric operands"):
            _eval('"a" + "b"')
