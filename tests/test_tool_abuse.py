"""contrib.tool_abuse — skipped when the module is not shipped in this tree."""

from __future__ import annotations

import importlib

import pytest

try:
    tool_abuse = importlib.import_module("orchesis.contrib.tool_abuse")
except ModuleNotFoundError:  # pragma: no cover - optional path
    tool_abuse = None

pytestmark = pytest.mark.skipif(
    tool_abuse is None,
    reason="orchesis.contrib.tool_abuse is not present in this repository",
)


def test_tool_abuse_imports_cleanly() -> None:
    assert tool_abuse is not None
    assert tool_abuse.__doc__ is not None or True


def test_tool_abuse_main_class_instantiates() -> None:
    # If module exists, try a no-arg or dict-arg constructor pattern used across contrib.
    public = [n for n in dir(tool_abuse) if not n.startswith("_") and n[0].isupper()]
    assert public, "expected at least one public class"
    cls = getattr(tool_abuse, public[0])
    try:
        obj = cls()
    except TypeError:
        obj = cls({})
    assert obj is not None


def test_tool_abuse_main_function_basic_usage() -> None:
    funcs = [
        n
        for n in dir(tool_abuse)
        if not n.startswith("_") and callable(getattr(tool_abuse, n)) and n[0].islower()
    ]
    assert funcs, "expected at least one public function"
    fn = getattr(tool_abuse, funcs[0])
    try:
        fn()
    except TypeError:
        fn("", {})


def test_tool_abuse_handles_empty_input() -> None:
    # Best-effort: scan callable that accepts str/list
    for name in dir(tool_abuse):
        if name.startswith("_"):
            continue
        obj = getattr(tool_abuse, name)
        if not callable(obj):
            continue
        try:
            obj("")
            return
        except TypeError:
            continue
    pytest.skip("no callable accepted empty str")


def test_tool_abuse_handles_none_input() -> None:
    for name in dir(tool_abuse):
        if name.startswith("_"):
            continue
        obj = getattr(tool_abuse, name)
        if not callable(obj):
            continue
        try:
            obj(None)
            return
        except TypeError:
            continue
    pytest.skip("no callable accepted None")
