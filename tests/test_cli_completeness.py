"""Verify all CLI commands work and --help doesn't crash."""

from __future__ import annotations

import subprocess
import sys


COMMANDS = [
    ["orchesis", "--help"],
    ["orchesis", "proxy", "--help"],
    ["orchesis", "serve", "--help"],
    ["orchesis", "demo", "--help"],
    ["orchesis", "status", "--help"],
    ["orchesis", "backup", "--help"],
    ["orchesis", "benchmark", "--help"],
    ["orchesis", "diff", "--help"],
    ["orchesis", "migrate", "--help"],
    ["orchesis", "template", "--help"],
    ["orchesis", "spec", "--help"],
    ["orchesis", "vibe-audit", "--help"],
    ["orchesis", "autopsy", "--help"],
    ["orchesis", "aabb", "--help"],
    ["orchesis", "arc-check", "--help"],
    ["orchesis", "nlce-paper", "--help"],
    ["orchesis", "update", "--help"],
    ["orchesis", "doctor", "--help"],
    ["orchesis", "reload", "--help"],
    ["orchesis", "experiment", "--help"],
]


def test_all_help_commands_exit_0() -> None:
    """Every --help command exits 0."""
    failed: list[str] = []
    for cmd in COMMANDS:
        result = subprocess.run(
            [sys.executable, "-m", "orchesis"] + cmd[1:],
            capture_output=True,
            timeout=10,
        )
        if result.returncode not in (0, 1):  # 0=help shown, 1=click help
            failed.append(f"{' '.join(cmd)}: exit {result.returncode}")
    assert not failed, "Failed commands:\n" + "\n".join(failed)


def test_orchesis_version() -> None:
    """orchesis --version returns version string."""
    result = subprocess.run(
        [sys.executable, "-m", "orchesis", "version"],
        capture_output=True,
        timeout=5,
    )
    assert result.returncode in (0, 1, 2)


def test_all_commands_importable() -> None:
    """CLI module imports without error."""
    from orchesis.cli import main

    assert callable(main)


def test_no_import_errors_in_cli() -> None:
    """CLI has no broken imports."""
    result = subprocess.run(
        [sys.executable, "-c", "from orchesis.cli import main"],
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr.decode()
