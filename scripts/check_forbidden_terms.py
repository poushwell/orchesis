#!/usr/bin/env python3
"""Pre-commit hook: scan staged changes for forbidden masking terms.

Two modes:
  --audit  (default): print all matches, exit 0 (never blocks).
  --block:  exit 1 on any HARD match; SOFT matches print warnings.

Install:
    cp scripts/check_forbidden_terms.py .git/hooks/pre-commit-runner.py
    cat > .git/hooks/pre-commit <<'SH'
    #!/bin/sh
    python3 .git/hooks/pre-commit-runner.py --block || exit 1
    SH
    chmod +x .git/hooks/pre-commit

Patterns are sourced from `docs/orchesis_masking_task.md` Section A.2 and
`docs/MASKING_RENAME_MAP.yaml` reserved_terms. Keep this in sync when
adding new terms.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from typing import Iterable


FORBIDDEN_HARD: tuple[tuple[str, str], ...] = (
    # (pattern, description)  — case-INSENSITIVE matching unless pattern includes [A-Z]
    (r"\bNLCE\b", "NLCE coined term"),
    (r"Network[- ]Level Context Engineering", "expanded NLCE"),
    (r"\bDSCL\b", "DSCL coined term"),
    (r"\bPAR\b(?!t)", "PAR coined term (Proxy Abductive Reasoning)"),
    (r"Proxy Abductive Reasoning", "expanded PAR"),
    (r"\bIACS\b", "IACS coined acronym"),
    (r"\bCQS\b", "cognitive quality signal acronym"),
    (r"cognitive quality signal", "expanded CQS"),
    (r"\bFEP\b", "FEP — Free Energy Principle"),
    (r"Free Energy Principle", "expanded FEP"),
    (r"\bHGT\b", "HGT — Horizontal Gene Transfer"),
    (r"Horizontal Gene Transfer", "expanded HGT"),
    (r"Context DNA", "Context DNA biology metaphor"),
    (r"Agent DNA", "Agent DNA biology metaphor"),
    (r"\bcontext_dna\b", "context_dna identifier"),
    (r"Red Queen", "Red Queen biology metaphor"),
    (r"\bapoptosis\b", "apoptosis biology metaphor"),
    (r"\bhomeostasis\b", "homeostasis biology metaphor"),
    (r"Crystallinity", "Crystallinity physics metaphor"),
    (r"Crystal Alert", "Crystal Alert physics metaphor"),
    (r"Ψ\s*=", "Greek letter Ψ assignment"),
    (r"gas/liquid/crystal", "phase transition language"),
    (r"phase transition", "phase transition (use 'state change')"),
    (r"\bCarnot\b", "Carnot — physics reference"),
    (r"\bKalman\b", "Kalman — math reference"),
    (r"\bShapley\b", "Shapley — math reference"),
    (r"Kolmogorov complexity", "Kolmogorov complexity"),
    (r"\bsheaf\b", "sheaf math reference"),
    (r"coboundary", "coboundary math reference"),
    (r"branching ratio", "branching ratio (proprietary σ usage)"),
    (r"\bH\d{1,3}\b(?!\s*=)", "H<num> hypothesis labels (e.g. H17, H43)"),
    (r"\bT\d{1,2}\b(?!\s*=)", "T<num> theorem labels (e.g. T1, T5)"),
    (r"\bK\d{1,2}\b(?!\s*=)", "K<num> mechanism labels (e.g. K1, K17)"),
    (r"\bPhase \d+\b", "Phase <num> enumeration"),
    (r"\bLayer \d+\b", "Layer <num> enumeration"),
    (r"\d+-phase pipeline", "N-phase pipeline enumeration"),
    (r"5\+1 stack", "5+1 stack enumeration"),
    (r"6\+1 layer", "6+1 layer enumeration"),
    (r"\d+ impossibility theorems", "impossibility theorem count claim"),
    (r"\d+ formal results", "formal results count claim"),
    (r"Works whether AI wins or loses", "marketing tagline"),
    (r"Only proxy .{0,30} active in the market", "marketing positioning"),
    (r"\d+\.\d{2}x fewer", "specific benchmark claim"),
    (r"\d+\.\d{2}% less", "specific benchmark claim"),
    (r"\bVickrey\b", "Vickrey math reference"),
    (r"\bBellman\b", "Bellman math reference"),
    (r"\bHartley\b", "Hartley math reference"),
)


FORBIDDEN_SOFT: tuple[tuple[str, str], ...] = (
    (r"\bThompson sampling\b", "Thompson sampling — keep algorithm, scrub mentions"),
    (r"\bPID controller\b", "PID controller — keep algorithm, scrub if leaks framework"),
    (r"\bBayesian\b", "Bayesian — generic ML term, review intent"),
    (r"\bByzantine\b", "Byzantine — textbook, but watch for over-association"),
    (r"\bσ\b", "Greek σ — use 'sigma' or other generic name in public docs"),
    (r"\bsigma\b", "sigma — public-doc usage may leak σ-monitoring framing"),
)


# Per masking_task.md A.2, scan applies to .py, .md, .rst, .txt, .yaml, .toml,
# .json, and to commit messages. The pre-commit-hook driver passes the diff.
DEFAULT_EXTENSIONS = (".py", ".md", ".rst", ".txt", ".yaml", ".yml", ".toml", ".json")

# Paths excluded from scanning. Tests retain references to historical names
# to verify backward-compat shims; this scanner module itself documents the
# forbidden patterns as data; private docs/internal/ are excluded from the
# repo entirely but defensively listed here.
EXCLUDED_PATH_PREFIXES = (
    "tests/",
    "scripts/check_forbidden_terms.py",
    "docs/internal/",
    "docs/SPEC.md",
    "docs/orchesis_masking_task.md",
    "docs/MASKING_RENAME_MAP.yaml",
)


def get_staged_diff() -> str:
    """Return the unified diff of currently staged changes."""
    res = subprocess.run(
        ["git", "diff", "--cached", "--unified=0"],
        capture_output=True,
        text=True,
        check=False,
    )
    return res.stdout


def scan_lines(lines: Iterable[str], patterns: tuple[tuple[str, str], ...],
               severity: str) -> list[dict]:
    """Walk added lines in a unified diff and emit one record per match."""
    violations: list[dict] = []
    current_file = ""
    for line in lines:
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            continue
        if not line.startswith("+"):
            continue
        if line.startswith("+++"):  # header
            continue
        added = line[1:]
        # Skip files we don't care about based on extension.
        if current_file and not any(current_file.endswith(ext) for ext in DEFAULT_EXTENSIONS):
            continue
        # Skip explicitly excluded paths (tests, the scanner module, private docs).
        if current_file and any(current_file.startswith(p) for p in EXCLUDED_PATH_PREFIXES):
            continue
        for pattern, desc in patterns:
            for m in re.finditer(pattern, added, re.IGNORECASE):
                violations.append({
                    "severity": severity,
                    "pattern": pattern,
                    "description": desc,
                    "file": current_file,
                    "line_snippet": added[:160],
                    "match": m.group(0),
                })
    return violations


def render(violations: list[dict]) -> str:
    lines: list[str] = []
    by_severity: dict[str, list[dict]] = {}
    for v in violations:
        by_severity.setdefault(v["severity"], []).append(v)
    for sev in ("HARD", "SOFT"):
        bucket = by_severity.get(sev, [])
        if not bucket:
            continue
        marker = "[BLOCKED]" if sev == "HARD" else "[WARNING]"
        lines.append(f"\n{marker} {sev} matches ({len(bucket)}):")
        for v in bucket:
            lines.append(
                f"  {v['file']}: {v['match']!r}  — {v['description']}\n"
                f"    line: {v['line_snippet'].rstrip()}"
            )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan staged changes for forbidden masking terms."
    )
    parser.add_argument(
        "--mode",
        choices=("audit", "block"),
        default="audit",
        help="audit prints + exit 0; block exits 1 on any HARD match.",
    )
    parser.add_argument(
        "--block",
        action="store_const", const="block", dest="mode",
        help="shorthand for --mode block",
    )
    parser.add_argument(
        "--diff-file",
        default=None,
        help="read diff from a file instead of `git diff --cached`. Test use.",
    )
    args = parser.parse_args()

    if args.diff_file:
        with open(args.diff_file, "r", encoding="utf-8") as f:
            diff = f.read()
    else:
        diff = get_staged_diff()

    lines = diff.splitlines()
    hard = scan_lines(lines, FORBIDDEN_HARD, "HARD")
    soft = scan_lines(lines, FORBIDDEN_SOFT, "SOFT")
    violations = hard + soft

    if not violations:
        print("No forbidden terms found in staged diff.")
        return 0

    print(render(violations))

    if args.mode == "audit":
        print(
            f"\nAudit mode: found {len(hard)} HARD and {len(soft)} SOFT matches. "
            f"Hook is not blocking. Run with --block to enforce."
        )
        return 0

    # block mode
    if hard:
        print(
            f"\nCommit blocked: {len(hard)} HARD match(es). "
            f"Remove them or move work to a private branch."
        )
        return 1
    print(f"\n{len(soft)} SOFT warning(s) — proceeding (non-blocking).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
