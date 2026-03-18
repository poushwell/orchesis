"""Vibe Code Audit MVP."""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any


class VibeCodeAuditor:
    """Audit AI-generated code for security and quality issues.

    Reuses 60-70% of Orchesis engine - same detection pipeline
    applied to code instead of LLM requests.
    """

    AUDIT_CHECKS = {
        "hardcoded_secrets": "Credentials, API keys in code",
        "sql_injection": "Unparameterized SQL queries",
        "command_injection": "Shell command construction from input",
        "path_traversal": "Unsafe file path construction",
        "insecure_random": "Math.random() for security purposes",
        "no_input_validation": "Functions accepting raw user input",
        "dependency_confusion": "Suspicious package names",
        "prompt_injection_in_code": "LLM prompts built from user input",
        "missing_error_handling": "Bare except/catch blocks",
        "debug_code_left": "print/console.log/debugger in production",
    }

    _SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    _GRADE_BANDS = [
        (97.0, "A+"),
        (90.0, "A"),
        (84.0, "B+"),
        (76.0, "B"),
        (60.0, "C"),
        (0.0, "D"),
    ]

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        level = str(cfg.get("severity_threshold", "low") or "low").strip().lower()
        self.severity_threshold = level if level in self._SEVERITY_ORDER else "low"

    def _passes_threshold(self, severity: str) -> bool:
        return self._SEVERITY_ORDER.get(severity, 1) >= self._SEVERITY_ORDER[self.severity_threshold]

    @staticmethod
    def _line_finding(check: str, severity: str, line: int, snippet: str, fix: str) -> dict[str, Any]:
        return {
            "check": check,
            "severity": severity,
            "line": int(line),
            "snippet": snippet[:200],
            "fix": fix,
        }

    @staticmethod
    def _score(findings: list[dict[str, Any]]) -> float:
        penalties = {"critical": 25.0, "high": 12.0, "medium": 6.0, "low": 2.0}
        score = 100.0
        for finding in findings:
            sev = str(finding.get("severity", "low")).lower()
            score -= penalties.get(sev, 2.0)
        return max(0.0, round(score, 3))

    @classmethod
    def _grade_for(cls, score: float) -> str:
        value = float(score)
        for threshold, grade in cls._GRADE_BANDS:
            if value >= threshold:
                return grade
        return "D"

    @staticmethod
    def _iter_lines(code: str) -> list[tuple[int, str]]:
        return [(idx, line) for idx, line in enumerate(str(code or "").splitlines(), start=1)]

    def get_fix_suggestion(self, finding: dict) -> str:
        """Get remediation for a finding."""
        check = str((finding or {}).get("check", "")).strip()
        suggestions = {
            "hardcoded_secrets": "Move secrets to environment variables or a vault provider.",
            "sql_injection": "Use parameterized queries instead of string interpolation.",
            "command_injection": "Avoid shell=True and pass argv list with strict allow-lists.",
            "path_traversal": "Normalize/validate paths and block '..' segments.",
            "insecure_random": "Use a cryptographic RNG for security-sensitive logic.",
            "no_input_validation": "Validate and sanitize user input at API boundaries.",
            "dependency_confusion": "Pin trusted package names and exact versions.",
            "prompt_injection_in_code": "Sanitize user text before embedding in prompts.",
            "missing_error_handling": "Catch specific exceptions and log structured details.",
            "debug_code_left": "Remove debug statements from production code paths.",
        }
        return suggestions.get(check, "Review and refactor this section with secure coding practices.")

    def audit_code(self, code: str, language: str = "python") -> dict:
        findings: list[dict[str, Any]] = []
        lines = self._iter_lines(code)

        secret_re = re.compile(r"(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{6,}['\"]", re.IGNORECASE)
        sql_re = re.compile(r"(select|insert|update|delete).*(\+|%)", re.IGNORECASE)
        sql_fstring_re = re.compile(r"f[\"'][^\"']*(select|insert|update|delete)[^\"']*\{[^}]+\}", re.IGNORECASE)
        cmd_re = re.compile(r"(subprocess\.(run|Popen)|os\.system).*(input|user|request|\+)", re.IGNORECASE)
        path_re = re.compile(r"(\.\./|os\.path\.join\([^)]*(input|user|request))", re.IGNORECASE)
        random_re = re.compile(r"(Math\.random\(|random\.random\()", re.IGNORECASE)
        llm_prompt_re = re.compile(r"(prompt|messages?).*(input|user|request).*(\+|f['\"])", re.IGNORECASE)
        debug_re = re.compile(r"(\bprint\(|console\.log\(|\bdebugger\b)", re.IGNORECASE)

        for line_no, line in lines:
            stripped = line.strip()
            if secret_re.search(line):
                findings.append(
                    self._line_finding(
                        "hardcoded_secrets",
                        "critical",
                        line_no,
                        stripped,
                        "Use env/vault secret injection.",
                    )
                )
            if sql_re.search(line) or sql_fstring_re.search(line):
                findings.append(
                    self._line_finding(
                        "sql_injection",
                        "high",
                        line_no,
                        stripped,
                        "Replace with parameterized SQL.",
                    )
                )
            if cmd_re.search(line):
                findings.append(
                    self._line_finding(
                        "command_injection",
                        "critical",
                        line_no,
                        stripped,
                        "Avoid shell command concatenation with user input.",
                    )
                )
            if path_re.search(line):
                findings.append(
                    self._line_finding(
                        "path_traversal",
                        "high",
                        line_no,
                        stripped,
                        "Normalize and validate path segments.",
                    )
                )
            if random_re.search(line) and ("security" in code.lower() or "token" in code.lower()):
                findings.append(
                    self._line_finding(
                        "insecure_random",
                        "medium",
                        line_no,
                        stripped,
                        "Use cryptographically secure randomness.",
                    )
                )
            if llm_prompt_re.search(line):
                findings.append(
                    self._line_finding(
                        "prompt_injection_in_code",
                        "medium",
                        line_no,
                        stripped,
                        "Avoid direct user input interpolation in prompts.",
                    )
                )
            if debug_re.search(line):
                findings.append(
                    self._line_finding(
                        "debug_code_left",
                        "low",
                        line_no,
                        stripped,
                        "Remove debug statements from production.",
                    )
                )
            if re.search(r"except\s*:\s*$|catch\s*\(\s*\)\s*\{?", stripped):
                findings.append(
                    self._line_finding(
                        "missing_error_handling",
                        "medium",
                        line_no,
                        stripped,
                        "Catch specific exceptions and add handling.",
                    )
                )

        # Heuristic for missing input validation.
        if "input(" in code or "request." in code or "req." in code:
            if not re.search(r"(validate|sanitize|schema|pydantic|marshmallow|zod|joi)", code, re.IGNORECASE):
                findings.append(
                    self._line_finding(
                        "no_input_validation",
                        "medium",
                        1,
                        "raw user input detected",
                        "Add explicit input validation.",
                    )
                )

        # Heuristic for dependency confusion references.
        if re.search(r"(pip install|npm install)\s+[\w\-]+", code, re.IGNORECASE):
            if not re.search(r"(==|@|--index-url|--extra-index-url)", code):
                findings.append(
                    self._line_finding(
                        "dependency_confusion",
                        "low",
                        1,
                        "un-pinned dependency install command",
                        "Pin exact dependency versions and trusted index.",
                    )
                )

        filtered = [item for item in findings if self._passes_threshold(str(item.get("severity", "low")))]
        for finding in filtered:
            finding["fix"] = self.get_fix_suggestion(finding)
        score = self._score(filtered)
        grade = self._grade_for(score)
        critical_count = sum(1 for item in filtered if str(item.get("severity", "")) == "critical")
        high_count = sum(1 for item in filtered if str(item.get("severity", "")) == "high")
        summary = (
            "No major issues detected."
            if not filtered
            else f"Detected {len(filtered)} findings ({critical_count} critical, {high_count} high)."
        )
        return {
            "audit_id": str(uuid.uuid4()),
            "language": str(language or "python"),
            "lines": len(lines),
            "findings": filtered,
            "score": score,
            "grade": grade,
            "summary": summary,
            "critical_count": critical_count,
            "high_count": high_count,
        }

    def audit_file(self, file_path: str) -> dict:
        """Audit a single file."""
        path = Path(file_path)
        code = path.read_text(encoding="utf-8")
        ext = path.suffix.lower().lstrip(".")
        lang = ext if ext else "python"
        report = self.audit_code(code, language=lang)
        report["file_path"] = str(path)
        return report

    def audit_directory(self, dir_path: str, extensions: list[str] | None = None) -> dict:
        """Audit all code files in directory."""
        root = Path(dir_path)
        ext_allow = (
            {f".{ext.strip().lower().lstrip('.')}" for ext in extensions if str(ext).strip()}
            if isinstance(extensions, list) and extensions
            else {".py", ".js", ".ts", ".tsx", ".java", ".go", ".rs"}
        )
        files = [path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in ext_allow]
        reports: list[dict[str, Any]] = []
        total_findings = 0
        for file_path in files:
            report = self.audit_file(str(file_path))
            reports.append(report)
            total_findings += len(report.get("findings", []))
        avg_score = (
            sum(float(item.get("score", 0.0) or 0.0) for item in reports) / float(len(reports))
            if reports
            else 100.0
        )
        return {
            "directory": str(root),
            "files_scanned": len(files),
            "reports": reports,
            "total_findings": int(total_findings),
            "avg_score": round(avg_score, 3),
        }
