"""Lightweight vibe code auditor used by API and CLI tests."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


class VibeCodeAuditor:
    AI_SPECIFIC_CHECKS = {
        "llm_prompt_in_code": "LLM prompt assembled directly in code",
        "no_output_validation": "LLM output used without validation",
        "infinite_retry_loop": "Infinite retry loop around model calls",
        "token_count_ignored": "Token budget not checked",
        "hallucination_unchecked": "No hallucination guard detected",
        "agent_trust_escalation": "Agent trust escalation pattern detected",
    }

    _SEVERITY_PENALTY = {
        "info": 0,
        "low": 5,
        "medium": 10,
        "high": 15,
        "critical": 25,
    }

    def __init__(self, config: dict[str, Any] | None = None):
        cfg = config or {}
        self.severity_threshold = str(cfg.get("severity_threshold", "low")).lower()

    def _severity_rank(self, severity: str) -> int:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return order.get(str(severity).lower(), 0)

    def _include(self, severity: str) -> bool:
        return self._severity_rank(severity) >= self._severity_rank(self.severity_threshold)

    def _grade_for_score(self, score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    def compute_score_v2(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        penalty = sum(
            self._SEVERITY_PENALTY.get(str(item.get("severity", "low")).lower(), 5)
            for item in findings
        )
        score = max(0, 100 - penalty)
        return {"penalty": penalty, "score": score, "grade": self._grade_for_score(float(score))}

    def _build_finding(self, check: str, severity: str, detail: str) -> dict[str, Any]:
        return {"check": check, "severity": severity, "detail": detail}

    def audit_code(self, code: str, language: str = "python") -> dict[str, Any]:
        text = str(code or "")
        findings: list[dict[str, Any]] = []

        if re.search(r"(API_KEY|SECRET|TOKEN)\s*=\s*['\"]", text, re.IGNORECASE):
            findings.append(
                self._build_finding("hardcoded_secrets", "critical", "Hardcoded secret-like value found")
            )
        if re.search(r"SELECT .*WHERE .*{", text, re.IGNORECASE | re.DOTALL):
            findings.append(
                self._build_finding("sql_injection", "critical", "String-interpolated SQL detected")
            )
        if re.search(r"subprocess\.(run|Popen)\(.*shell\s*=\s*True", text, re.DOTALL):
            findings.append(
                self._build_finding("command_injection", "high", "Shell execution with dynamic input")
            )
        if re.search(r"(system:|assistant:|user:)\s*\{?user_input\}?", text, re.IGNORECASE):
            findings.append(
                self._build_finding("llm_prompt_in_code", "medium", "Prompt assembled from raw user input")
            )
        if "client.responses.create" in text and not re.search(
            r"validate|schema|jsonschema|pydantic", text, re.IGNORECASE
        ):
            findings.append(
                self._build_finding("no_output_validation", "high", "Model output lacks validation")
            )
        if re.search(r"while\s+True:.*client\.responses\.create", text, re.DOTALL):
            findings.append(
                self._build_finding("infinite_retry_loop", "high", "Potential infinite retry loop")
            )
        if "client.responses.create" in text and not re.search(
            r"max_tokens|token|context_window", text, re.IGNORECASE
        ):
            findings.append(
                self._build_finding("token_count_ignored", "low", "No token budget handling detected")
            )
        if "client.responses.create" in text and not re.search(
            r"verify|validate|ground|check", text, re.IGNORECASE
        ):
            findings.append(
                self._build_finding("hallucination_unchecked", "low", "No hallucination validation detected")
            )
        if re.search(r"trust_tier\s*=\s*['\"]?(admin|root)|bypass approval|auto-approve", text, re.IGNORECASE):
            findings.append(
                self._build_finding("agent_trust_escalation", "high", "Trust escalation pattern detected")
            )

        filtered = [item for item in findings if self._include(str(item.get("severity", "low")))]
        scored = self.compute_score_v2(filtered)
        return {
            "language": language,
            "findings": filtered,
            "score": float(scored["score"]),
            "grade": scored["grade"],
            "critical_count": sum(1 for item in filtered if item["severity"] == "critical"),
            "high_count": sum(1 for item in filtered if item["severity"] == "high"),
            "summary": "No major issues detected" if not filtered else f"{len(filtered)} finding(s) detected",
        }

    def audit_file(self, file_path: str) -> dict[str, Any]:
        path = Path(file_path)
        report = self.audit_code(
            path.read_text(encoding="utf-8", errors="replace"),
            language=path.suffix.lstrip(".") or "text",
        )
        report["file_path"] = str(path)
        return report

    def audit_directory(self, dir_path: str, extensions: list[str] | None = None) -> dict[str, Any]:
        ext_set = {f".{item.lstrip('.').lower()}" for item in extensions} if extensions else {".py", ".js", ".ts"}
        root = Path(dir_path)
        reports: list[dict[str, Any]] = []
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in ext_set:
                reports.append(self.audit_file(str(path)))
        avg_score = round(
            sum(float(item.get("score", 0)) for item in reports) / len(reports),
            2,
        ) if reports else 100.0
        return {
            "files_scanned": len(reports),
            "total_findings": sum(len(item.get("findings", [])) for item in reports),
            "avg_score": avg_score,
            "reports": reports,
        }

    def audit_directory_summary(self, dir_path: str, extensions: list[str] | None = None) -> dict[str, Any]:
        directory_report = self.audit_directory(dir_path, extensions=extensions)
        reports = list(directory_report.get("reports", []))
        worst_files = sorted(
            (
                {
                    "file_path": item.get("file_path", ""),
                    "score": item.get("score", 0),
                    "grade": item.get("grade", "A"),
                }
                for item in reports
            ),
            key=lambda item: (float(item["score"]), str(item["file_path"])),
        )[:5]
        avg_score = float(directory_report.get("avg_score", 100.0))
        return {
            "files_audited": int(directory_report.get("files_scanned", 0)),
            "avg_score": avg_score,
            "grade": self._grade_for_score(avg_score),
            "critical_files": sum(1 for item in reports if int(item.get("critical_count", 0)) > 0),
            "total_findings": int(directory_report.get("total_findings", 0)),
            "worst_files": worst_files,
        }

    def get_fix_suggestion(self, finding: dict[str, Any]) -> str:
        check = str(finding.get("check", ""))
        suggestions = {
            "sql_injection": "Use parameterized queries instead of string interpolation.",
            "command_injection": "Avoid shell=True and pass arguments as a list.",
            "hardcoded_secrets": "Move secrets to environment variables or a vault.",
            "no_output_validation": "Validate model responses with a schema before use.",
        }
        return suggestions.get(check, "Review and harden the affected code path.")

    def format_badge_text(self, report: dict[str, Any]) -> str:
        score = float(report.get("score", 0))
        grade = str(report.get("grade", "D"))
        return f"Vibe Code Audit: {score:.0f}/100 ({grade})"
