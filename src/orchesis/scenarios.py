"""Adversarial scenario runner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from orchesis.engine import evaluate
from orchesis.fuzzer import FuzzResult
from orchesis.state import RateLimitTracker


@dataclass
class ScenarioResult:
    name: str
    description: str
    steps_total: int
    steps_allowed: int
    steps_denied: int
    bypasses: list[FuzzResult] = field(default_factory=list)
    success: bool = True


class AdversarialScenarios:
    """Pre-built attack scenarios modeling real threats."""

    def __init__(self, policy: dict[str, Any], registry=None):
        self._policy = policy
        self._registry = registry

    def run_all(self) -> list[ScenarioResult]:
        """Run all scenarios."""
        return [
            self.escalation_attack(),
            self.budget_drainer(),
            self.identity_rotation(),
            self.session_hopping(),
            self.slow_probe(),
            self.mixed_legitimate_malicious(),
        ]

    def _run_step(
        self,
        request: dict[str, Any],
        *,
        expected_deny: bool,
        category: str,
        mutation: str,
        tracker: RateLimitTracker,
    ) -> FuzzResult:
        decision = evaluate(request, self._policy, state=tracker, registry=self._registry)
        return FuzzResult(
            request=request,
            decision_allowed=decision.allowed,
            decision_reasons=list(decision.reasons),
            expected_deny=expected_deny,
            is_bypass=expected_deny and decision.allowed,
            category=category,
            mutation=mutation,
        )

    def _build_result(self, name: str, description: str, steps: list[FuzzResult], success: bool) -> ScenarioResult:
        allowed = sum(1 for step in steps if step.decision_allowed)
        denied = len(steps) - allowed
        bypasses = [step for step in steps if step.is_bypass]
        return ScenarioResult(
            name=name,
            description=description,
            steps_total=len(steps),
            steps_allowed=allowed,
            steps_denied=denied,
            bypasses=bypasses,
            success=success and len(bypasses) == 0,
        )

    def escalation_attack(self) -> ScenarioResult:
        """Gradual privilege escalation simulation."""
        tracker = RateLimitTracker(persist_path=None)
        steps: list[tuple[dict[str, Any], bool, str]] = [
            ({"tool": "read_file", "params": {"path": "/data/safe.txt"}, "cost": 0.1, "context": {"agent": "untrusted_bot"}}, False, "read_safe"),
            ({"tool": "read_file", "params": {"path": "/data/config.yaml"}, "cost": 0.1, "context": {"agent": "untrusted_bot"}}, False, "read_config"),
            ({"tool": "read_file", "params": {"path": "/etc/hostname"}, "cost": 0.1, "context": {"agent": "untrusted_bot"}}, True, "read_etc"),
            ({"tool": "write_file", "params": {"path": "/data/test.txt", "content": "x"}, "cost": 0.1, "context": {"agent": "untrusted_bot"}}, True, "write_attempt"),
            ({"tool": "delete_file", "params": {"path": "/data/test.txt"}, "cost": 0.1, "context": {"agent": "untrusted_bot"}}, True, "delete_attempt"),
            ({"tool": "read_file", "params": {"path": "/root/.ssh/id_rsa"}, "cost": 0.1, "context": {"agent": "untrusted_bot"}}, True, "read_root"),
            ({"tool": "run_sql", "params": {"query": "DROP TABLE users"}, "cost": 0.1, "context": {"agent": "untrusted_bot"}}, True, "sql_drop"),
        ]
        results = [
            self._run_step(
                request,
                expected_deny=expected_deny,
                category="escalation_attack",
                mutation=mutation,
                tracker=tracker,
            )
            for request, expected_deny, mutation in steps
        ]
        return self._build_result("escalation_attack", "Progressive escalation probe", results, success=True)

    def budget_drainer(self) -> ScenarioResult:
        """Repeated near-limit calls that should hit daily budget."""
        tracker = RateLimitTracker(persist_path=None)
        max_cost = 2.0
        daily_budget = 100.0
        rules = self._policy.get("rules")
        if isinstance(rules, list):
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                if isinstance(rule.get("max_cost_per_call"), int | float):
                    max_cost = min(max_cost, float(rule["max_cost_per_call"]))
                if isinstance(rule.get("daily_budget"), int | float):
                    daily_budget = min(daily_budget, float(rule["daily_budget"]))
        call_cost = max(0.01, max_cost - 0.01)
        running_spend = 0.0
        results: list[FuzzResult] = []
        for idx in range(80):
            expected_deny = (running_spend + call_cost) > daily_budget
            request = {
                "tool": "api_call",
                "params": {"endpoint": "model"},
                "cost": call_cost,
                "context": {"agent": "budget_bot"},
            }
            result = self._run_step(
                request,
                expected_deny=expected_deny,
                category="budget_drainer",
                mutation=f"drain_{idx}",
                tracker=tracker,
            )
            if result.decision_allowed:
                running_spend += call_cost
            results.append(result)
        saw_denial = any(not item.decision_allowed for item in results)
        return self._build_result(
            "budget_drainer",
            "Gradual daily budget drain",
            results,
            success=saw_denial,
        )

    def identity_rotation(self) -> ScenarioResult:
        """Rotate identity every request (known attribution limitation)."""
        tracker = RateLimitTracker(persist_path=None)
        results: list[FuzzResult] = []
        for idx in range(10):
            request = {
                "tool": "read_file",
                "params": {"path": "/data/safe.txt"},
                "cost": 0.1,
                "context": {"agent": f"bot_{idx+1}"},
            }
            results.append(
                self._run_step(
                    request,
                    expected_deny=False,
                    category="identity_rotation",
                    mutation=f"agent_rotated_{idx+1}",
                    tracker=tracker,
                )
            )
        # Documented limitation: rotating identifiers weakens per-agent controls.
        return self._build_result(
            "identity_rotation",
            "Known limitation: rotating agent_id can evade per-agent attribution",
            results,
            success=False,
        )

    def session_hopping(self) -> ScenarioResult:
        """Same agent rotates sessions."""
        tracker = RateLimitTracker(persist_path=None)
        results: list[FuzzResult] = []
        for idx in range(20):
            request = {
                "tool": "read_file",
                "params": {"path": "/data/safe.txt"},
                "cost": 0.1,
                "context": {"agent": "hopper", "session": f"s{idx+1}"},
            }
            results.append(
                self._run_step(
                    request,
                    expected_deny=False,
                    category="session_hopping",
                    mutation=f"session_{idx+1}",
                    tracker=tracker,
                )
            )
        return self._build_result("session_hopping", "Session hopping probe", results, success=True)

    def slow_probe(self) -> ScenarioResult:
        """Slow denied probes across sensitive paths."""
        tracker = RateLimitTracker(persist_path=None)
        paths = ["/etc/passwd", "/root/.ssh/id_rsa", "/var/secrets/token.txt"]
        results: list[FuzzResult] = []
        for idx in range(30):
            request = {
                "tool": "read_file",
                "params": {"path": paths[idx % len(paths)]},
                "cost": 0.1,
                "context": {"agent": "slow_probe_bot"},
            }
            results.append(
                self._run_step(
                    request,
                    expected_deny=True,
                    category="slow_probe",
                    mutation=f"probe_{idx+1}",
                    tracker=tracker,
                )
            )
        return self._build_result("slow_probe", "Slow denied probing", results, success=True)

    def mixed_legitimate_malicious(self) -> ScenarioResult:
        """80% legitimate + 20% malicious mixed traffic."""
        tracker = RateLimitTracker(persist_path=None)
        results: list[FuzzResult] = []
        for idx in range(100):
            if idx % 5 == 0:
                request = {
                    "tool": "read_file",
                    "params": {"path": "/etc/passwd"},
                    "cost": 0.1,
                    "context": {"agent": "mixed_bot", "session": f"mix-{idx}"},
                }
                expected_deny = True
                mutation = f"malicious_{idx}"
            else:
                request = {
                    "tool": "read_file",
                    "params": {"path": "/data/safe.txt"},
                    "cost": 0.1,
                    "context": {"agent": "mixed_bot", "session": f"mix-{idx}"},
                }
                expected_deny = False
                mutation = f"legitimate_{idx}"
            results.append(
                self._run_step(
                    request,
                    expected_deny=expected_deny,
                    category="mixed_legitimate_malicious",
                    mutation=mutation,
                    tracker=tracker,
                )
            )
        return self._build_result(
            "mixed_legitimate_malicious",
            "Legitimate and malicious traffic blend",
            results,
            success=True,
        )
