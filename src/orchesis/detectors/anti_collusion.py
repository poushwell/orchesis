"""Anti-Collusion Mode for multi-agent coordination detection."""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from orchesis.utils.log import get_logger

logger = get_logger(__name__)


@dataclass
class AgentAction:
    agent_id: str
    action: str
    timestamp: float
    data_hash: str = ""
    input_hashes: list = field(default_factory=list)
    output_hashes: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class CollusionPair:
    agent_a: str
    agent_b: str
    signal_type: str
    confidence: float
    evidence: dict = field(default_factory=dict)
    description: str = ""


@dataclass
class CollusionResult:
    collusion_detected: bool = False
    pairs: list = field(default_factory=list)
    fleet_risk_score: float = 0.0
    recommendation: str = ""


class AntiCollusionDetector:
    def __init__(self, temporal_window_s: float = 10.0, min_actions: int = 2, correlation_threshold: float = 0.7):
        self.temporal_window_s = float(temporal_window_s)
        self.min_actions = int(min_actions)
        self.correlation_threshold = float(correlation_threshold)
        self._actions: dict[str, list[AgentAction]] = {}

    def record_action(
        self,
        agent_id,
        action,
        data_hash: str = "",
        input_hashes=None,
        output_hashes=None,
        metadata=None,
    ) -> None:
        """Record an agent action for fleet analysis."""
        aid = str(agent_id or "unknown")
        record = AgentAction(
            agent_id=aid,
            action=str(action or ""),
            timestamp=time.time(),
            data_hash=str(data_hash or ""),
            input_hashes=list(input_hashes) if input_hashes else [],
            output_hashes=list(output_hashes) if output_hashes else [],
            metadata=dict(metadata) if isinstance(metadata, dict) else {},
        )
        self._actions.setdefault(aid, []).append(record)

    def check_fleet(self) -> CollusionResult:
        """Analyze all recorded actions for collusion patterns."""
        agents = self.get_monitored_agents()
        if len(agents) < 2:
            return CollusionResult(collusion_detected=False, pairs=[], fleet_risk_score=0.0, recommendation="")

        all_pairs: list[CollusionPair] = []
        for a, b in itertools.combinations(agents, 2):
            a_actions = self.get_actions(a)
            b_actions = self.get_actions(b)
            if len(a_actions) + len(b_actions) < self.min_actions:
                continue

            temporal = self._check_temporal_correlation(a_actions, b_actions)
            if temporal:
                all_pairs.append(temporal)

            data_flow = self._check_data_flow(a_actions, b_actions)
            if data_flow:
                all_pairs.append(data_flow)

        merged_actions: list[AgentAction] = []
        for aid in agents:
            merged_actions.extend(self.get_actions(aid))
        merged_actions.sort(key=lambda a: a.timestamp)

        all_pairs.extend(self._check_role_splitting(merged_actions))
        all_pairs.extend(self._check_synchronized_anomalies())

        detected = len(all_pairs) > 0
        if not detected:
            return CollusionResult(collusion_detected=False, pairs=[], fleet_risk_score=0.0, recommendation="")

        max_conf = max(pair.confidence for pair in all_pairs)
        score = min(1.0, max_conf + 0.08 * max(0, len(all_pairs) - 1))
        recommendation = (
            "Potential agent collusion detected. Restrict cross-agent context sharing, "
            "enable stricter policy composition checks, and inspect correlated traces."
        )

        logger.warning(
            "Anti-collusion detector found suspicious coordination",
            extra={"component": "anti_collusion", "agent_count": len(agents), "signal_count": len(all_pairs)},
        )
        return CollusionResult(
            collusion_detected=True,
            pairs=all_pairs,
            fleet_risk_score=score,
            recommendation=recommendation,
        )

    def _check_temporal_correlation(
        self, agent_a_actions: list[AgentAction], agent_b_actions: list[AgentAction]
    ) -> Optional[CollusionPair]:
        """Check if two agents' actions are temporally correlated."""
        if not agent_a_actions or not agent_b_actions:
            return None

        correlated = 0
        total = len(agent_a_actions) * len(agent_b_actions)
        min_delta = None
        for a_act in agent_a_actions:
            for b_act in agent_b_actions:
                delta = abs(a_act.timestamp - b_act.timestamp)
                if delta <= self.temporal_window_s:
                    correlated += 1
                    min_delta = delta if min_delta is None else min(min_delta, delta)

        if total == 0:
            return None
        ratio = correlated / float(total)
        if ratio < self.correlation_threshold:
            return None

        if len(agent_a_actions) + len(agent_b_actions) < self.min_actions:
            return None

        confidence = min(1.0, ratio)
        return CollusionPair(
            agent_a=agent_a_actions[0].agent_id,
            agent_b=agent_b_actions[0].agent_id,
            signal_type="temporal",
            confidence=confidence,
            evidence={"correlated_pairs": correlated, "total_pairs": total, "min_delta_s": min_delta},
            description="Agents execute tightly correlated action timing.",
        )

    def _check_data_flow(self, agent_a_actions: list[AgentAction], agent_b_actions: list[AgentAction]) -> Optional[CollusionPair]:
        """Check if data flows from A to B (output hash -> input hash)."""
        if not agent_a_actions or not agent_b_actions:
            return None

        matches = 0
        hashes: set[str] = set()
        for a_act in agent_a_actions:
            a_outputs = {h for h in a_act.output_hashes if h}
            if a_act.data_hash:
                a_outputs.add(a_act.data_hash)
            if not a_outputs:
                continue

            for b_act in agent_b_actions:
                delta = b_act.timestamp - a_act.timestamp
                if delta < 0 or delta > self.temporal_window_s:
                    continue
                b_inputs = {h for h in b_act.input_hashes if h}
                if b_act.data_hash:
                    b_inputs.add(b_act.data_hash)
                common = a_outputs.intersection(b_inputs)
                if common:
                    matches += 1
                    hashes.update(common)

        if matches == 0:
            return None

        confidence = min(1.0, 0.65 + 0.1 * matches)
        return CollusionPair(
            agent_a=agent_a_actions[0].agent_id,
            agent_b=agent_b_actions[0].agent_id,
            signal_type="data_flow",
            confidence=confidence,
            evidence={"matched_hashes": sorted(hashes), "match_count": matches},
            description="Data output from one agent appears in another agent input.",
        )

    def _check_role_splitting(self, all_actions: list[AgentAction]) -> list[CollusionPair]:
        """Check if combined actions form dangerous chains."""
        if len(all_actions) < 2:
            return []
        try:
            from orchesis.risk.compositional import KNOWN_DANGEROUS_CHAINS
        except Exception as exc:
            logger.debug("Skipping role splitting check: %s", exc, extra={"component": "anti_collusion"})
            return []

        pairs: list[CollusionPair] = []
        action_names = [a.action for a in all_actions]
        for chain in KNOWN_DANGEROUS_CHAINS:
            pattern = list(chain.pattern)
            plen = len(pattern)
            if plen < 2 or len(action_names) < plen:
                continue

            for idx in range(len(action_names) - plen + 1):
                window = all_actions[idx : idx + plen]
                if [w.action for w in window] != pattern:
                    continue
                agents = [w.agent_id for w in window if w.agent_id]
                unique_agents = sorted(set(agents))
                if len(unique_agents) < 2:
                    continue

                for agent_a, agent_b in itertools.combinations(unique_agents, 2):
                    pairs.append(
                        CollusionPair(
                            agent_a=agent_a,
                            agent_b=agent_b,
                            signal_type="role_split",
                            confidence=0.85 if getattr(chain, "severity", "") == "HIGH" else 0.72,
                            evidence={
                                "chain_id": getattr(chain, "chain_id", ""),
                                "pattern": pattern,
                                "category": getattr(chain, "category", ""),
                            },
                            description=f"Agents split dangerous chain {getattr(chain, 'chain_id', 'unknown')}.",
                        )
                    )

        return pairs

    def _check_synchronized_anomalies(self) -> list[CollusionPair]:
        """Check for synchronized behavioral changes."""
        agents = self.get_monitored_agents()
        if len(agents) < 3:
            return []

        actions: list[AgentAction] = []
        for aid in agents:
            actions.extend(self.get_actions(aid))
        actions.sort(key=lambda x: x.timestamp)
        if not actions:
            return []

        burst_window = min(5.0, self.temporal_window_s)
        involved_agents: set[str] = set()
        for idx, start in enumerate(actions):
            current_agents = {start.agent_id}
            for follow in actions[idx + 1 :]:
                if (follow.timestamp - start.timestamp) > burst_window:
                    break
                current_agents.add(follow.agent_id)
            if len(current_agents) >= 3:
                involved_agents = current_agents
                break

        if len(involved_agents) < 3:
            return []

        pairs: list[CollusionPair] = []
        agents_sorted = sorted(involved_agents)
        confidence = min(1.0, 0.7 + (len(agents_sorted) - 3) * 0.05)
        for agent_a, agent_b in itertools.combinations(agents_sorted, 2):
            pairs.append(
                CollusionPair(
                    agent_a=agent_a,
                    agent_b=agent_b,
                    signal_type="sync_anomaly",
                    confidence=confidence,
                    evidence={"agent_count": len(agents_sorted), "window_s": burst_window},
                    description="Multiple agents show synchronized activity burst.",
                )
            )
        return pairs

    def clear(self, agent_id=None):
        if agent_id is None:
            self._actions.clear()
            return
        self._actions.pop(str(agent_id), None)

    def get_actions(self, agent_id) -> list[AgentAction]:
        return list(self._actions.get(str(agent_id), []))

    def get_monitored_agents(self) -> list[str]:
        return sorted(self._actions.keys())

