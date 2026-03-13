"""Structural pattern analysis for AI agent traffic."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
import threading
import time
from typing import Optional

from orchesis.input_guard import sanitize_text


@dataclass
class StructuralSignature:
    """Signature of a single request's structure."""

    role_sequence: tuple[str, ...]
    tool_sequence: tuple[str, ...]
    message_count: int
    has_system_prompt: bool
    has_tool_calls: bool
    has_tool_results: bool
    model: str
    estimated_tokens: int


@dataclass
class PatternMatch:
    """A detected structural pattern."""

    pattern_type: str
    confidence: float
    occurrences: int
    window: int
    description: str
    evidence: list[StructuralSignature] = field(default_factory=list)


class StructuralPatternDetector:
    """Detects recurring structural patterns in agent request sequences."""

    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        self.history_size = max(1, int(cfg.get("history_size", 100)))
        self.min_pattern_length = max(1, int(cfg.get("min_pattern_length", 2)))
        self.max_pattern_length = max(self.min_pattern_length, int(cfg.get("max_pattern_length", 10)))
        self.min_occurrences = max(2, int(cfg.get("min_occurrences", 3)))
        self.similarity_threshold = min(1.0, max(0.1, float(cfg.get("similarity_threshold", 0.8))))
        self._histories: dict[str, deque[StructuralSignature]] = {}
        self._lock = threading.Lock()

    def extract_signature(self, request_data: dict) -> StructuralSignature:
        messages = request_data.get("messages")
        if not isinstance(messages, list):
            messages = []
        model = str(request_data.get("model", "") or "")
        roles: list[str] = []
        tools: list[str] = []
        total_tokens = 0
        has_system = False
        has_tool_calls = False
        has_tool_results = False

        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "") or "").strip().lower()
            if role:
                roles.append(role)
            if role == "system":
                has_system = True
            if role == "tool":
                has_tool_results = True

            safe_content = sanitize_text(msg.get("content", ""))
            content = safe_content if safe_content is not None else ""
            total_tokens += max(1, len(content.split())) if content else 0

            calls = msg.get("tool_calls")
            if isinstance(calls, list) and calls:
                has_tool_calls = True
                for call in calls:
                    if isinstance(call, dict):
                        name = (
                            call.get("name")
                            or (call.get("function") or {}).get("name")
                            or call.get("tool_name")
                            or ""
                        )
                        safe_name = sanitize_text(name)
                        n = (safe_name or "").strip().lower()
                        if n:
                            tools.append(n)

        request_tools = request_data.get("tools")
        if isinstance(request_tools, list):
            for item in request_tools:
                safe_item = sanitize_text(item)
                n = (safe_item or "").strip().lower()
                if n:
                    tools.append(n)
                    has_tool_calls = True

        return StructuralSignature(
            role_sequence=tuple(roles),
            tool_sequence=tuple(tools),
            message_count=len(messages),
            has_system_prompt=has_system,
            has_tool_calls=has_tool_calls,
            has_tool_results=has_tool_results,
            model=model,
            estimated_tokens=max(0, int(request_data.get("tokens", 0) or total_tokens)),
        )

    def record(self, agent_id: str, signature: StructuralSignature) -> None:
        key = str(agent_id or "unknown")
        with self._lock:
            history = self._histories.get(key)
            if history is None:
                history = deque(maxlen=self.history_size)
                self._histories[key] = history
            history.append(signature)

    def detect_patterns(self, agent_id: str) -> list[PatternMatch]:
        key = str(agent_id or "unknown")
        with self._lock:
            history = list(self._histories.get(key, deque()))
        if len(history) < self.min_pattern_length:
            return []
        patterns: list[PatternMatch] = []
        patterns.extend(self.detect_tool_chain_loops(history))
        patterns.extend(self.detect_role_cycles(history))
        patterns.extend(self.detect_request_templates(history))
        patterns.extend(self.detect_escalation_chains(history))
        patterns.extend(self.detect_ping_pong(history))
        # Deduplicate by pattern type + description.
        seen: set[tuple[str, str]] = set()
        result: list[PatternMatch] = []
        for p in patterns:
            key_t = (p.pattern_type, p.description)
            if key_t in seen:
                continue
            seen.add(key_t)
            result.append(p)
        return result

    def detect_tool_chain_loops(self, history: list[StructuralSignature]) -> list[PatternMatch]:
        tool_seq = [sig.tool_sequence for sig in history if sig.tool_sequence]
        if len(tool_seq) < self.min_occurrences:
            return []
        matches: list[PatternMatch] = []
        n = len(tool_seq)
        max_len = min(self.max_pattern_length, n)
        for pattern_len in range(self.min_pattern_length, max_len + 1):
            counts: dict[tuple[tuple[str, ...], ...], list[int]] = {}
            for i in range(0, n - pattern_len + 1):
                window = tuple(tool_seq[i : i + pattern_len])
                counts.setdefault(window, []).append(i)
            for window, indices in counts.items():
                if len(indices) >= self.min_occurrences:
                    evidence = []
                    for idx in indices[: self.min_occurrences]:
                        evidence.extend(history[idx : idx + pattern_len])
                    conf = min(1.0, len(indices) / float(self.min_occurrences + 1))
                    matches.append(
                        PatternMatch(
                            pattern_type="tool_chain_loop",
                            confidence=round(conf, 3),
                            occurrences=len(indices),
                            window=n,
                            description=f"Repeating tool chain length={pattern_len}",
                            evidence=evidence[:20],
                        )
                    )
                    return matches
        return matches

    def detect_role_cycles(self, history: list[StructuralSignature]) -> list[PatternMatch]:
        roles = [sig.role_sequence for sig in history if sig.role_sequence]
        if len(roles) < self.min_occurrences:
            return []
        counter = Counter(roles)
        cycle = [(seq, count) for seq, count in counter.items() if count >= self.min_occurrences]
        if not cycle:
            return []
        seq, count = max(cycle, key=lambda x: x[1])
        evidence = [sig for sig in history if sig.role_sequence == seq][:20]
        return [
            PatternMatch(
                pattern_type="role_cycle",
                confidence=min(1.0, count / float(self.min_occurrences + 1)),
                occurrences=count,
                window=len(history),
                description=f"Repeating role sequence: {'-'.join(seq)}",
                evidence=evidence,
            )
        ]

    def detect_request_templates(self, history: list[StructuralSignature]) -> list[PatternMatch]:
        templates: dict[tuple, list[StructuralSignature]] = {}
        for sig in history:
            key = (
                sig.message_count,
                sig.role_sequence,
                sig.tool_sequence,
                sig.has_system_prompt,
                sig.has_tool_calls,
                sig.has_tool_results,
                sig.model,
            )
            templates.setdefault(key, []).append(sig)
        hits = [(k, v) for k, v in templates.items() if len(v) >= self.min_occurrences]
        if not hits:
            return []
        _, sigs = max(hits, key=lambda item: len(item[1]))
        occ = len(sigs)
        return [
            PatternMatch(
                pattern_type="request_template",
                confidence=min(1.0, occ / float(self.min_occurrences + 2)),
                occurrences=occ,
                window=len(history),
                description="Repeated structurally identical requests",
                evidence=sigs[:20],
            )
        ]

    def detect_escalation_chains(self, history: list[StructuralSignature]) -> list[PatternMatch]:
        if len(history) < 5:
            return []
        best_match: Optional[PatternMatch] = None
        for i in range(0, len(history) - 4):
            window = history[i : i + 5]
            token_increases = sum(
                1 for j in range(4) if window[j + 1].estimated_tokens > window[j].estimated_tokens
            )
            msg_increases = sum(
                1 for j in range(4) if window[j + 1].message_count > window[j].message_count
            )
            ratio = max(token_increases / 4.0, msg_increases / 4.0)
            # With 5-request windows we have 4 adjacent comparisons; allow one dip (~75%).
            if ratio >= 0.75:
                match = PatternMatch(
                    pattern_type="escalation_chain",
                    confidence=round(min(1.0, ratio), 3),
                    occurrences=5,
                    window=5,
                    description="Progressively growing request complexity",
                    evidence=window,
                )
                if best_match is None or match.confidence > best_match.confidence:
                    best_match = match
        return [best_match] if best_match is not None else []

    def detect_ping_pong(self, history: list[StructuralSignature]) -> list[PatternMatch]:
        seq = [sig.tool_sequence for sig in history if sig.tool_sequence]
        if len(seq) < max(6, self.min_occurrences * 2):
            return []
        # Look at tail to find clear alternation.
        tail = seq[-max(6, self.min_occurrences * 2) :]
        distinct = list(dict.fromkeys(tail))
        if len(distinct) != 2:
            return []
        a, b = distinct[0], distinct[1]
        ok = True
        for idx, item in enumerate(tail):
            expected = a if idx % 2 == 0 else b
            if item != expected:
                ok = False
                break
        if not ok:
            return []
        return [
            PatternMatch(
                pattern_type="ping_pong",
                confidence=0.95,
                occurrences=len(tail),
                window=len(tail),
                description="Alternating between two tool patterns",
                evidence=history[-len(tail) :],
            )
        ]

    def structural_similarity(self, sig_a: StructuralSignature, sig_b: StructuralSignature) -> float:
        def jaccard_tuple(a: tuple[str, ...], b: tuple[str, ...]) -> float:
            sa = set(a)
            sb = set(b)
            if not sa and not sb:
                return 1.0
            union = sa | sb
            if not union:
                return 1.0
            return len(sa & sb) / float(len(union))

        role_match = jaccard_tuple(sig_a.role_sequence, sig_b.role_sequence)
        if sig_a.tool_sequence == sig_b.tool_sequence:
            tool_match = 1.0
        else:
            tool_match = jaccard_tuple(sig_a.tool_sequence, sig_b.tool_sequence)

        def rel_close(a: int, b: int) -> float:
            aa = max(0, int(a))
            bb = max(0, int(b))
            den = max(aa, bb, 1)
            return max(0.0, 1.0 - abs(aa - bb) / float(den))

        msg_sim = rel_close(sig_a.message_count, sig_b.message_count)
        model_sim = 1.0 if sig_a.model == sig_b.model else 0.0
        token_sim = rel_close(sig_a.estimated_tokens, sig_b.estimated_tokens)

        score = (
            (0.3 * role_match)
            + (0.3 * tool_match)
            + (0.15 * msg_sim)
            + (0.1 * model_sim)
            + (0.15 * token_sim)
        )
        return round(max(0.0, min(1.0, score)), 6)

    def check(self, agent_id: str, request_data: dict) -> tuple[bool, list[PatternMatch]]:
        signature = self.extract_signature(request_data)
        self.record(agent_id, signature)
        matches = self.detect_patterns(agent_id)
        return bool(matches), matches

    def get_agent_history(self, agent_id: str) -> dict:
        key = str(agent_id or "unknown")
        with self._lock:
            history = list(self._histories.get(key, deque()))
        if not history:
            return {"count": 0, "first_seen": 0.0, "last_seen": 0.0}
        tool_usage = Counter()
        for sig in history:
            tool_usage.update(sig.tool_sequence)
        return {
            "count": len(history),
            "has_tools": any(sig.has_tool_calls for sig in history),
            "models": sorted({sig.model for sig in history if sig.model}),
            "avg_messages": round(sum(sig.message_count for sig in history) / len(history), 3),
            "avg_tokens": round(sum(sig.estimated_tokens for sig in history) / len(history), 3),
            "top_tools": tool_usage.most_common(5),
            "generated_at": time.time(),
        }

    def get_all_agents(self) -> dict:
        with self._lock:
            keys = list(self._histories.keys())
        return {key: self.get_agent_history(key) for key in keys}

    def reset(self, agent_id: str) -> None:
        key = str(agent_id or "unknown")
        with self._lock:
            self._histories.pop(key, None)
