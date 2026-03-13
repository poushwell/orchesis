"""Unified adaptive detection engine for Orchesis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import logging
import threading
import time
from typing import Any, Optional

from orchesis.entropy_detector import EntropyDetector
from orchesis.ngram_profiler import NgramProfiler, ProfileDrift
from orchesis.session_risk import RiskSignal, SessionRiskAccumulator
from orchesis.structural_patterns import PatternMatch, StructuralPatternDetector

_ADAPTIVE_LOGGER = logging.getLogger("orchesis.adaptive_detector")


@dataclass
class DetectionResult:
    """Unified result from all detectors."""

    anomaly_score: float
    is_anomalous: bool
    risk_level: str
    recommended_action: str
    entropy_score: float
    structural_score: float
    ngram_drift_score: float
    session_risk_score: float
    patterns_found: list[PatternMatch] = field(default_factory=list)
    drift_type: str = "normal"
    entropy_anomalous: bool = False
    structural_anomalous: bool = False
    ngram_anomalous: bool = False
    agent_id: str = ""
    timestamp: float = 0.0
    detectors_run: list[str] = field(default_factory=list)
    detection_time_us: float = 0.0


class AdaptiveDetector:
    """Combines multiple anomaly detectors into one scored decision."""

    _DEFAULT_WEIGHTS = {
        "entropy": 0.30,
        "structural": 0.25,
        "ngram": 0.25,
        "session_risk": 0.20,
    }
    _DEFAULT_THRESHOLDS = {"low": 30.0, "medium": 50.0, "high": 70.0, "critical": 100.0}
    _DEFAULT_ACTIONS = {"low": "allow", "medium": "warn", "high": "throttle", "critical": "block"}
    _PATTERN_POINTS = {
        "tool_chain_loop": 30.0,
        "role_cycle": 20.0,
        "request_template": 25.0,
        "escalation_chain": 35.0,
        "ping_pong": 25.0,
    }

    def __init__(self, config: Optional[dict] = None):
        cfg = config if isinstance(config, dict) else {}
        self.enabled = bool(cfg.get("enabled", True))
        det_cfg = cfg.get("detectors") if isinstance(cfg.get("detectors"), dict) else {}
        self._detectors_enabled = {
            "entropy": bool(det_cfg.get("entropy", True)),
            "structural": bool(det_cfg.get("structural", True)),
            "ngram": bool(det_cfg.get("ngram", True)),
            "session_risk": bool(det_cfg.get("session_risk", True)),
        }
        weights_cfg = cfg.get("weights") if isinstance(cfg.get("weights"), dict) else {}
        self._weights = {
            key: float(weights_cfg.get(key, self._DEFAULT_WEIGHTS[key]))
            for key in self._DEFAULT_WEIGHTS
        }
        thr_cfg = cfg.get("thresholds") if isinstance(cfg.get("thresholds"), dict) else {}
        self._thresholds = {
            key: float(thr_cfg.get(key, self._DEFAULT_THRESHOLDS[key]))
            for key in self._DEFAULT_THRESHOLDS
        }
        act_cfg = cfg.get("actions") if isinstance(cfg.get("actions"), dict) else {}
        self._actions = {
            key: str(act_cfg.get(key, self._DEFAULT_ACTIONS[key]))
            for key in self._DEFAULT_ACTIONS
        }

        entropy_cfg = cfg.get("entropy") if isinstance(cfg.get("entropy"), dict) else {}
        structural_cfg = cfg.get("structural") if isinstance(cfg.get("structural"), dict) else {}
        ngram_cfg = cfg.get("ngram") if isinstance(cfg.get("ngram"), dict) else {}
        sr_cfg = cfg.get("session_risk") if isinstance(cfg.get("session_risk"), dict) else {}
        warn = float(sr_cfg.get("warn_threshold", self._thresholds["medium"]))
        block = float(sr_cfg.get("block_threshold", sr_cfg.get("escalation_threshold", self._thresholds["high"])))

        self._entropy_detector = EntropyDetector(entropy_cfg) if self._detectors_enabled["entropy"] else None
        self._structural_detector = (
            StructuralPatternDetector(structural_cfg) if self._detectors_enabled["structural"] else None
        )
        self._ngram_profiler = NgramProfiler(ngram_cfg) if self._detectors_enabled["ngram"] else None
        self._session_risk = (
            SessionRiskAccumulator(
                warn_threshold=warn,
                block_threshold=block,
                decay_half_life_seconds=float(sr_cfg.get("decay_half_life_seconds", 300.0)),
                max_signals_per_session=int(sr_cfg.get("max_signals_per_session", 100)),
                session_ttl_seconds=float(sr_cfg.get("session_ttl_seconds", 3600.0)),
                category_diversity_bonus=float(sr_cfg.get("category_diversity_bonus", 10.0)),
                enabled=True,
            )
            if self._detectors_enabled["session_risk"]
            else None
        )
        self._lock = threading.Lock()
        self._agent_results: dict[str, DetectionResult] = {}
        self._stats = {
            "checks_total": 0,
            "anomalies_total": 0,
            "risk_counts": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "detector_errors": {"entropy": 0, "structural": 0, "ngram": 0, "session_risk": 0},
            "total_detection_time_us": 0.0,
        }

    @staticmethod
    def _extract_request_text(request_data: dict[str, Any]) -> tuple[str, str, list[str]]:
        messages = request_data.get("messages")
        if not isinstance(messages, list):
            messages = []
        all_parts: list[str] = []
        assistant_parts: list[str] = []
        tools: list[str] = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "") or "").strip().lower()
            content = msg.get("content")
            if isinstance(content, str) and content.strip():
                all_parts.append(content.strip())
                if role == "assistant":
                    assistant_parts.append(content.strip())
            calls = msg.get("tool_calls")
            if isinstance(calls, list):
                for item in calls:
                    if isinstance(item, dict):
                        name = (
                            item.get("name")
                            or (item.get("function") or {}).get("name")
                            or item.get("tool_name")
                            or ""
                        )
                        if isinstance(name, str) and name.strip():
                            tools.append(name.strip())
        req_tools = request_data.get("tools")
        if isinstance(req_tools, list):
            for item in req_tools:
                if isinstance(item, str) and item.strip():
                    tools.append(item.strip())
                elif isinstance(item, dict):
                    name = item.get("name")
                    if isinstance(name, str) and name.strip():
                        tools.append(name.strip())
        return " ".join(all_parts).strip(), " ".join(assistant_parts).strip(), tools

    def _structural_to_score(self, patterns: list[PatternMatch]) -> float:
        if not patterns:
            return 0.0
        score = 0.0
        seen_types: set[str] = set()
        for idx, pattern in enumerate(patterns):
            base = self._PATTERN_POINTS.get(pattern.pattern_type, 15.0)
            confidence = max(0.0, min(1.0, float(pattern.confidence)))
            factor = 1.0 if idx == 0 else 0.7
            score += base * confidence * factor
            seen_types.add(pattern.pattern_type)
        if len(seen_types) >= 3:
            score += 20.0
        return round(min(100.0, max(0.0, score)), 2)

    @staticmethod
    def _risk_level(score: float, thresholds: dict[str, float]) -> str:
        if score <= thresholds["low"]:
            return "low"
        if score <= thresholds["medium"]:
            return "medium"
        if score <= thresholds["high"]:
            return "high"
        return "critical"

    def _normalize_weights(self, detector_scores: dict[str, float]) -> dict[str, float]:
        active = [name for name, score in detector_scores.items() if score >= 0.0]
        if not active:
            return {}
        raw_sum = sum(max(0.0, self._weights.get(name, 0.0)) for name in active)
        if raw_sum <= 0.0:
            equal = 1.0 / float(len(active))
            return {name: equal for name in active}
        return {name: max(0.0, self._weights.get(name, 0.0)) / raw_sum for name in active}

    def _record_session_signal(self, session_id: str, category: str, score_100: float, source: str) -> None:
        if self._session_risk is None:
            return
        score = max(0.0, min(100.0, float(score_100)))
        if score <= 0.0:
            return
        severity = "low"
        if score >= 85.0:
            severity = "critical"
        elif score >= 70.0:
            severity = "high"
        elif score >= 45.0:
            severity = "medium"
        self._session_risk.record_signal(
            session_id,
            RiskSignal(
                category=category,
                confidence=max(0.0, min(1.0, score / 100.0)),
                severity=severity,
                source=source,
                description=f"{source} score={score:.1f}",
            ),
        )

    def check(self, agent_id: str, request_data: dict[str, Any]) -> DetectionResult:
        started_ns = time.perf_counter_ns()
        ts = time.time()
        safe_agent = str(agent_id or "unknown")
        req = request_data if isinstance(request_data, dict) else {}

        if not self.enabled:
            return DetectionResult(
                anomaly_score=0.0,
                is_anomalous=False,
                risk_level="low",
                recommended_action="allow",
                entropy_score=0.0,
                structural_score=0.0,
                ngram_drift_score=0.0,
                session_risk_score=0.0,
                agent_id=safe_agent,
                timestamp=ts,
                detectors_run=[],
                detection_time_us=0.0,
            )

        all_text, assistant_text, tools = self._extract_request_text(req)
        detectors_run: list[str] = []
        patterns: list[PatternMatch] = []
        entropy_score = -1.0
        entropy_anom = False
        structural_score = -1.0
        structural_anom = False
        ngram_score = -1.0
        ngram_anom = False
        drift_type = "normal"
        session_risk_score = -1.0

        if self._entropy_detector is not None:
            try:
                entropy_req = dict(req)
                entropy_req["tools"] = tools
                entropy_anom, entropy_score, _ = self._entropy_detector.check(safe_agent, entropy_req)
                detectors_run.append("entropy")
            except Exception as exc:  # noqa: BLE001
                _ADAPTIVE_LOGGER.warning("entropy detector failed: %s", exc)
                with self._lock:
                    self._stats["detector_errors"]["entropy"] += 1

        if self._structural_detector is not None:
            try:
                structural_anom, patterns = self._structural_detector.check(safe_agent, req)
                structural_score = self._structural_to_score(patterns)
                detectors_run.append("structural")
            except Exception as exc:  # noqa: BLE001
                _ADAPTIVE_LOGGER.warning("structural detector failed: %s", exc)
                with self._lock:
                    self._stats["detector_errors"]["structural"] += 1

        if self._ngram_profiler is not None:
            try:
                sample = assistant_text if assistant_text else all_text
                ngram_anom, drift = self._ngram_profiler.check(safe_agent, sample)
                if isinstance(drift, ProfileDrift):
                    ngram_score = max(0.0, min(100.0, float(drift.drift_score) * 100.0))
                    drift_type = str(drift.drift_type or "normal")
                detectors_run.append("ngram")
            except Exception as exc:  # noqa: BLE001
                _ADAPTIVE_LOGGER.warning("ngram detector failed: %s", exc)
                with self._lock:
                    self._stats["detector_errors"]["ngram"] += 1

        if self._session_risk is not None:
            try:
                if entropy_score > 0:
                    self._record_session_signal(safe_agent, "entropy_anomaly", entropy_score, "entropy")
                if structural_score > 0:
                    self._record_session_signal(
                        safe_agent, "structural_anomaly", structural_score, "structural"
                    )
                if ngram_score > 0:
                    self._record_session_signal(safe_agent, "ngram_drift", ngram_score, "ngram")
                assessment = self._session_risk.evaluate(safe_agent)
                session_risk_score = float(assessment.composite_score)
                detectors_run.append("session_risk")
            except Exception as exc:  # noqa: BLE001
                _ADAPTIVE_LOGGER.warning("session risk detector failed: %s", exc)
                with self._lock:
                    self._stats["detector_errors"]["session_risk"] += 1

        detector_scores = {
            "entropy": entropy_score,
            "structural": structural_score,
            "ngram": ngram_score,
            "session_risk": session_risk_score,
        }
        norm_weights = self._normalize_weights(detector_scores)
        combined = 0.0
        for name, weight in norm_weights.items():
            combined += max(0.0, detector_scores.get(name, 0.0)) * weight
        combined = round(max(0.0, min(100.0, combined)), 2)
        risk_level = self._risk_level(combined, self._thresholds)
        action = self._actions.get(risk_level, "allow")
        is_anomalous = combined > self._thresholds["low"]
        elapsed_us = (time.perf_counter_ns() - started_ns) / 1000.0

        result = DetectionResult(
            anomaly_score=combined,
            is_anomalous=is_anomalous,
            risk_level=risk_level,
            recommended_action=action,
            entropy_score=round(max(0.0, entropy_score), 2),
            structural_score=round(max(0.0, structural_score), 2),
            ngram_drift_score=round(max(0.0, ngram_score) / 100.0, 6),
            session_risk_score=round(max(0.0, session_risk_score), 2),
            patterns_found=list(patterns),
            drift_type=drift_type,
            entropy_anomalous=bool(entropy_anom),
            structural_anomalous=bool(structural_anom),
            ngram_anomalous=bool(ngram_anom),
            agent_id=safe_agent,
            timestamp=ts,
            detectors_run=detectors_run,
            detection_time_us=round(elapsed_us, 3),
        )
        with self._lock:
            self._agent_results[safe_agent] = result
            self._stats["checks_total"] += 1
            self._stats["total_detection_time_us"] += result.detection_time_us
            if result.is_anomalous:
                self._stats["anomalies_total"] += 1
            self._stats["risk_counts"][risk_level] += 1
        return result

    def get_agent_status(self, agent_id: str) -> dict[str, Any]:
        key = str(agent_id or "unknown")
        with self._lock:
            cached = self._agent_results.get(key)
        if cached is None:
            return {"agent_id": key, "found": False}
        payload = asdict(cached)
        payload["found"] = True
        if self._entropy_detector is not None:
            payload["entropy_baseline"] = self._entropy_detector.get_baseline(key)
        if self._structural_detector is not None:
            payload["structural_history"] = self._structural_detector.get_agent_history(key)
        if self._ngram_profiler is not None:
            payload["ngram_profile"] = self._ngram_profiler.get_profile(key)
        if self._session_risk is not None:
            payload["session_risk"] = self._session_risk.get_session_state(key)
        return payload

    def get_all_agents(self) -> dict[str, Any]:
        with self._lock:
            keys = list(self._agent_results.keys())
        return {agent: self.get_agent_status(agent) for agent in keys}

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            checks = int(self._stats["checks_total"])
            avg_us = self._stats["total_detection_time_us"] / float(checks) if checks > 0 else 0.0
            return {
                "enabled": self.enabled,
                "checks_total": checks,
                "anomalies_total": int(self._stats["anomalies_total"]),
                "risk_counts": dict(self._stats["risk_counts"]),
                "detector_errors": dict(self._stats["detector_errors"]),
                "avg_detection_time_us": round(avg_us, 3),
                "detectors_enabled": dict(self._detectors_enabled),
                "weights": dict(self._weights),
                "thresholds": dict(self._thresholds),
            }

    def reset(self, agent_id: str) -> None:
        key = str(agent_id or "unknown")
        if self._entropy_detector is not None:
            self._entropy_detector.reset(key)
        if self._structural_detector is not None:
            self._structural_detector.reset(key)
        if self._ngram_profiler is not None:
            self._ngram_profiler.reset(key)
        if self._session_risk is not None:
            self._session_risk.reset_session(key)
        with self._lock:
            self._agent_results.pop(key, None)

    def reset_all(self) -> None:
        with self._lock:
            keys = list(self._agent_results.keys())
        for key in keys:
            self.reset(key)
