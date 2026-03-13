"""Privacy filter for community data sharing."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
import time
import uuid
from typing import Any, Optional

from orchesis import __version__ as ORCHESIS_VERSION

PRIVACY_LEVEL_OFF = 0
PRIVACY_LEVEL_MINIMAL = 1
PRIVACY_LEVEL_STANDARD = 2
PRIVACY_LEVEL_EXTENDED = 3
PRIVACY_LEVEL_RESEARCH = 4

_RISK_LEVELS = {"low", "medium", "high", "critical"}
_DRIFT_TYPES = {"normal", "injection", "model_switch", "persona_drift", ""}
_ARS_GRADES = {"A", "B", "C", "D", "F", ""}
_PII_PATTERNS = [
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\b(?:\+?\d[\d\-() ]{7,}\d)\b"),
]
_SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"bearer\s+[A-Za-z0-9._\-]{12,}", flags=re.IGNORECASE),
]
_PATH_URL_PATTERNS = [
    re.compile(r"(?:^|[\s])/(?:etc|root|home|var|Users|windows)\b"),
    re.compile(r"[A-Za-z]:\\"),
    re.compile(r"https?://", flags=re.IGNORECASE),
]
_PROMPTISH_PATTERNS = [
    re.compile(r"ignore\s+previous\s+instructions", flags=re.IGNORECASE),
    re.compile(r"\b(system|assistant|user)\s*:", flags=re.IGNORECASE),
    re.compile(r"```"),
]


@dataclass
class CommunitySignal:
    """A single anonymized signal ready for sharing."""

    signal_id: str
    timestamp: float
    signal_type: str
    threat_ids: list[str] = field(default_factory=list)
    anomaly_score: float = 0.0
    risk_level: str = ""
    agent_type_hash: str = ""
    ars_grade: str = ""
    request_tokens: int = 0
    response_tokens: int = 0
    model_name: str = ""
    latency_ms: float = 0.0
    cache_hit: bool = False
    pattern_types: list[str] = field(default_factory=list)
    drift_type: str = ""
    entropy_score: float = 0.0
    privacy_level: int = PRIVACY_LEVEL_STANDARD
    orchesis_version: str = ORCHESIS_VERSION


class PrivacyFilter:
    """Filters and anonymizes data before community sharing."""

    def __init__(self, privacy_level: int = PRIVACY_LEVEL_STANDARD, min_anomaly_score: float = 30.0):
        self.privacy_level = max(PRIVACY_LEVEL_OFF, min(PRIVACY_LEVEL_RESEARCH, int(privacy_level)))
        self.min_anomaly_score = max(0.0, float(min_anomaly_score))
        self._signals_created = 0
        self._signals_rejected = 0
        self._fields_stripped: dict[str, int] = {}

    def _strip(self, field_name: str) -> None:
        self._fields_stripped[field_name] = int(self._fields_stripped.get(field_name, 0)) + 1

    @staticmethod
    def _threat_ids_from_detection(detection_result: Any) -> list[str]:
        raw: list[str] = []
        if hasattr(detection_result, "threat_ids") and isinstance(getattr(detection_result, "threat_ids"), list):
            raw.extend(str(x) for x in getattr(detection_result, "threat_ids"))
        if hasattr(detection_result, "threat_matches") and isinstance(
            getattr(detection_result, "threat_matches"), list
        ):
            for item in getattr(detection_result, "threat_matches"):
                tid = ""
                if isinstance(item, dict):
                    tid = str(item.get("threat_id", "") or "")
                else:
                    tid = str(getattr(item, "threat_id", "") or "")
                if tid:
                    raw.append(tid)
        if isinstance(detection_result, dict):
            if isinstance(detection_result.get("threat_ids"), list):
                raw.extend(str(x) for x in detection_result.get("threat_ids", []))
            if isinstance(detection_result.get("threat_matches"), list):
                for item in detection_result.get("threat_matches", []):
                    if isinstance(item, dict) and item.get("threat_id"):
                        raw.append(str(item.get("threat_id")))
        out: list[str] = []
        for tid in raw:
            token = tid.strip().upper()
            if token and token not in out:
                out.append(token[:64])
        return out

    @staticmethod
    def _safe_get(source: Any, key: str, default: Any) -> Any:
        if isinstance(source, dict):
            return source.get(key, default)
        if hasattr(source, key):
            return getattr(source, key)
        return default

    def create_signal(
        self,
        detection_result: Any = None,
        telemetry_record: Any = None,
        ars_data: Any = None,
        request_meta: Any = None,
    ) -> Optional[CommunitySignal]:
        if self.privacy_level == PRIVACY_LEVEL_OFF:
            self._signals_rejected += 1
            return None
        if detection_result is None and telemetry_record is None:
            self._signals_rejected += 1
            return None

        threat_ids = self._threat_ids_from_detection(detection_result)
        anomaly_score = float(self._safe_get(detection_result, "anomaly_score", 0.0) or 0.0)
        risk_level = str(self._safe_get(detection_result, "risk_level", "") or "")
        pattern_types = [str(x) for x in (self._safe_get(detection_result, "pattern_types", []) or [])]
        if not pattern_types and isinstance(self._safe_get(detection_result, "patterns_found", None), list):
            for item in self._safe_get(detection_result, "patterns_found", []):
                if isinstance(item, dict):
                    ptype = str(item.get("pattern_type", "") or "")
                else:
                    ptype = str(getattr(item, "pattern_type", "") or "")
                if ptype:
                    pattern_types.append(ptype)
        drift_type = str(self._safe_get(detection_result, "drift_type", "normal") or "normal")
        entropy_score = float(self._safe_get(detection_result, "entropy_score", 0.0) or 0.0)
        if anomaly_score < self.min_anomaly_score and not threat_ids:
            self._signals_rejected += 1
            return None

        request_tokens = int(self._safe_get(telemetry_record, "input_tokens", 0) or 0)
        response_tokens = int(self._safe_get(telemetry_record, "output_tokens", 0) or 0)
        model_name = str(
            self._safe_get(telemetry_record, "model_used", "")
            or self._safe_get(detection_result, "model_name", "")
            or self._safe_get(request_meta, "model", "")
            or ""
        )
        latency_ms = float(self._safe_get(telemetry_record, "total_ms", 0.0) or 0.0)
        cache_hit = bool(self._safe_get(telemetry_record, "cache_hit", False))
        ars_grade = str(self._safe_get(ars_data, "grade", "") or "")
        signal_type = "threat" if threat_ids else "anomaly"
        if any("loop" in p for p in pattern_types):
            signal_type = "loop"
        elif drift_type in {"injection", "model_switch", "persona_drift"}:
            signal_type = "drift"

        profile = self._safe_get(request_meta, "agent_behavioral_data", {})
        if not isinstance(profile, dict):
            profile = {"agent_hint": str(self._safe_get(request_meta, "agent_type", "unknown"))}
        agent_hash = self.hash_agent_profile(profile)

        signal = CommunitySignal(
            signal_id=str(uuid.uuid4()),
            timestamp=time.time(),
            signal_type=signal_type,
            threat_ids=threat_ids,
            anomaly_score=max(0.0, min(100.0, anomaly_score)),
            risk_level=risk_level if risk_level in _RISK_LEVELS else "",
            agent_type_hash=agent_hash,
            ars_grade=ars_grade if ars_grade in _ARS_GRADES else "",
            request_tokens=max(0, request_tokens),
            response_tokens=max(0, response_tokens),
            model_name=model_name[:64],
            latency_ms=max(0.0, latency_ms),
            cache_hit=cache_hit,
            pattern_types=[p[:64] for p in pattern_types if p][:10],
            drift_type=drift_type if drift_type in _DRIFT_TYPES else "",
            entropy_score=max(0.0, min(100.0, entropy_score)),
            privacy_level=self.privacy_level,
            orchesis_version=ORCHESIS_VERSION,
        )

        if self.privacy_level <= PRIVACY_LEVEL_MINIMAL:
            if signal.anomaly_score:
                self._strip("anomaly_score")
            if signal.risk_level:
                self._strip("risk_level")
            if signal.agent_type_hash:
                self._strip("agent_type_hash")
            if signal.ars_grade:
                self._strip("ars_grade")
            signal.anomaly_score = 0.0
            signal.risk_level = ""
            signal.agent_type_hash = ""
            signal.ars_grade = ""
            signal.request_tokens = 0
            signal.response_tokens = 0
            signal.model_name = ""
            signal.latency_ms = 0.0
            signal.cache_hit = False
            signal.pattern_types = []
            signal.drift_type = ""
            signal.entropy_score = 0.0
            self._strip("metrics")
        elif self.privacy_level == PRIVACY_LEVEL_STANDARD:
            if signal.agent_type_hash:
                self._strip("agent_type_hash")
            signal.agent_type_hash = ""
            signal.pattern_types = []
            signal.drift_type = ""
            signal.entropy_score = 0.0
            self._strip("behavioral")
        elif self.privacy_level == PRIVACY_LEVEL_EXTENDED:
            signal.latency_ms = 0.0
            signal.request_tokens = 0
            signal.response_tokens = 0
            self._strip("timing_tokens")

        if not self.validate_signal(signal):
            self._signals_rejected += 1
            return None
        self._signals_created += 1
        return signal

    def hash_agent_profile(self, agent_behavioral_data: dict) -> str:
        canonical = json.dumps(agent_behavioral_data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def validate_signal(self, signal: CommunitySignal) -> bool:
        try:
            uuid.UUID(str(signal.signal_id))
        except Exception:
            return False
        now = time.time()
        if float(signal.timestamp) < now - 3600.0 or float(signal.timestamp) > now + 300.0:
            return False
        if signal.risk_level and signal.risk_level not in _RISK_LEVELS:
            return False
        if signal.ars_grade and signal.ars_grade not in _ARS_GRADES:
            return False
        if signal.drift_type and signal.drift_type not in _DRIFT_TYPES:
            return False
        if len(signal.model_name) > 64:
            return False
        text_fields = [
            signal.signal_type,
            signal.model_name,
            signal.agent_type_hash,
            signal.risk_level,
            signal.ars_grade,
            signal.drift_type,
        ] + list(signal.threat_ids) + list(signal.pattern_types)
        for text_field in text_fields:
            if not isinstance(text_field, str):
                return False
            if len(text_field) > 256:
                return False
            for pattern in _PII_PATTERNS + _SECRET_PATTERNS + _PATH_URL_PATTERNS + _PROMPTISH_PATTERNS:
                if pattern.search(text_field):
                    return False
        return True

    def get_privacy_report(self) -> dict[str, Any]:
        return {
            "signals_created": int(self._signals_created),
            "signals_rejected": int(self._signals_rejected),
            "fields_stripped": dict(self._fields_stripped),
            "privacy_level": int(self.privacy_level),
        }
