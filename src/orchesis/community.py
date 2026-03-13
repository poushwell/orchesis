"""Community Intelligence Network client."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import logging
from pathlib import Path
import sqlite3
import threading
import time
import uuid
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request as UrlRequest, urlopen

from orchesis.privacy_filter import (
    CommunitySignal,
    PRIVACY_LEVEL_STANDARD,
    PrivacyFilter,
)

_COMMUNITY_LOGGER = logging.getLogger("orchesis.community")


@dataclass
class CommunitySignature:
    """A threat signature received from the community."""

    signature_id: str
    signature_type: str
    pattern: str
    confidence: float
    reporters: int
    first_seen: float
    last_seen: float
    severity: str


@dataclass
class CommunityStats:
    """Statistics about community participation."""

    trust_score: float
    signals_sent: int
    signals_pending: int
    signatures_received: int
    signatures_cached: int
    last_sync: float
    hub_status: str
    contribution_ratio: float
    community_size: int


class CommunityClient:
    """Client for the Orchesis Community Intelligence Network."""

    def __init__(self, config: Optional[dict] = None):
        cfg = config if isinstance(config, dict) else {}
        self.enabled = bool(cfg.get("enabled", True))
        self.privacy_level = int(cfg.get("privacy_level", PRIVACY_LEVEL_STANDARD))
        self.hub_url = str(cfg.get("hub_url", "https://community.orchesis.io/api/v1")).rstrip("/")
        self.send_interval_seconds = max(0.1, float(cfg.get("send_interval_seconds", 300.0)))
        self.poll_interval_seconds = max(0.1, float(cfg.get("poll_interval_seconds", 900.0)))
        self.max_batch_size = max(1, int(cfg.get("max_batch_size", 100)))
        self.max_pending_signals = max(1, int(cfg.get("max_pending_signals", 10000)))
        self.max_cached_signatures = max(100, int(cfg.get("max_cached_signatures", 5000)))
        self.min_anomaly_score = max(0.0, float(cfg.get("min_anomaly_score", 30.0)))
        self._hub_status = "offline"
        self._trust_score = 0.0
        self._community_size = 0
        self._signals_sent = 0
        self._signatures_received = 0
        self._last_sync = 0.0
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._sender_thread: threading.Thread | None = None
        self._receiver_thread: threading.Thread | None = None
        self._privacy_filter = PrivacyFilter(self.privacy_level, min_anomaly_score=self.min_anomaly_score)
        self._data_dir = Path(str(cfg.get("data_dir", ".orchesis/community")))
        self._instance_file = self._data_dir / "instance_id"
        self._db_path = self._data_dir / "community.sqlite3"
        self.instance_id = ""
        if not self.enabled:
            return
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self.instance_id = self._get_or_create_instance_id()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _set_metadata(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO metadata(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            conn.commit()

    def _get_metadata(self, key: str, default: str = "") -> str:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
            return str(row["value"]) if row else default

    def record_signal(self, signal: CommunitySignal) -> None:
        if not self.enabled:
            return
        try:
            if not self._privacy_filter.validate_signal(signal):
                return
            payload = json.dumps(asdict(signal), ensure_ascii=False)
            now = time.time()
            with self._lock:
                with self._connect() as conn:
                    conn.execute(
                        "INSERT INTO pending_signals(signal_json, created_at, retry_count, sent_at) VALUES(?, ?, 0, NULL)",
                        (payload, now),
                    )
                    count_row = conn.execute("SELECT COUNT(*) AS c FROM pending_signals WHERE sent_at IS NULL").fetchone()
                    pending = int(count_row["c"]) if count_row else 0
                    if pending > self.max_pending_signals:
                        to_drop = pending - self.max_pending_signals
                        conn.execute(
                            "DELETE FROM pending_signals WHERE id IN (SELECT id FROM pending_signals WHERE sent_at IS NULL ORDER BY created_at ASC LIMIT ?)",
                            (to_drop,),
                        )
                    conn.commit()
        except Exception as exc:  # noqa: BLE001
            _COMMUNITY_LOGGER.warning("record_signal failed: %s", exc)

    def record_detection(
        self,
        detection_result: Any,
        telemetry_record: Any = None,
        ars_data: Any = None,
        request_meta: Any = None,
    ) -> None:
        if not self.enabled:
            return
        try:
            signal = self._privacy_filter.create_signal(
                detection_result=detection_result,
                telemetry_record=telemetry_record,
                ars_data=ars_data,
                request_meta=request_meta,
            )
            if signal is None:
                return
            if float(signal.anomaly_score) < self.min_anomaly_score and not signal.threat_ids:
                return
            self.record_signal(signal)
        except Exception as exc:  # noqa: BLE001
            _COMMUNITY_LOGGER.warning("record_detection failed: %s", exc)

    def _post_json(self, url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any], dict[str, str]]:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = UrlRequest(
            url,
            data=data,
            headers={"Content-Type": "application/json", "X-Orchesis-Instance": self.instance_id},
            method="POST",
        )
        with urlopen(req, timeout=5) as resp:
            raw = resp.read().decode("utf-8") if resp.length != 0 else "{}"
            body = json.loads(raw) if raw.strip() else {}
            return int(resp.status), body if isinstance(body, dict) else {}, dict(resp.headers.items())

    def _get_json(self, url: str) -> tuple[int, Any]:
        req = UrlRequest(url, headers={"X-Orchesis-Instance": self.instance_id}, method="GET")
        with urlopen(req, timeout=5) as resp:
            raw = resp.read().decode("utf-8")
            payload = json.loads(raw) if raw.strip() else {}
            return int(resp.status), payload

    def _send_batch(self) -> tuple[int, int]:
        if not self.enabled:
            return (0, 0)
        try:
            with self._lock:
                with self._connect() as conn:
                    rows = conn.execute(
                        "SELECT id, signal_json FROM pending_signals WHERE sent_at IS NULL ORDER BY created_at ASC LIMIT ?",
                        (self.max_batch_size,),
                    ).fetchall()
            if not rows:
                return (0, 0)
            signals: list[dict[str, Any]] = []
            ids: list[int] = []
            for row in rows:
                ids.append(int(row["id"]))
                try:
                    parsed = json.loads(str(row["signal_json"]))
                    if isinstance(parsed, dict):
                        signals.append(parsed)
                except Exception:
                    continue
            if not signals:
                return (0, 0)
            status, body, _headers = self._post_json(
                f"{self.hub_url}/signals",
                {"instance_id": self.instance_id, "signals": signals},
            )
            if 200 <= status < 300:
                now = time.time()
                with self._lock:
                    with self._connect() as conn:
                        conn.executemany("UPDATE pending_signals SET sent_at = ? WHERE id = ?", [(now, sid) for sid in ids])
                        conn.commit()
                sent = len(ids)
                self._signals_sent += sent
                self._hub_status = "connected"
                self._trust_score = float(body.get("trust_score", self._trust_score))
                self._community_size = int(body.get("community_size", self._community_size))
                return (sent, 0)
            with self._lock:
                with self._connect() as conn:
                    conn.executemany(
                        "UPDATE pending_signals SET retry_count = retry_count + 1 WHERE id = ?",
                        [(sid,) for sid in ids],
                    )
                    conn.commit()
            self._hub_status = "error"
            return (0, len(ids))
        except HTTPError as exc:
            self._hub_status = "error"
            if int(exc.code) == 429:
                retry_after = 0.0
                try:
                    retry_after = float(exc.headers.get("Retry-After", "0") or "0")
                except Exception:
                    retry_after = 0.0
                if retry_after > 0:
                    time.sleep(min(1.0, retry_after))
                return (0, 0)
            _COMMUNITY_LOGGER.warning("community send failed: %s", exc)
            return (0, 0)
        except (URLError, OSError) as exc:
            self._hub_status = "offline"
            _COMMUNITY_LOGGER.warning("community hub unreachable: %s", exc)
            return (0, 0)
        except Exception as exc:  # noqa: BLE001
            self._hub_status = "error"
            _COMMUNITY_LOGGER.warning("send_batch error: %s", exc)
            return (0, 0)

    def _poll_signatures(self) -> int:
        if not self.enabled:
            return 0
        try:
            since = int(self._last_sync or 0)
            status, payload = self._get_json(f"{self.hub_url}/signatures?since={since}")
            if status < 200 or status >= 300:
                self._hub_status = "error"
                return 0
            items = payload.get("signatures", payload) if isinstance(payload, dict) else payload
            if not isinstance(items, list):
                return 0
            accepted = 0
            now = time.time()
            with self._lock:
                with self._connect() as conn:
                    for raw in items:
                        if not isinstance(raw, dict):
                            continue
                        sid = str(raw.get("signature_id", "") or "")
                        if not sid:
                            continue
                        sig = {
                            "signature_id": sid,
                            "signature_type": str(raw.get("signature_type", "") or ""),
                            "pattern": str(raw.get("pattern", "") or ""),
                            "confidence": float(raw.get("confidence", 0.0) or 0.0),
                            "reporters": int(raw.get("reporters", 0) or 0),
                            "first_seen": float(raw.get("first_seen", now) or now),
                            "last_seen": float(raw.get("last_seen", now) or now),
                            "severity": str(raw.get("severity", "low") or "low"),
                        }
                        expires = raw.get("expires_at")
                        expires_at = float(expires) if isinstance(expires, (int, float)) else None
                        conn.execute(
                            "INSERT INTO community_signatures(signature_id, signature_json, received_at, expires_at) VALUES(?, ?, ?, ?) "
                            "ON CONFLICT(signature_id) DO UPDATE SET signature_json=excluded.signature_json, received_at=excluded.received_at, expires_at=excluded.expires_at",
                            (sid, json.dumps(sig, ensure_ascii=False), now, expires_at),
                        )
                        accepted += 1
                    row = conn.execute("SELECT COUNT(*) AS c FROM community_signatures").fetchone()
                    total_cached = int(row["c"]) if row else 0
                    if total_cached > self.max_cached_signatures:
                        drop = total_cached - self.max_cached_signatures
                        conn.execute(
                            "DELETE FROM community_signatures WHERE signature_id IN (SELECT signature_id FROM community_signatures ORDER BY received_at ASC LIMIT ?)",
                            (drop,),
                        )
                    conn.commit()
            self._last_sync = now
            self._set_metadata("last_sync", str(now))
            self._signatures_received += accepted
            self._hub_status = "connected"
            return accepted
        except (URLError, OSError) as exc:
            self._hub_status = "offline"
            _COMMUNITY_LOGGER.warning("community poll offline: %s", exc)
            return 0
        except Exception as exc:  # noqa: BLE001
            self._hub_status = "error"
            _COMMUNITY_LOGGER.warning("poll_signatures error: %s", exc)
            return 0

    def get_community_signatures(self) -> list[CommunitySignature]:
        if not self.enabled:
            return []
        now = time.time()
        out: list[CommunitySignature] = []
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT signature_json, expires_at FROM community_signatures ORDER BY received_at DESC"
                ).fetchall()
        for row in rows:
            expires_at = row["expires_at"]
            if isinstance(expires_at, (int, float)) and float(expires_at) > 0.0 and float(expires_at) < now:
                continue
            try:
                parsed = json.loads(str(row["signature_json"]))
                if not isinstance(parsed, dict):
                    continue
                out.append(
                    CommunitySignature(
                        signature_id=str(parsed.get("signature_id", "")),
                        signature_type=str(parsed.get("signature_type", "")),
                        pattern=str(parsed.get("pattern", "")),
                        confidence=float(parsed.get("confidence", 0.0) or 0.0),
                        reporters=int(parsed.get("reporters", 0) or 0),
                        first_seen=float(parsed.get("first_seen", 0.0) or 0.0),
                        last_seen=float(parsed.get("last_seen", 0.0) or 0.0),
                        severity=str(parsed.get("severity", "low") or "low"),
                    )
                )
            except Exception:
                continue
        return out

    def has_signature(self, signature_id: str) -> bool:
        if not self.enabled:
            return False
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT 1 AS ok FROM community_signatures WHERE signature_id = ? LIMIT 1",
                    (str(signature_id),),
                ).fetchone()
                return row is not None

    def _sender_loop(self) -> None:
        while not self._stop_event.wait(self.send_interval_seconds):
            try:
                self._send_batch()
                self._cleanup_old_signals()
            except Exception as exc:  # noqa: BLE001
                _COMMUNITY_LOGGER.warning("community sender loop error: %s", exc)

    def _receiver_loop(self) -> None:
        while not self._stop_event.wait(self.poll_interval_seconds):
            try:
                self._poll_signatures()
                self._cleanup_old_signals()
            except Exception as exc:  # noqa: BLE001
                _COMMUNITY_LOGGER.warning("community receiver loop error: %s", exc)

    def start(self) -> None:
        if not self.enabled:
            return
        if self._sender_thread is not None and self._sender_thread.is_alive():
            return
        self._stop_event.clear()
        self._sender_thread = threading.Thread(target=self._sender_loop, name="community-sender", daemon=True)
        self._receiver_thread = threading.Thread(target=self._receiver_loop, name="community-receiver", daemon=True)
        self._sender_thread.start()
        self._receiver_thread.start()

    def stop(self) -> None:
        if not self.enabled:
            return
        self._stop_event.set()
        if self._sender_thread is not None:
            self._sender_thread.join(timeout=3.0)
        if self._receiver_thread is not None:
            self._receiver_thread.join(timeout=3.0)
        try:
            self._send_batch()
        except Exception:
            pass
        self._cleanup_old_signals()

    def _get_or_create_instance_id(self) -> str:
        if self._instance_file.exists():
            existing = self._instance_file.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        value = str(uuid.uuid4())
        self._instance_file.write_text(value, encoding="utf-8")
        return value

    def _init_db(self) -> None:
        try:
            with self._connect() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS pending_signals ("
                    "id INTEGER PRIMARY KEY,"
                    "signal_json TEXT NOT NULL,"
                    "created_at REAL NOT NULL,"
                    "retry_count INTEGER DEFAULT 0,"
                    "sent_at REAL DEFAULT NULL)"
                )
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS community_signatures ("
                    "signature_id TEXT PRIMARY KEY,"
                    "signature_json TEXT NOT NULL,"
                    "received_at REAL NOT NULL,"
                    "expires_at REAL DEFAULT NULL)"
                )
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS metadata ("
                    "key TEXT PRIMARY KEY,"
                    "value TEXT NOT NULL)"
                )
                conn.commit()
            last_sync = self._get_metadata("last_sync", "0")
            try:
                self._last_sync = float(last_sync)
            except Exception:
                self._last_sync = 0.0
        except sqlite3.DatabaseError:
            recovered_path = self._data_dir / f"community-recovered-{int(time.time() * 1000)}.sqlite3"
            try:
                if self._db_path.exists():
                    backup = self._db_path.with_suffix(".corrupt")
                    try:
                        self._db_path.replace(backup)
                    except Exception:
                        self._db_path.unlink(missing_ok=True)
            except Exception:
                pass
            self._db_path = recovered_path
            with self._connect() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    "CREATE TABLE pending_signals (id INTEGER PRIMARY KEY, signal_json TEXT NOT NULL, created_at REAL NOT NULL, retry_count INTEGER DEFAULT 0, sent_at REAL DEFAULT NULL)"
                )
                conn.execute(
                    "CREATE TABLE community_signatures (signature_id TEXT PRIMARY KEY, signature_json TEXT NOT NULL, received_at REAL NOT NULL, expires_at REAL DEFAULT NULL)"
                )
                conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                conn.commit()

    def _cleanup_old_signals(self) -> None:
        if not self.enabled:
            return
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM pending_signals WHERE sent_at IS NOT NULL AND sent_at < ?", (now - 86400.0,))
                conn.execute("DELETE FROM pending_signals WHERE sent_at IS NULL AND created_at < ?", (now - 7 * 86400.0,))
                conn.execute(
                    "DELETE FROM community_signatures WHERE expires_at IS NOT NULL AND expires_at > 0 AND expires_at < ?",
                    (now,),
                )
                conn.commit()

    def get_stats(self) -> CommunityStats:
        if not self.enabled:
            return CommunityStats(0.0, 0, 0, 0, 0, 0.0, "offline", 0.0, 0)
        with self._lock:
            with self._connect() as conn:
                pending_row = conn.execute("SELECT COUNT(*) AS c FROM pending_signals WHERE sent_at IS NULL").fetchone()
                cached_row = conn.execute("SELECT COUNT(*) AS c FROM community_signatures").fetchone()
        pending = int(pending_row["c"]) if pending_row else 0
        cached = int(cached_row["c"]) if cached_row else 0
        received = int(self._signatures_received)
        ratio = (self._signals_sent / float(max(1, received))) if received > 0 else float(self._signals_sent)
        return CommunityStats(
            trust_score=float(self._trust_score),
            signals_sent=int(self._signals_sent),
            signals_pending=pending,
            signatures_received=received,
            signatures_cached=cached,
            last_sync=float(self._last_sync),
            hub_status=str(self._hub_status),
            contribution_ratio=float(ratio),
            community_size=int(self._community_size),
        )

    def get_status(self) -> dict[str, Any]:
        stats = self.get_stats()
        return {
            "enabled": bool(self.enabled),
            "privacy_level": int(self.privacy_level),
            "hub_status": stats.hub_status,
            "signals_pending": int(stats.signals_pending),
            "signatures_cached": int(stats.signatures_cached),
            "trust_score": float(stats.trust_score),
            "last_sync": float(stats.last_sync) if stats.last_sync > 0 else None,
        }
