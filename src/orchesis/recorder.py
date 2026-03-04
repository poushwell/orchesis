"""Session recording subsystem for Time Machine."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import threading
import time
from typing import Any, IO
import uuid


@dataclass
class SessionRecord:
    request_id: str
    session_id: str
    timestamp: float
    request: dict[str, Any]
    response: dict[str, Any] | None
    status_code: int
    provider: str
    model: str
    latency_ms: float
    cost: float
    error: str | None
    metadata: dict[str, Any]


@dataclass
class SessionSummary:
    session_id: str
    start_time: float
    end_time: float
    request_count: int
    total_cost: float
    models_used: list[str]
    error_count: int
    file_path: str
    file_size_bytes: int


@dataclass
class _SessionWriter:
    file_path: Path
    handle: IO[bytes]
    record_count: int = 0


class SessionRecorder:
    """Thread-safe JSONL(+gzip) session recorder with rotation."""

    def __init__(
        self,
        *,
        storage_path: str = ".orchesis/sessions",
        compress: bool = True,
        max_file_size_mb: int = 10,
        max_records_per_file: int = 10_000,
    ) -> None:
        self._storage_path = Path(storage_path)
        self._storage_path.mkdir(parents=True, exist_ok=True)
        self._compress = bool(compress)
        self._max_file_size = max(1, int(max_file_size_mb)) * 1024 * 1024
        self._max_records_per_file = max(1, int(max_records_per_file))
        self._writers: dict[str, _SessionWriter] = {}
        self._lock = threading.Lock()
        self._total_recorded = 0
        self._index_path = self._storage_path / "index.json"
        self._index: dict[str, dict[str, Any]] = {}
        self._load_index()

    def __enter__(self) -> SessionRecorder:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        _ = (exc_type, exc, tb)
        self.close_all()

    def __del__(self) -> None:
        try:
            self.close_all()
        except Exception:
            pass

    def _filename(self, session_id: str, suffix: str = "") -> str:
        date_part = datetime.now(timezone.utc).strftime("%Y%m%d")
        ext = ".jsonl.gz" if self._compress else ".jsonl"
        tail = f"_{suffix}" if suffix else ""
        return f"{session_id}_{date_part}{tail}{ext}"

    def _load_index(self) -> None:
        try:
            if self._index_path.exists():
                loaded = json.loads(self._index_path.read_text(encoding="utf-8"))
                self._index = loaded if isinstance(loaded, dict) else {}
        except Exception:
            self._index = {}

    def _save_index(self) -> None:
        try:
            self._index_path.write_text(
                json.dumps(self._index, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _open_writer(self, session_id: str, suffix: str = "") -> _SessionWriter:
        path = self._storage_path / self._filename(session_id, suffix=suffix)
        if self._compress:
            handle = gzip.open(path, "ab")
        else:
            handle = path.open("ab")
        return _SessionWriter(file_path=path, handle=handle)

    def _should_rotate(self, writer: _SessionWriter) -> bool:
        try:
            size = writer.file_path.stat().st_size
        except OSError:
            size = 0
        return size >= self._max_file_size or writer.record_count >= self._max_records_per_file

    def _rotate(self, session_id: str, writer: _SessionWriter) -> _SessionWriter:
        try:
            writer.handle.flush()
            writer.handle.close()
        except Exception:
            pass
        new_writer = self._open_writer(session_id, suffix=uuid.uuid4().hex[:6])
        self._writers[session_id] = new_writer
        return new_writer

    def record(self, record: SessionRecord) -> None:
        payload = (json.dumps(asdict(record), ensure_ascii=False) + "\n").encode("utf-8")
        with self._lock:
            writer = self._writers.get(record.session_id)
            if writer is None:
                writer = self._open_writer(record.session_id)
                self._writers[record.session_id] = writer
            if self._should_rotate(writer):
                writer = self._rotate(record.session_id, writer)
            writer.handle.write(payload)
            writer.handle.flush()
            writer.record_count += 1
            self._total_recorded += 1
            sid = record.session_id
            entry = self._index.get(sid)
            if entry is None:
                entry = {
                    "session_id": sid,
                    "start_time": record.timestamp,
                    "end_time": record.timestamp,
                    "request_count": 0,
                    "total_cost": 0.0,
                    "models_used": [],
                    "error_count": 0,
                    "file_path": str(writer.file_path),
                    "file_size_bytes": 0,
                }
            now_cost = float(record.cost)
            entry["end_time"] = record.timestamp
            entry["request_count"] = int(entry.get("request_count", 0)) + 1
            entry["total_cost"] = round(float(entry.get("total_cost", 0.0)) + now_cost, 8)
            models_used = entry.setdefault("models_used", [])
            if record.model and isinstance(models_used, list) and record.model not in models_used:
                models_used.append(record.model)
            if record.error or record.status_code >= 400:
                entry["error_count"] = int(entry.get("error_count", 0)) + 1
            entry["file_path"] = str(writer.file_path)
            try:
                entry["file_size_bytes"] = int(writer.file_path.stat().st_size)
            except OSError:
                pass
            self._index[sid] = entry
            self._save_index()

    def close_session(self, session_id: str) -> None:
        with self._lock:
            writer = self._writers.pop(session_id, None)
            if writer is not None:
                writer.handle.flush()
                writer.handle.close()

    def close_all(self) -> None:
        with self._lock:
            ids = list(self._writers.keys())
        for session_id in ids:
            self.close_session(session_id)

    def _iter_session_files(self) -> list[Path]:
        files = sorted(self._storage_path.glob("*.jsonl*"))
        return [item for item in files if item.is_file()]

    @staticmethod
    def _session_id_from_file(path: Path) -> str:
        name = path.name
        part = name.split("_", 1)[0]
        return part

    def _read_file_records(self, path: Path) -> list[SessionRecord]:
        records: list[SessionRecord] = []
        try:
            if path.suffix == ".gz":
                fh = gzip.open(path, "rt", encoding="utf-8")
            else:
                fh = path.open("r", encoding="utf-8")
            with fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(payload, dict):
                        records.append(SessionRecord(**payload))
        except Exception:
            return []
        return records

    def _list_sessions_from_files(self) -> list[SessionSummary]:
        summaries: dict[str, SessionSummary] = {}
        for path in self._iter_session_files():
            sid = self._session_id_from_file(path)
            records = self._read_file_records(path)
            if not records:
                continue
            start_time = records[0].timestamp
            end_time = records[-1].timestamp
            request_count = len(records)
            total_cost = sum(float(item.cost) for item in records)
            models = sorted({item.model for item in records if isinstance(item.model, str) and item.model})
            errors = sum(1 for item in records if item.error or int(item.status_code) >= 400)
            file_size = path.stat().st_size if path.exists() else 0
            current = summaries.get(sid)
            summary = SessionSummary(
                session_id=sid,
                start_time=start_time,
                end_time=end_time,
                request_count=request_count,
                total_cost=round(total_cost, 8),
                models_used=models,
                error_count=errors,
                file_path=str(path),
                file_size_bytes=file_size,
            )
            if current is None or summary.end_time > current.end_time:
                summaries[sid] = summary
        return sorted(summaries.values(), key=lambda item: item.end_time, reverse=True)

    def list_sessions(self) -> list[SessionSummary]:
        with self._lock:
            if self._index:
                summaries: list[SessionSummary] = []
                for entry in self._index.values():
                    if not isinstance(entry, dict):
                        continue
                    models = entry.get("models_used", [])
                    summaries.append(
                        SessionSummary(
                            session_id=str(entry.get("session_id", "")),
                            start_time=float(entry.get("start_time", 0.0) or 0.0),
                            end_time=float(entry.get("end_time", 0.0) or 0.0),
                            request_count=int(entry.get("request_count", 0) or 0),
                            total_cost=float(entry.get("total_cost", 0.0) or 0.0),
                            models_used=models if isinstance(models, list) else [],
                            error_count=int(entry.get("error_count", 0) or 0),
                            file_path=str(entry.get("file_path", "")),
                            file_size_bytes=int(entry.get("file_size_bytes", 0) or 0),
                        )
                    )
                return sorted(summaries, key=lambda item: item.end_time, reverse=True)
        # Backward compatibility for recordings created before index.json existed.
        return self._list_sessions_from_files()

    def load_session(self, session_id: str) -> list[SessionRecord]:
        self.close_session(session_id)
        records: list[SessionRecord] = []
        for path in self._iter_session_files():
            if self._session_id_from_file(path) != session_id:
                continue
            records.extend(self._read_file_records(path))
        return sorted(records, key=lambda item: item.timestamp)

    def get_session_summary(self, session_id: str) -> SessionSummary:
        self.close_session(session_id)
        records = self.load_session(session_id)
        if not records:
            raise FileNotFoundError(f"Session not found: {session_id}")
        candidate_files = [p for p in self._iter_session_files() if self._session_id_from_file(p) == session_id]
        latest_path = max(candidate_files, key=lambda p: p.stat().st_mtime) if candidate_files else Path("")
        total_cost = sum(float(item.cost) for item in records)
        models = sorted({item.model for item in records if isinstance(item.model, str) and item.model})
        errors = sum(1 for item in records if item.error or int(item.status_code) >= 400)
        return SessionSummary(
            session_id=session_id,
            start_time=records[0].timestamp,
            end_time=records[-1].timestamp,
            request_count=len(records),
            total_cost=round(total_cost, 8),
            models_used=models,
            error_count=errors,
            file_path=str(latest_path),
            file_size_bytes=latest_path.stat().st_size if latest_path.exists() else 0,
        )

    def delete_session(self, session_id: str) -> bool:
        self.close_session(session_id)
        deleted = False
        for path in self._iter_session_files():
            if self._session_id_from_file(path) == session_id:
                try:
                    path.unlink()
                    deleted = True
                except OSError:
                    pass
        with self._lock:
            self._index.pop(session_id, None)
            self._save_index()
        return deleted

    def cleanup(self, max_age_days: int = 30) -> int:
        self.close_all()
        ttl = max(1, int(max_age_days)) * 86400
        now = time.time()
        deleted = 0
        for path in self._iter_session_files():
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            if (now - mtime) > ttl:
                try:
                    path.unlink()
                    deleted += 1
                except OSError:
                    pass
        remaining_sids = {self._session_id_from_file(p) for p in self._iter_session_files()}
        with self._lock:
            self._index = {k: v for k, v in self._index.items() if k in remaining_sids}
            self._save_index()
        return deleted

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            active = len(self._writers)
            total_recorded = int(self._total_recorded)
        size = 0
        for path in self._iter_session_files():
            try:
                size += int(path.stat().st_size)
            except OSError:
                continue
        return {
            "active_sessions": active,
            "total_recorded": total_recorded,
            "storage_size_bytes": size,
        }
