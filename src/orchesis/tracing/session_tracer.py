"""
SessionTracer - SQLite-backed session and request tracing.

Stores per-request traces with session correlation,
tool calls, costs, timings, and security findings.

Usage:
    tracer = SessionTracer(db_path="~/.orchesis/traces.db")
    tracer.start_session(agent_id="agent-1", metadata={"framework": "paperclip"})
    tracer.record_request(session_id, request_data)
    tracer.record_response(session_id, request_id, response_data)
    timeline = tracer.get_session_timeline(session_id)
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from orchesis.utils.log import get_logger

logger = get_logger(__name__)


@dataclass
class TraceEvent:
    event_id: str = ""
    session_id: str = ""
    request_id: str = ""
    event_type: str = ""
    timestamp: float = 0.0
    agent_id: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionSummary:
    session_id: str = ""
    agent_id: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    request_count: int = 0
    tool_call_count: int = 0
    total_cost_usd: float = 0.0
    security_findings: int = 0
    error_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    start_time REAL NOT NULL,
    end_time REAL,
    metadata TEXT DEFAULT '{}',
    status TEXT DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    request_id TEXT DEFAULT '',
    event_type TEXT NOT NULL,
    timestamp REAL NOT NULL,
    agent_id TEXT DEFAULT '',
    data TEXT DEFAULT '{}',
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id);
"""


class SessionTracer:
    """
    SQLite-backed session tracer for Orchesis.

    Thread-safe. Uses WAL mode for concurrent reads.
    DB path default: ~/.orchesis/traces.db
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_dir = Path.home() / ".orchesis"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "traces.db")

        self.db_path = str(Path(db_path).expanduser())
        self._local = threading.local()
        self._init_db()
        logger.info(
            "SessionTracer initialized",
            extra={"component": "tracer", "db_path": self.db_path},
        )

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local SQLite connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self) -> None:
        """Create tables and indexes if missing."""
        conn = self._get_conn()
        conn.executescript(SCHEMA)
        conn.commit()

    def start_session(self, agent_id: str, metadata: Optional[dict[str, Any]] = None) -> str:
        """Start a new tracing session and return session_id."""
        session_id = f"sess-{uuid.uuid4().hex[:12]}"
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO sessions (session_id, agent_id, start_time, metadata) VALUES (?, ?, ?, ?)",
            (session_id, str(agent_id), now, json.dumps(metadata or {})),
        )
        conn.commit()
        logger.info(
            "Session started",
            extra={"component": "tracer", "session_id": session_id, "agent_id": agent_id},
        )
        return session_id

    def end_session(self, session_id: str) -> None:
        """Mark session as ended."""
        conn = self._get_conn()
        conn.execute(
            "UPDATE sessions SET end_time = ?, status = 'ended' WHERE session_id = ?",
            (time.time(), session_id),
        )
        conn.commit()

    def record_event(
        self,
        session_id: str,
        event_type: str,
        data: Optional[dict[str, Any]] = None,
        request_id: str = "",
        agent_id: str = "",
    ) -> str:
        """Record a trace event and return event_id."""
        event_id = f"evt-{uuid.uuid4().hex[:12]}"
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO events (event_id, session_id, request_id, event_type, timestamp, agent_id, data) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                session_id,
                request_id,
                event_type,
                time.time(),
                agent_id,
                json.dumps(data or {}),
            ),
        )
        conn.commit()
        return event_id

    def record_request(self, session_id: str, request_data: dict[str, Any]) -> str:
        """Record an incoming request and return request_id."""
        request_id = f"req-{uuid.uuid4().hex[:12]}"
        self.record_event(
            session_id,
            "request",
            request_data,
            request_id=request_id,
            agent_id=str(request_data.get("agent_id", "")),
        )
        return request_id

    def record_response(self, session_id: str, request_id: str, response_data: dict[str, Any]) -> None:
        """Record a response for a request."""
        self.record_event(
            session_id,
            "response",
            response_data,
            request_id=request_id,
        )

    def record_tool_call(
        self,
        session_id: str,
        request_id: str,
        tool_name: str,
        args: dict[str, Any],
        result: Any = None,
    ) -> None:
        """Record a tool call within a request."""
        self.record_event(
            session_id,
            "tool_call",
            {
                "tool": tool_name,
                "args": args,
                "result": str(result)[:1000] if result is not None else None,
            },
            request_id=request_id,
        )

    def record_cost(
        self,
        session_id: str,
        request_id: str,
        cost_usd: float,
        tokens: Optional[dict[str, Any]] = None,
    ) -> None:
        """Record cost for a request."""
        self.record_event(
            session_id,
            "cost",
            {"cost_usd": float(cost_usd), "tokens": tokens or {}},
            request_id=request_id,
        )

    def record_security_finding(self, session_id: str, finding: dict[str, Any]) -> None:
        """Record a security finding."""
        self.record_event(session_id, "security_finding", finding)

    def get_session_timeline(self, session_id: str) -> list[TraceEvent]:
        """Get all events for a session ordered by time."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY timestamp",
            (session_id,),
        ).fetchall()
        return [
            TraceEvent(
                event_id=row["event_id"],
                session_id=row["session_id"],
                request_id=row["request_id"],
                event_type=row["event_type"],
                timestamp=float(row["timestamp"] or 0.0),
                agent_id=row["agent_id"],
                data=json.loads(row["data"]) if row["data"] else {},
            )
            for row in rows
        ]

    def get_session_summary(self, session_id: str) -> SessionSummary:
        """Get aggregated summary for a session."""
        conn = self._get_conn()
        session = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if not session:
            return SessionSummary(session_id=session_id)

        events = self.get_session_timeline(session_id)
        request_count = sum(1 for event in events if event.event_type == "request")
        tool_count = sum(1 for event in events if event.event_type == "tool_call")
        security_count = sum(1 for event in events if event.event_type == "security_finding")
        error_count = sum(1 for event in events if event.event_type == "error")
        total_cost = sum(float(event.data.get("cost_usd", 0.0) or 0.0) for event in events if event.event_type == "cost")

        return SessionSummary(
            session_id=session_id,
            agent_id=session["agent_id"],
            start_time=float(session["start_time"] or 0.0),
            end_time=float(session["end_time"] or 0.0),
            request_count=request_count,
            tool_call_count=tool_count,
            total_cost_usd=total_cost,
            security_findings=security_count,
            error_count=error_count,
            metadata=json.loads(session["metadata"]) if session["metadata"] else {},
        )

    def list_sessions(self, agent_id: Optional[str] = None, limit: int = 100) -> list[dict[str, Any]]:
        """List sessions, optionally filtered by agent_id."""
        safe_limit = max(1, int(limit))
        conn = self._get_conn()
        if agent_id:
            rows = conn.execute(
                "SELECT * FROM sessions WHERE agent_id = ? ORDER BY start_time DESC LIMIT ?",
                (agent_id, safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_session(self, session_id: str) -> None:
        """Delete a session and all associated events."""
        conn = self._get_conn()
        conn.execute("DELETE FROM events WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        conn.commit()

    def close(self) -> None:
        """Close thread-local database connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
