"""Policy synchronization primitives for multi-node deployments."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

def _get_httpx():
    try:
        import httpx

        return httpx
    except ImportError:
        raise ImportError(
            "httpx is required for policy sync. "
            "Install with: pip install orchesis[integrations]"
        ) from None


class _LazyHttpx:
    def __getattr__(self, name: str) -> Any:
        return getattr(_get_httpx(), name)


httpx = _LazyHttpx()


def _now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class SyncStatus:
    """Synchronization status of one enforcement node."""

    node_id: str
    policy_version: str
    last_sync: str
    in_sync: bool
    latency_ms: float


class PolicySyncClient:
    """Enforcement node that pulls policy updates from control plane."""

    def __init__(
        self,
        control_url: str,
        api_token: str,
        node_id: str | None = None,
        poll_interval_seconds: int = 30,
    ) -> None:
        self._control_url = control_url.rstrip("/")
        self._token = api_token
        self._node_id = node_id or f"node-{uuid.uuid4().hex[:8]}"
        self._poll_interval = max(1, int(poll_interval_seconds))
        self._current_version: str | None = None
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._status = SyncStatus(
            node_id=self._node_id,
            policy_version="unknown",
            last_sync=_now_iso(),
            in_sync=False,
            latency_ms=0.0,
        )
        self._latest_policy: dict[str, Any] | None = None
        self._pending_version: str | None = None

    def _headers(self) -> dict[str, str]:
        """Build authorization headers for control-plane requests."""
        return {"Authorization": f"Bearer {self._token}"}

    def check_for_update(self) -> tuple[bool, dict[str, Any] | None]:
        """Check control plane for new policy version."""
        response = httpx.get(
            f"{self._control_url}/api/v1/policy",
            headers=self._headers(),
            timeout=10.0,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            return False, None
        remote_version = payload.get("version_id")
        if not isinstance(remote_version, str) or not remote_version:
            return False, None
        with self._lock:
            if self._current_version == remote_version:
                return False, None
        yaml_content = payload.get("yaml_content")
        if not isinstance(yaml_content, str):
            return False, None
        import yaml

        parsed = yaml.safe_load(yaml_content)
        policy = parsed if isinstance(parsed, dict) else {"rules": []}
        self._pending_version = remote_version
        return True, policy

    def sync_once(self) -> SyncStatus:
        """Pull latest policy if changed and return sync status."""
        started = time.perf_counter()
        in_sync = False
        policy_changed = False
        policy_version = self._current_version or "unknown"
        self._latest_policy = None
        try:
            heartbeat = httpx.post(
                f"{self._control_url}/api/v1/nodes/heartbeat",
                headers=self._headers(),
                json={
                    "node_id": self._node_id,
                    "policy_version": self._current_version or "unknown",
                },
                timeout=10.0,
            )
            heartbeat.raise_for_status()
            heartbeat_payload = heartbeat.json()
            if isinstance(heartbeat_payload, dict):
                in_sync = bool(heartbeat_payload.get("in_sync", False))
                policy_changed = bool(heartbeat_payload.get("policy_changed", False))
                remote_version = heartbeat_payload.get("current_version")
                if isinstance(remote_version, str) and remote_version:
                    policy_version = remote_version
        except Exception:
            # Fail-soft: keep current policy and try direct pull fallback.
            in_sync = False

        try:
            has_update, policy = self.check_for_update()
        except Exception:
            has_update, policy = False, None
        if has_update and isinstance(policy, dict):
            self._latest_policy = policy
            with self._lock:
                if isinstance(self._pending_version, str):
                    self._current_version = self._pending_version
                    policy_version = self._current_version
            in_sync = True
            policy_changed = True
        elif policy_changed:
            # Heartbeat indicates change; mark out-of-sync if pull failed.
            in_sync = False

        latency_ms = max(0.0, (time.perf_counter() - started) * 1000.0)
        status = SyncStatus(
            node_id=self._node_id,
            policy_version=policy_version,
            last_sync=_now_iso(),
            in_sync=in_sync,
            latency_ms=latency_ms,
        )
        with self._lock:
            self._status = status
        return status

    def start_background_sync(self, on_update: Callable[[dict[str, Any]], None]) -> None:
        """Start daemon thread polling control plane for policy changes."""
        if self._running:
            return
        self._running = True

        def _worker() -> None:
            while self._running:
                before = self._current_version
                self.sync_once()
                after = self._current_version
                if before != after and isinstance(self._latest_policy, dict):
                    try:
                        on_update(self._latest_policy)
                    except Exception:
                        pass
                time.sleep(self._poll_interval)

        self._thread = threading.Thread(target=_worker, name=f"sync-{self._node_id}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop background synchronization thread."""
        self._running = False
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    @property
    def node_id(self) -> str:
        """Node identifier used in heartbeats."""
        return self._node_id

    @property
    def current_version(self) -> str | None:
        """Current local policy version."""
        return self._current_version

    @property
    def latest_policy(self) -> dict[str, Any] | None:
        """Latest downloaded policy payload."""
        return self._latest_policy

    @property
    def status(self) -> SyncStatus:
        """Most recently observed synchronization status."""
        with self._lock:
            return self._status


class PolicySyncServer:
    """Control-plane side tracker for connected enforcement nodes."""

    def __init__(self) -> None:
        self._nodes: dict[str, SyncStatus] = {}
        self._current_version: str = ""
        self._force_sync: dict[str, bool] = {}
        self._lock = threading.Lock()

    def set_current_version(self, policy_version: str) -> None:
        """Update active control-plane policy version."""
        with self._lock:
            self._current_version = policy_version
            for node_id, status in list(self._nodes.items()):
                self._nodes[node_id] = SyncStatus(
                    node_id=status.node_id,
                    policy_version=status.policy_version,
                    last_sync=status.last_sync,
                    in_sync=(status.policy_version == self._current_version),
                    latency_ms=status.latency_ms,
                )

    def register_node(self, node_id: str, policy_version: str, latency_ms: float = 0.0) -> None:
        """Register or update a node synchronization status."""
        with self._lock:
            self._nodes[node_id] = SyncStatus(
                node_id=node_id,
                policy_version=policy_version,
                last_sync=_now_iso(),
                in_sync=(policy_version == self._current_version),
                latency_ms=max(0.0, float(latency_ms)),
            )

    def get_nodes(self) -> list[SyncStatus]:
        """List known nodes and their synchronization state."""
        with self._lock:
            return sorted(self._nodes.values(), key=lambda item: item.node_id)

    def get_out_of_sync(self) -> list[SyncStatus]:
        """Return nodes that are not on current policy version."""
        with self._lock:
            return sorted(
                [item for item in self._nodes.values() if not item.in_sync],
                key=lambda item: item.node_id,
            )

    def request_force_sync(self, node_id: str) -> None:
        """Mark node to force policy pull on next heartbeat."""
        with self._lock:
            self._force_sync[node_id] = True

    def consume_force_sync(self, node_id: str) -> bool:
        """Consume force-sync flag for node, if present."""
        with self._lock:
            return bool(self._force_sync.pop(node_id, False))
