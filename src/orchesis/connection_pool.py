"""Thread-safe upstream HTTP connection pooling."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import http.client
import ssl
import threading
import time
from typing import Any


class ConnectionPoolExhausted(Exception):
    """Raised when acquire() times out while the pool is at capacity."""


@dataclass
class PoolConfig:
    max_connections_per_host: int = 10
    max_total_connections: int = 50
    connection_timeout: float = 30.0
    idle_timeout: float = 60.0
    retry_on_connection_error: bool = True
    max_retries: int = 2


class PooledConnection:
    """Wrap http.client connection with pool metadata."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        use_ssl: bool = True,
        timeout: float = 30.0,
        idle_timeout: float = 60.0,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.use_ssl = bool(use_ssl)
        self._idle_timeout = max(0.01, float(idle_timeout))
        self.created_at = time.monotonic()
        self.last_used = self.created_at
        self.in_use = False
        self.request_count = 0
        if self.use_ssl:
            context = ssl.create_default_context()
            self._conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                self.host,
                self.port,
                timeout=timeout,
                context=context,
            )
        else:
            self._conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)

    @property
    def conn(self) -> http.client.HTTPConnection:
        return self._conn

    @property
    def is_idle_expired(self) -> bool:
        return (time.monotonic() - self.last_used) > self._idle_timeout

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


class ConnectionPool:
    """Bounded, thread-safe host-keyed HTTP connection pool."""

    def __init__(self, config: PoolConfig | None = None) -> None:
        self._config = config if isinstance(config, PoolConfig) else PoolConfig()
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._pools: dict[tuple[str, int], list[PooledConnection]] = defaultdict(list)
        self._total_connections = 0
        self._stats: dict[str, Any] = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "errors": 0,
            "active": 0,
            "waits": 0,
            "pool_overflow_count": 0,
        }

    def acquire(self, host: str, port: int = 443, use_ssl: bool = True) -> PooledConnection:
        host_key = str(host).strip()
        if not host_key:
            raise ValueError("host is required")
        key = (host_key, int(port))
        deadline = time.monotonic() + max(0.5, self._config.connection_timeout)
        with self._cond:
            while True:
                self._evict_expired_locked(key)
                pool = self._pools[key]
                for pc in pool:
                    if not pc.in_use and not pc.is_idle_expired:
                        pc.in_use = True
                        pc.last_used = time.monotonic()
                        self._stats["hits"] += 1
                        self._stats["active"] += 1
                        return pc
                if len(pool) < self._config.max_connections_per_host and self._total_connections < self._config.max_total_connections:
                    created = PooledConnection(
                        host=host_key,
                        port=port,
                        use_ssl=use_ssl,
                        timeout=self._config.connection_timeout,
                        idle_timeout=self._config.idle_timeout,
                    )
                    created.in_use = True
                    pool.append(created)
                    self._total_connections += 1
                    self._stats["misses"] += 1
                    self._stats["active"] += 1
                    return created
                now = time.monotonic()
                remaining = deadline - now
                if remaining <= 0:
                    at_host_cap = len(pool) >= self._config.max_connections_per_host
                    at_total_cap = self._total_connections >= self._config.max_total_connections
                    if at_host_cap or at_total_cap:
                        self._stats["pool_overflow_count"] = int(self._stats["pool_overflow_count"]) + 1
                        raise ConnectionPoolExhausted(
                            f"connection pool exhausted for {host_key}:{int(port)} "
                            f"(per_host_cap={at_host_cap}, total_cap={at_total_cap})"
                        )
                    created = PooledConnection(
                        host=host_key,
                        port=port,
                        use_ssl=use_ssl,
                        timeout=self._config.connection_timeout,
                        idle_timeout=self._config.idle_timeout,
                    )
                    created.in_use = True
                    pool.append(created)
                    self._total_connections += 1
                    self._stats["misses"] += 1
                    self._stats["active"] += 1
                    return created
                self._stats["waits"] += 1
                self._cond.wait(timeout=min(0.05, remaining))

    def release(self, pooled_connection: PooledConnection, error: bool = False) -> None:
        with self._cond:
            pooled_connection.in_use = False
            pooled_connection.last_used = time.monotonic()
            pooled_connection.request_count += 1
            self._stats["active"] = max(0, int(self._stats["active"]) - 1)
            if error:
                self._remove_connection_locked(pooled_connection)
                self._stats["errors"] += 1
            else:
                self._evict_expired_locked((pooled_connection.host, pooled_connection.port))
            self._cond.notify()

    def _evict_expired_locked(self, key: tuple[str, int] | None = None) -> None:
        keys = [key] if key is not None else list(self._pools.keys())
        for item in keys:
            pool = self._pools.get(item, [])
            expired = [pc for pc in pool if not pc.in_use and pc.is_idle_expired]
            for pc in expired:
                pc.close()
                pool.remove(pc)
                self._total_connections = max(0, self._total_connections - 1)
                self._stats["evictions"] += 1
            if not pool and item in self._pools:
                self._pools.pop(item, None)

    def _remove_connection_locked(self, pooled_connection: PooledConnection) -> None:
        key = (pooled_connection.host, pooled_connection.port)
        pool = self._pools.get(key, [])
        if pooled_connection in pool:
            pooled_connection.close()
            pool.remove(pooled_connection)
            self._total_connections = max(0, self._total_connections - 1)
        if not pool:
            self._pools.pop(key, None)

    def close_all(self) -> None:
        with self._cond:
            for pool in self._pools.values():
                for pc in pool:
                    pc.close()
            self._pools.clear()
            self._total_connections = 0
            self._stats["active"] = 0
            self._cond.notify_all()

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            self._evict_expired_locked(None)
            return {
                **self._stats,
                "total_connections": int(self._total_connections),
                "pools": {f"{host}:{port}": len(pool) for (host, port), pool in self._pools.items()},
            }

