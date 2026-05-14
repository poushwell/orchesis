from __future__ import annotations

import pytest

from orchesis.connection_pool import ConnectionPool, ConnectionPoolExhausted, PoolConfig


def test_connection_pool_no_overflow_past_max() -> None:
    pool = ConnectionPool(
        PoolConfig(max_connections_per_host=1, max_total_connections=1, connection_timeout=0.15)
    )
    c1 = pool.acquire("example.com", 80, use_ssl=False)
    try:
        with pytest.raises(ConnectionPoolExhausted):
            pool.acquire("example.com", 80, use_ssl=False)
    finally:
        pool.release(c1)
        pool.close_all()
    stats = pool.get_stats()
    assert int(stats.get("pool_overflow_count", 0)) >= 1
