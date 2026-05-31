#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for utils/async_requester.py

Tests ConnectionPool, RateLimiter, and AsyncRequestDispatcher.
All tests are self-contained using only stdlib + pytest.
"""

import threading
import time

import pytest

from utils.async_requester import (
    AsyncRequestDispatcher,
    ConnectionPool,
    RateLimiter,
)

from utils.exceptions import ConnectionTimeoutError, NetworkError


# ── ConnectionPool Tests ──────────────────────────────────────────────


class TestConnectionPool:
    """Tests for ConnectionPool."""

    def test_init_default(self) -> None:
        pool = ConnectionPool()
        assert pool.available == 10
        assert pool.in_use == 0

    def test_init_custom(self) -> None:
        pool = ConnectionPool(max_connections=5, timeout=10.0)
        assert pool.available == 5
        assert pool.in_use == 0

    def test_acquire_returns_object(self) -> None:
        pool = ConnectionPool(max_connections=3)
        conn = pool.acquire()
        assert conn is not None
        assert pool.in_use == 1
        assert pool.available == 2

    def test_release_returns_slot(self) -> None:
        pool = ConnectionPool(max_connections=3)
        conn = pool.acquire()
        assert pool.in_use == 1
        pool.release(conn)
        assert pool.in_use == 0
        assert pool.available == 3

    def test_acquire_blocks_when_exhausted_and_raises_on_timeout(self) -> None:
        pool = ConnectionPool(max_connections=1, timeout=0.1)
        conn = pool.acquire()
        assert pool.in_use == 1
        with pytest.raises(ConnectionTimeoutError):
            pool.acquire()
        pool.release(conn)

    def test_acquire_unblocks_after_release(self) -> None:
        pool = ConnectionPool(max_connections=1, timeout=2.0)
        conn = pool.acquire()
        released = threading.Event()

        def releaser() -> None:
            time.sleep(0.1)
            pool.release(conn)
            released.set()

        t = threading.Thread(target=releaser)
        t.start()
        # Should not raise - the release happens before timeout
        conn2 = pool.acquire()
        assert conn2 is not None
        t.join()
        assert released.is_set()
        pool.release(conn2)

    def test_available_and_in_use_properties(self) -> None:
        pool = ConnectionPool(max_connections=5)
        conns = [pool.acquire() for _ in range(3)]
        assert pool.in_use == 3
        assert pool.available == 2
        for c in conns:
            pool.release(c)
        assert pool.in_use == 0
        assert pool.available == 5

    def test_close_all(self) -> None:
        pool = ConnectionPool(max_connections=5)
        pool.acquire()
        pool.close_all()
        with pytest.raises(NetworkError):
            pool.acquire()

    def test_connection_reuse(self) -> None:
        pool = ConnectionPool(max_connections=2)
        conn1 = pool.acquire()
        pool.release(conn1)
        conn2 = pool.acquire()
        # Should get back the same connection object
        assert conn2 is conn1
        pool.release(conn2)


# ── RateLimiter Tests ─────────────────────────────────────────────────


class TestRateLimiter:
    """Tests for RateLimiter."""

    def test_init_default(self) -> None:
        rl = RateLimiter()
        assert rl.tokens <= 20.0

    def test_try_acquire_succeeds_up_to_burst(self) -> None:
        rl = RateLimiter(rate=100.0, burst=5)
        results = [rl.try_acquire() for _ in range(5)]
        assert all(results)

    def test_try_acquire_fails_after_burst_exhausted(self) -> None:
        rl = RateLimiter(rate=0.1, burst=3)
        # Exhaust burst
        for _ in range(3):
            assert rl.try_acquire()
        # Should fail now - rate is very slow so no refill yet
        assert not rl.try_acquire()

    def test_acquire_blocks_and_succeeds_after_refill(self) -> None:
        # Rate of 100/s means tokens refill fast
        rl = RateLimiter(rate=100.0, burst=1)
        assert rl.try_acquire()
        # After exhaustion, acquire with timeout should succeed quickly
        # because rate=100 means 1 token per 0.01s
        result = rl.acquire(timeout=1.0)
        assert result is True

    def test_acquire_returns_false_on_timeout(self) -> None:
        rl = RateLimiter(rate=0.01, burst=1)
        assert rl.try_acquire()  # exhaust
        result = rl.acquire(timeout=0.05)
        assert result is False

    def test_tokens_property(self) -> None:
        rl = RateLimiter(rate=10.0, burst=10)
        initial = rl.tokens
        assert initial <= 10.0
        rl.try_acquire()
        assert rl.tokens < initial

    def test_reset(self) -> None:
        rl = RateLimiter(rate=10.0, burst=5)
        for _ in range(5):
            rl.try_acquire()
        assert rl.tokens < 1.0
        rl.reset()
        assert rl.tokens == 5.0


# ── AsyncRequestDispatcher Tests ──────────────────────────────────────


class TestAsyncRequestDispatcher:
    """Tests for AsyncRequestDispatcher."""

    def test_init(self) -> None:
        dispatcher = AsyncRequestDispatcher(max_workers=5)
        assert dispatcher.pending_count == 0
        assert dispatcher.completed_count == 0
        dispatcher.shutdown()

    def test_submit_runs_callable(self) -> None:
        dispatcher = AsyncRequestDispatcher(max_workers=2)
        future = dispatcher.submit(lambda x: x * 2, 5)
        result = future.result(timeout=5.0)
        assert result == 10
        dispatcher.shutdown()

    def test_batch_submit_runs_multiple(self) -> None:
        dispatcher = AsyncRequestDispatcher(max_workers=4)
        tasks = [
            (lambda x: x * 2, (1,), {}),
            (lambda x: x * 3, (2,), {}),
            (lambda x: x + 10, (3,), {}),
        ]
        futures = dispatcher.batch_submit(tasks)
        results = [f.result(timeout=5.0) for f in futures]
        assert results == [2, 6, 13]
        dispatcher.shutdown()

    def test_map_yields_results_in_order(self) -> None:
        dispatcher = AsyncRequestDispatcher(max_workers=4)
        results = list(dispatcher.map(lambda x: x ** 2, [1, 2, 3, 4]))
        assert results == [1, 4, 9, 16]
        dispatcher.shutdown()

    def test_shutdown_prevents_new_submissions(self) -> None:
        dispatcher = AsyncRequestDispatcher(max_workers=2)
        dispatcher.shutdown()
        with pytest.raises(RuntimeError):
            dispatcher.submit(lambda: None)

    def test_completed_count_increments(self) -> None:
        dispatcher = AsyncRequestDispatcher(max_workers=4)
        futures = [dispatcher.submit(lambda: time.sleep(0.01)) for _ in range(5)]
        for f in futures:
            f.result(timeout=5.0)
        # Allow a moment for counter updates
        time.sleep(0.05)
        assert dispatcher.completed_count == 5
        dispatcher.shutdown()

    def test_with_rate_limiter(self) -> None:
        rl = RateLimiter(rate=1000.0, burst=100)
        dispatcher = AsyncRequestDispatcher(max_workers=4, rate_limiter=rl)
        future = dispatcher.submit(lambda: 42)
        assert future.result(timeout=5.0) == 42
        dispatcher.shutdown()

    def test_with_connection_pool(self) -> None:
        pool = ConnectionPool(max_connections=5)
        dispatcher = AsyncRequestDispatcher(max_workers=4, pool=pool)
        future = dispatcher.submit(lambda: "hello")
        assert future.result(timeout=5.0) == "hello"
        dispatcher.shutdown()
        pool.close_all()
