#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for core/scan_pool.py

Tests ScanTask, ScanResult, and ScanWorkerPool.
All tests are self-contained using only stdlib + pytest.
"""

import importlib.util
import os
import sys
import time
import threading


# Load scan_pool directly from file to avoid core/__init__.py
# which triggers yaml/requests dependencies
_spec = importlib.util.spec_from_file_location(
    "scan_pool",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "scan_pool.py"),
)
_scan_pool = importlib.util.module_from_spec(_spec)
sys.modules["scan_pool"] = _scan_pool
_spec.loader.exec_module(_scan_pool)

ScanTask = _scan_pool.ScanTask
ScanResult = _scan_pool.ScanResult
ScanWorkerPool = _scan_pool.ScanWorkerPool


# ── ScanTask Tests ────────────────────────────────────────────────────


class TestScanTask:
    """Tests for ScanTask dataclass."""

    def test_default_fields(self) -> None:
        task = ScanTask(module_name="xss", url="http://example.com")
        assert task.module_name == "xss"
        assert task.url == "http://example.com"
        assert task.method == "GET"
        assert task.param == ""
        assert task.value == ""
        assert task.priority == 0

    def test_custom_fields(self) -> None:
        task = ScanTask(
            module_name="sqli",
            url="http://target.com/login",
            method="POST",
            param="username",
            value="' OR 1=1--",
            priority=1,
        )
        assert task.module_name == "sqli"
        assert task.url == "http://target.com/login"
        assert task.method == "POST"
        assert task.param == "username"
        assert task.value == "' OR 1=1--"
        assert task.priority == 1


# ── ScanResult Tests ──────────────────────────────────────────────────


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_default_fields(self) -> None:
        task = ScanTask(module_name="test", url="http://x.com")
        result = ScanResult(task=task, success=True)
        assert result.task is task
        assert result.success is True
        assert result.error is None
        assert result.duration_ms == 0.0
        assert result.findings_count == 0

    def test_failed_result(self) -> None:
        task = ScanTask(module_name="test", url="http://x.com")
        result = ScanResult(
            task=task,
            success=False,
            error="Connection refused",
            duration_ms=123.4,
        )
        assert result.success is False
        assert result.error == "Connection refused"
        assert result.duration_ms == 123.4


# ── ScanWorkerPool Tests ──────────────────────────────────────────────


class TestScanWorkerPool:
    """Tests for ScanWorkerPool."""

    def _make_executor(self, delay: float = 0.0, fail: bool = False) -> "callable":
        """Create a simple executor function for testing."""

        def executor_fn(task: ScanTask) -> ScanResult:
            if delay > 0:
                time.sleep(delay)
            if fail:
                raise RuntimeError("Module crashed")
            return ScanResult(
                task=task,
                success=True,
                findings_count=1,
            )

        return executor_fn

    def test_init(self) -> None:
        pool = ScanWorkerPool(max_workers=5)
        assert pool.total_tasks == 0
        assert pool.completed_tasks == 0
        assert pool.failed_tasks == 0

    def test_submit_tasks(self) -> None:
        pool = ScanWorkerPool(max_workers=5)
        tasks = [
            ScanTask(module_name="xss", url="http://a.com"),
            ScanTask(module_name="sqli", url="http://b.com"),
        ]
        pool.submit_tasks(tasks)
        assert pool.total_tasks == 2

    def test_execute_all_simple(self) -> None:
        pool = ScanWorkerPool(
            max_workers=5,
            executor_fn=self._make_executor(),
        )
        tasks = [
            ScanTask(module_name="xss", url="http://a.com"),
            ScanTask(module_name="sqli", url="http://b.com"),
            ScanTask(module_name="lfi", url="http://c.com"),
        ]
        pool.submit_tasks(tasks)
        results = pool.execute_all()
        assert len(results) == 3
        assert all(r.success for r in results)
        assert pool.completed_tasks == 3
        assert pool.failed_tasks == 0

    def test_error_isolation(self) -> None:
        """One failing task does not crash others."""
        call_count = {"value": 0}
        lock = threading.Lock()

        def mixed_executor(task: ScanTask) -> ScanResult:
            with lock:
                call_count["value"] += 1
            if task.module_name == "crasher":
                raise RuntimeError("Module crashed!")
            return ScanResult(task=task, success=True, findings_count=1)

        pool = ScanWorkerPool(max_workers=5, executor_fn=mixed_executor)
        tasks = [
            ScanTask(module_name="xss", url="http://a.com"),
            ScanTask(module_name="crasher", url="http://b.com"),
            ScanTask(module_name="sqli", url="http://c.com"),
        ]
        pool.submit_tasks(tasks)
        results = pool.execute_all()
        assert len(results) == 3
        # Two should succeed, one should fail
        successes = [r for r in results if r.success]
        failures = [r for r in results if not r.success]
        assert len(successes) == 2
        assert len(failures) == 1
        assert "Module crashed" in failures[0].error
        assert pool.failed_tasks == 1

    def test_progress_callback(self) -> None:
        """Progress callback is invoked for each completed task."""
        callback_results: list[ScanResult] = []

        def on_progress(result: ScanResult) -> None:
            callback_results.append(result)

        pool = ScanWorkerPool(
            max_workers=5,
            executor_fn=self._make_executor(),
            progress_callback=on_progress,
        )
        tasks = [ScanTask(module_name=f"mod{i}", url=f"http://t{i}.com") for i in range(4)]
        pool.submit_tasks(tasks)
        pool.execute_all()
        assert len(callback_results) == 4

    def test_priority_ordering(self) -> None:
        """Tasks with lower priority value execute first (verified by result order tracking)."""
        execution_order: list[str] = []
        lock = threading.Lock()

        def tracking_executor(task: ScanTask) -> ScanResult:
            with lock:
                execution_order.append(task.module_name)
            return ScanResult(task=task, success=True)

        # Use single worker to guarantee sequential execution
        pool = ScanWorkerPool(max_workers=1, executor_fn=tracking_executor)
        tasks = [
            ScanTask(module_name="low_priority", url="http://a.com", priority=10),
            ScanTask(module_name="high_priority", url="http://b.com", priority=0),
            ScanTask(module_name="medium_priority", url="http://c.com", priority=5),
        ]
        pool.submit_tasks(tasks)
        pool.execute_all()
        # With max_workers=1, execution order follows priority sort
        assert execution_order == ["high_priority", "medium_priority", "low_priority"]

    def test_execute_all_empty(self) -> None:
        """execute_all with no tasks returns empty list."""
        pool = ScanWorkerPool(max_workers=5)
        results = pool.execute_all()
        assert results == []

    def test_duration_recorded(self) -> None:
        """Duration is recorded for completed tasks."""

        def slow_executor(task: ScanTask) -> ScanResult:
            time.sleep(0.05)
            return ScanResult(task=task, success=True)

        pool = ScanWorkerPool(max_workers=2, executor_fn=slow_executor)
        tasks = [ScanTask(module_name="slow", url="http://a.com")]
        pool.submit_tasks(tasks)
        results = pool.execute_all()
        assert len(results) == 1
        # Duration should be at least 50ms
        assert results[0].duration_ms >= 40.0

    def test_shutdown(self) -> None:
        """Shutdown prevents further task execution."""
        pool = ScanWorkerPool(max_workers=5, executor_fn=self._make_executor())
        pool.shutdown()
        tasks = [ScanTask(module_name="xss", url="http://a.com")]
        pool.submit_tasks(tasks)
        # execute_all should return empty or partial since shutdown was called
        results = pool.execute_all()
        # After shutdown, no new tasks are dispatched
        assert len(results) == 0

    def test_concurrent_execution_is_faster(self) -> None:
        """Multiple workers execute faster than sequential."""

        def slow_fn(task: ScanTask) -> ScanResult:
            time.sleep(0.05)
            return ScanResult(task=task, success=True)

        pool = ScanWorkerPool(max_workers=5, executor_fn=slow_fn)
        tasks = [ScanTask(module_name=f"m{i}", url=f"http://t{i}.com") for i in range(5)]
        pool.submit_tasks(tasks)
        start = time.monotonic()
        results = pool.execute_all()
        elapsed = time.monotonic() - start
        assert len(results) == 5
        # 5 tasks at 50ms each sequential would be 250ms
        # With 5 workers they should complete in roughly 50-100ms
        assert elapsed < 0.2
