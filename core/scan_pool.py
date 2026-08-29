#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Concurrent scan worker pool with error isolation and priority scheduling.

Uses concurrent.futures.ThreadPoolExecutor for bounded concurrency.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class ScanTask:
    """Represents a single scan task to be executed by the worker pool."""

    module_name: str
    url: str
    method: str = "GET"
    param: str = ""
    value: str = ""
    priority: int = 0  # lower = higher priority


@dataclass
class ScanResult:
    """Result of executing a single scan task."""

    task: ScanTask
    success: bool
    error: Optional[str] = None
    duration_ms: float = 0.0
    findings_count: int = 0


class ScanWorkerPool:
    """Concurrent module execution pool with error isolation.

    Executes scan tasks with bounded concurrency. One module crash
    does not affect other tasks. Tasks are sorted by priority before
    execution (lower priority value = executed first).
    """

    def __init__(
        self,
        max_workers: int = 10,
        rate_limiter: Optional[object] = None,
        progress_callback: Optional[Callable[[ScanResult], None]] = None,
        executor_fn: Optional[Callable[[ScanTask], ScanResult]] = None,
    ) -> None:
        self._max_workers = max_workers
        self._rate_limiter = rate_limiter
        self._progress_callback = progress_callback
        self._executor_fn = executor_fn
        self._lock = threading.Lock()
        self._tasks: list[ScanTask] = []
        self._results: list[ScanResult] = []
        self._total: int = 0
        self._completed: int = 0
        self._failed: int = 0
        self._shutdown: bool = False

    def submit_tasks(self, tasks: list[ScanTask]) -> None:
        """Add tasks to the pool queue.

        Tasks are accumulated until execute_all() is called.
        """
        with self._lock:
            self._tasks.extend(tasks)
            self._total += len(tasks)

    def _execute_single(self, task: ScanTask) -> ScanResult:
        """Execute a single task with error isolation."""
        start = time.monotonic()

        # Honour rate limiter if attached
        if self._rate_limiter is not None:
            try:
                acquire = getattr(self._rate_limiter, "acquire", None)
                if acquire is not None:
                    acquire()
            except Exception as exc:
                logger.warning("Rate limiter error: %s", exc)

        try:
            if self._executor_fn is not None:
                result = self._executor_fn(task)
            else:
                # Default no-op execution when no executor_fn is provided
                result = ScanResult(
                    task=task,
                    success=True,
                    duration_ms=(time.monotonic() - start) * 1000,
                )
            # Ensure duration is set if executor_fn didn't set it
            if result.duration_ms == 0.0:
                result.duration_ms = (time.monotonic() - start) * 1000
            return result
        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000
            return ScanResult(
                task=task,
                success=False,
                error=str(exc),
                duration_ms=duration_ms,
            )

    def execute_all(self, timeout: Optional[float] = None) -> list[ScanResult]:
        """Execute all submitted tasks with bounded concurrency.

        Tasks are sorted by priority (lower value = higher priority)
        before execution. Returns a list of ScanResult objects.

        Args:
            timeout: Maximum time in seconds to wait for all tasks.
                     None means wait indefinitely.
        """
        with self._lock:
            tasks = sorted(self._tasks, key=lambda t: t.priority)
            self._tasks = []

        if not tasks:
            return []

        results: list[ScanResult] = []
        futures: dict[Future[ScanResult], ScanTask] = {}

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            for task in tasks:
                if self._shutdown:
                    break
                future = executor.submit(self._execute_single, task)
                futures[future] = task

            for future in as_completed(futures, timeout=timeout):
                try:
                    result = future.result()
                except Exception as exc:
                    task = futures[future]
                    result = ScanResult(
                        task=task,
                        success=False,
                        error=str(exc),
                    )

                results.append(result)
                with self._lock:
                    self._results.append(result)
                    self._completed += 1
                    if not result.success:
                        self._failed += 1

                if self._progress_callback is not None:
                    try:
                        self._progress_callback(result)
                    except Exception:
                        pass

        return results

    def shutdown(self) -> None:
        """Signal the pool to stop accepting new work."""
        self._shutdown = True

    @property
    def total_tasks(self) -> int:
        """Total number of tasks submitted."""
        with self._lock:
            return self._total

    @property
    def completed_tasks(self) -> int:
        """Number of tasks that have completed."""
        with self._lock:
            return self._completed

    @property
    def failed_tasks(self) -> int:
        """Number of tasks that failed."""
        with self._lock:
            return self._failed
