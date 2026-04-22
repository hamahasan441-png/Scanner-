#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Distributed Scan Worker Support
=========================================================

Provides a Redis-backed task queue so multiple machines can cooperate
on scanning a large target surface.

Roles:
  Controller:  Dispatches targets onto the queue.
               ``python main.py -t domain.com --distribute redis://host:6379``

  Worker:      Pulls targets from the queue and scans them.
               ``python main.py --worker redis://host:6379``

Queue protocol (JSON messages):
  Task:   {"target": "https://...", "config": {...}, "task_id": "..."}
  Result: {"task_id": "...", "target": "...", "findings_count": N,
           "findings": [...], "elapsed": F, "error": null}

Falls back gracefully when Redis is not available.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Dict, List, Optional

from config import Colors

logger = logging.getLogger(__name__)

TASK_QUEUE_KEY = "atomic:tasks"
RESULT_QUEUE_KEY = "atomic:results"
HEARTBEAT_KEY = "atomic:workers"
QUEUE_TIMEOUT = 30  # seconds to block-wait on queue pop


def _connect_redis(redis_url: str):
    """Connect to Redis and return a client instance."""
    try:
        import redis

        client = redis.from_url(redis_url, decode_responses=True)
        client.ping()
        return client
    except ImportError:
        raise RuntimeError("redis-py not installed. Run: pip install redis")
    except Exception as exc:
        raise RuntimeError(f"Cannot connect to Redis at {redis_url}: {exc}") from exc


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------


class DistributedController:
    """Pushes scan targets onto the Redis task queue and collects results."""

    def __init__(self, redis_url: str, config: dict):
        self.redis_url = redis_url
        self.config = config
        self.client = _connect_redis(redis_url)
        self.pending_tasks: Dict[str, str] = {}  # task_id → target

    def dispatch(self, targets: List[str]) -> List[str]:
        """Push *targets* onto the task queue.

        Returns a list of task IDs.
        """
        task_ids = []
        for target in targets:
            task_id = uuid.uuid4().hex[:12]
            task = json.dumps(
                {
                    "task_id": task_id,
                    "target": target,
                    "config": self.config,
                }
            )
            self.client.rpush(TASK_QUEUE_KEY, task)
            self.pending_tasks[task_id] = target
            task_ids.append(task_id)

        print(
            f"{Colors.info(f'[DISTRIBUTED] Dispatched {len(task_ids)} tasks to {self.redis_url}')}"
        )
        return task_ids

    def collect_results(
        self,
        task_ids: List[str],
        timeout: float = 3600,
    ) -> List[dict]:
        """Block until all tasks complete or *timeout* is reached."""
        remaining = set(task_ids)
        results = []
        deadline = time.time() + timeout

        print(f"{Colors.info(f'[DISTRIBUTED] Waiting for {len(remaining)} results ...')}")

        while remaining and time.time() < deadline:
            raw = self.client.blpop(RESULT_QUEUE_KEY, timeout=5)
            if not raw:
                continue
            _, msg = raw
            try:
                result = json.loads(msg)
                tid = result.get("task_id", "")
                if tid in remaining:
                    remaining.discard(tid)
                    results.append(result)
                    target = result.get("target", "?")
                    fc = result.get("findings_count", 0)
                    err = result.get("error")
                    status = f"{Colors.RED}FAIL{Colors.RESET}" if err else f"{Colors.GREEN} OK {Colors.RESET}"
                    print(
                        f"  [{status}] {target}  findings={fc}"
                        + (f"  error={err}" if err else "")
                    )
                    # Also push back any unrecognised results
                else:
                    self.client.rpush(RESULT_QUEUE_KEY, msg)
            except json.JSONDecodeError:
                pass

        if remaining:
            logger.warning(
                "[DISTRIBUTED] %d tasks timed out: %s",
                len(remaining),
                remaining,
            )

        return results

    def active_workers(self) -> int:
        """Return the number of currently active workers."""
        try:
            return self.client.scard(HEARTBEAT_KEY)
        except Exception:
            return 0


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------


class DistributedWorker:
    """Pulls tasks from the Redis queue and scans them."""

    def __init__(self, redis_url: str, worker_id: Optional[str] = None):
        self.redis_url = redis_url
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.client = _connect_redis(redis_url)
        self._running = True
        self.tasks_completed = 0

    def _heartbeat(self):
        """Register this worker as active with a TTL."""
        try:
            self.client.sadd(HEARTBEAT_KEY, self.worker_id)
            self.client.expire(HEARTBEAT_KEY, 60)
        except Exception:
            pass

    def _unregister(self):
        try:
            self.client.srem(HEARTBEAT_KEY, self.worker_id)
        except Exception:
            pass

    def run(self, config_override: Optional[dict] = None):
        """Start the worker loop.  Blocks until stopped."""
        print(
            f"\n{Colors.BOLD}{Colors.CYAN}"
            f"[WORKER] {self.worker_id} started — listening on {self.redis_url}"
            f"{Colors.RESET}"
        )
        try:
            while self._running:
                self._heartbeat()
                raw = self.client.blpop(TASK_QUEUE_KEY, timeout=QUEUE_TIMEOUT)
                if not raw:
                    continue
                _, msg = raw
                try:
                    task = json.loads(msg)
                except json.JSONDecodeError:
                    continue

                task_id = task.get("task_id", "unknown")
                target = task.get("target", "")
                task_config = task.get("config", {})
                if config_override:
                    task_config.update(config_override)

                print(
                    f"{Colors.info(f'[WORKER] {self.worker_id} scanning {target} (task={task_id})')}"
                )
                result = self._run_task(task_id, target, task_config)
                self.client.rpush(RESULT_QUEUE_KEY, json.dumps(result, default=str))
                self.tasks_completed += 1

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[WORKER] Stopped by user.{Colors.RESET}")
        finally:
            self._unregister()

        print(
            f"{Colors.info(f'[WORKER] {self.worker_id} done — completed {self.tasks_completed} tasks')}"
        )

    def _run_task(self, task_id: str, target: str, config: dict) -> dict:
        """Execute a single scan task and return a result dict."""
        start = time.time()
        try:
            from core.engine import AtomicEngine

            engine = AtomicEngine(config)
            engine.scan(target)
            findings = [
                (
                    {k: getattr(f, k, "") for k in
                     ["technique", "url", "param", "severity", "confidence", "cvss", "evidence"]}
                    if not isinstance(f, dict) else f
                )
                for f in engine.findings
            ]
            return {
                "task_id": task_id,
                "target": target,
                "worker_id": self.worker_id,
                "findings_count": len(findings),
                "findings": findings,
                "elapsed": round(time.time() - start, 2),
                "error": None,
            }
        except Exception as exc:
            logger.exception("Worker task failed for %s: %s", target, exc)
            return {
                "task_id": task_id,
                "target": target,
                "worker_id": self.worker_id,
                "findings_count": 0,
                "findings": [],
                "elapsed": round(time.time() - start, 2),
                "error": str(exc),
            }

    def stop(self):
        """Signal the worker to stop after the current task."""
        self._running = False
