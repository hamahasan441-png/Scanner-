#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Scheduled Scanning Engine
Supports recurring scans with cron expressions and interval-based scheduling.

Schedule types:
  interval  — Run every N minutes/hours/days
  cron      — Full cron expression (minute hour day month weekday)
  once      — Single future execution
"""

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

# Named constants
FALLBACK_DELAY_SECONDS = 86400  # 24 hours


@dataclass
class ScheduleEntry:
    """A scheduled scan definition."""
    schedule_id: str = ''
    name: str = ''
    target: str = ''
    schedule_type: str = 'interval'  # interval | cron | once
    interval_seconds: int = 3600     # for interval type
    cron_expression: str = ''        # for cron type  (min hour dom mon dow)
    next_run: float = 0.0            # next execution epoch
    last_run: float = 0.0
    run_count: int = 0
    max_runs: int = 0                # 0 = unlimited
    enabled: bool = True
    config: dict = field(default_factory=dict)
    created_at: str = ''
    created_by: str = ''

    def to_dict(self) -> dict:
        return {
            'schedule_id': self.schedule_id,
            'name': self.name,
            'target': self.target,
            'schedule_type': self.schedule_type,
            'interval_seconds': self.interval_seconds,
            'cron_expression': self.cron_expression,
            'next_run': datetime.fromtimestamp(self.next_run, tz=timezone.utc).isoformat() if self.next_run else None,
            'last_run': datetime.fromtimestamp(self.last_run, tz=timezone.utc).isoformat() if self.last_run else None,
            'run_count': self.run_count,
            'max_runs': self.max_runs,
            'enabled': self.enabled,
            'config': self.config,
            'created_at': self.created_at,
            'created_by': self.created_by,
        }


def _parse_cron_field(field_str: str, min_val: int, max_val: int) -> list:
    """Parse a single cron field into a list of valid integer values."""
    values = set()
    for part in field_str.split(','):
        part = part.strip()
        if part == '*':
            values.update(range(min_val, max_val + 1))
        elif '/' in part:
            base, step = part.split('/', 1)
            step = int(step)
            start = min_val if base == '*' else int(base)
            values.update(range(start, max_val + 1, step))
        elif '-' in part:
            lo, hi = part.split('-', 1)
            values.update(range(int(lo), int(hi) + 1))
        else:
            values.add(int(part))
    return sorted(v for v in values if min_val <= v <= max_val)


def parse_cron(expression: str) -> dict:
    """Parse a 5-field cron expression into component lists.

    Format: ``minute hour day_of_month month day_of_week``
    Returns dict with keys: minutes, hours, days, months, weekdays
    """
    fields = expression.strip().split()
    if len(fields) != 5:
        raise ValueError(f'Cron expression must have 5 fields, got {len(fields)}')

    return {
        'minutes': _parse_cron_field(fields[0], 0, 59),
        'hours': _parse_cron_field(fields[1], 0, 23),
        'days': _parse_cron_field(fields[2], 1, 31),
        'months': _parse_cron_field(fields[3], 1, 12),
        'weekdays': _parse_cron_field(fields[4], 0, 6),
    }


def cron_matches(expression: str, dt: datetime) -> bool:
    """Check whether a datetime matches a cron expression."""
    cron = parse_cron(expression)
    return (
        dt.minute in cron['minutes']
        and dt.hour in cron['hours']
        and dt.day in cron['days']
        and dt.month in cron['months']
        and dt.weekday() in cron['weekdays']
    )


def next_cron_time(expression: str, after: Optional[datetime] = None) -> float:
    """Calculate the next execution time for a cron expression.

    Returns epoch timestamp.  Scans up to 366 days ahead.
    """
    if after is None:
        after = datetime.now(timezone.utc)
    cron = parse_cron(expression)

    # Start from the next full minute
    candidate = after.replace(second=0, microsecond=0)
    candidate = candidate.replace(
        minute=candidate.minute + 1 if candidate.minute < 59 else 0,
        hour=candidate.hour + (1 if candidate.minute >= 59 else 0),
    )

    # Brute-force scan (efficient for typical cron patterns)
    max_iterations = 366 * 24 * 60  # one year of minutes
    for _ in range(max_iterations):
        if (candidate.minute in cron['minutes']
                and candidate.hour in cron['hours']
                and candidate.day in cron['days']
                and candidate.month in cron['months']
                and candidate.weekday() in cron['weekdays']):
            return candidate.timestamp()
        # Advance by one minute
        epoch = candidate.timestamp() + 60
        candidate = datetime.fromtimestamp(epoch, tz=timezone.utc)

    # Fallback: 24 hours from now
    return time.time() + FALLBACK_DELAY_SECONDS


class ScanScheduler:
    """Manage and execute scheduled scans."""

    def __init__(self, scan_callback: Optional[Callable] = None):
        """
        Args:
            scan_callback: Function called when a schedule triggers.
                           Signature: callback(schedule_entry: ScheduleEntry)
        """
        self._schedules: Dict[str, ScheduleEntry] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._scan_callback = scan_callback
        self._history: List[dict] = []

    def set_scan_callback(self, callback: Callable) -> None:
        """Set or replace the scan callback after construction."""
        self._scan_callback = callback

    # --- CRUD operations ---

    def add_schedule(
        self,
        name: str,
        target: str,
        schedule_type: str = 'interval',
        interval_seconds: int = 3600,
        cron_expression: str = '',
        max_runs: int = 0,
        config: Optional[dict] = None,
        created_by: str = '',
    ) -> ScheduleEntry:
        """Create a new scheduled scan."""
        sid = str(uuid.uuid4())[:8]
        now = time.time()

        if schedule_type == 'cron':
            if not cron_expression:
                raise ValueError('cron_expression required for cron schedule type')
            parse_cron(cron_expression)  # validate
            nxt = next_cron_time(cron_expression)
        elif schedule_type == 'once':
            nxt = now + interval_seconds
        else:
            nxt = now + interval_seconds

        entry = ScheduleEntry(
            schedule_id=sid,
            name=name,
            target=target,
            schedule_type=schedule_type,
            interval_seconds=interval_seconds,
            cron_expression=cron_expression,
            next_run=nxt,
            max_runs=max_runs,
            enabled=True,
            config=config or {},
            created_at=datetime.now(timezone.utc).isoformat(),
            created_by=created_by,
        )

        with self._lock:
            self._schedules[sid] = entry
        return entry

    def remove_schedule(self, schedule_id: str) -> bool:
        with self._lock:
            return self._schedules.pop(schedule_id, None) is not None

    def get_schedule(self, schedule_id: str) -> Optional[ScheduleEntry]:
        return self._schedules.get(schedule_id)

    def list_schedules(self) -> List[dict]:
        with self._lock:
            return [e.to_dict() for e in self._schedules.values()]

    def toggle_schedule(self, schedule_id: str, enabled: bool) -> bool:
        entry = self._schedules.get(schedule_id)
        if not entry:
            return False
        entry.enabled = enabled
        return True

    def get_history(self, limit: int = 50) -> List[dict]:
        return self._history[-limit:]

    # --- Scheduler loop ---

    def start(self):
        """Start the background scheduler thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name='scan-scheduler')
        self._thread.start()

    def stop(self):
        """Stop the scheduler."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def is_running(self) -> bool:
        return self._running

    def _loop(self):
        """Main scheduler loop — checks every 30 seconds for due schedules."""
        while self._running:
            now = time.time()
            with self._lock:
                due = [
                    e for e in self._schedules.values()
                    if e.enabled and e.next_run <= now
                ]

            for entry in due:
                self._execute(entry)

            # Sleep in small increments for responsive shutdown
            for _ in range(6):
                if not self._running:
                    break
                time.sleep(5)

    def _execute(self, entry: ScheduleEntry):
        """Execute a scheduled scan and update the entry."""
        try:
            if self._scan_callback:
                self._scan_callback(entry)
        except Exception as exc:
            self._history.append({
                'schedule_id': entry.schedule_id,
                'target': entry.target,
                'status': 'error',
                'error': str(exc),
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })
        else:
            self._history.append({
                'schedule_id': entry.schedule_id,
                'target': entry.target,
                'status': 'triggered',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })

        # Cap history
        if len(self._history) > 500:
            self._history = self._history[-500:]

        entry.last_run = time.time()
        entry.run_count += 1

        # Calculate next run
        if entry.schedule_type == 'once':
            entry.enabled = False
        elif entry.schedule_type == 'cron':
            entry.next_run = next_cron_time(entry.cron_expression)
        else:
            entry.next_run = time.time() + entry.interval_seconds

        # Disable if max_runs reached
        if entry.max_runs > 0 and entry.run_count >= entry.max_runs:
            entry.enabled = False

    def check_due(self) -> List[ScheduleEntry]:
        """Return schedules that are currently due (for manual tick)."""
        now = time.time()
        with self._lock:
            return [
                e for e in self._schedules.values()
                if e.enabled and e.next_run <= now
            ]

    def tick(self):
        """Manual tick — execute all due schedules. Useful for testing."""
        for entry in self.check_due():
            self._execute(entry)
