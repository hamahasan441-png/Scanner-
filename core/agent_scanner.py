#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Phase 4 — Agent-Based Autonomous Scanner

Implements the OBSERVE → THINK → ACT → REFLECT → ADAPT loop
with target decomposition, hypothesis generation, goal planning,
and pivot-driven scope expansion.
"""

import re
from urllib.parse import urlparse, parse_qs

from config import Colors
from core.engine import Finding
from core.goal_planner import GoalPlanner, Goal
from core.pivot_detector import PivotDetector


def _classify_target(target: str) -> str:
    """Classify target as url, domain, ip, cidr, or wildcard."""
    parsed = urlparse(target)
    host = parsed.hostname or ''

    if '*' in target:
        return 'wildcard'

    # CIDR
    if '/' in host:
        return 'cidr'

    # IP address
    parts = host.split('.')
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return 'ip'

    # URL with path/query → focused
    if parsed.path and parsed.path != '/' or parsed.query:
        return 'url'

    return 'domain'


class AgentScanner:
    """Autonomous agent that drives goal-based scanning."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get('verbose', False)
        self.planner = GoalPlanner(engine)
        self.pivot_detector = PivotDetector(engine)
        self._agent_notes = []

    # ── public API ────────────────────────────────────────────────────

    def run(self, target: str, real_ip_result=None, waf_bypass_profile=None) -> dict:
        """Execute the full agent scan lifecycle."""
        print(f"\n{Colors.info('Phase 4: Agent Autonomous Scanner...')}")
        self.engine.emit_pipeline_event('agent_start', {'target': target})

        # Step A — Decompose
        target_map = self.decompose(target)

        # Step B — Build intel bundle and hypothesize
        intel = self._build_intel_bundle(real_ip_result, waf_bypass_profile)
        hypotheses = self.hypothesize(target_map, intel)

        # Step C — Plan
        goals = self.plan(hypotheses)
        if self.verbose:
            print(f"  {Colors.info(f'Goal stack: {len(goals)} goals planned')}")

        # Step D — Execute
        self.execute_loop()

        # Build result
        summary = self.planner.get_summary()
        result = {
            'target_map': target_map,
            'hypotheses': hypotheses,
            'goals_completed': [g.id for g in self.planner.goals if g.status == 'completed'],
            'goals_skipped': [g.id for g in self.planner.goals if g.status == 'skipped'],
            'pivots_found': self.pivot_detector.get_pivots(),
            'agent_notes': self._agent_notes,
            'scan_coverage_pct': self._calc_coverage(),
        }

        self._print_summary(result, summary)
        self.engine.emit_pipeline_event('agent_done', {
            'goals_completed': summary.get('completed', 0),
            'pivots': len(result['pivots_found']),
        })
        return result

    # ── Step A: Target Decomposition ──────────────────────────────────

    def decompose(self, target: str) -> dict:
        """Classify and decompose the target."""
        target_type = _classify_target(target)
        parsed = urlparse(target)
        return {
            'primary': target,
            'target_type': target_type,
            'hostname': parsed.hostname or '',
            'subdomains': [],
            'ip_ranges': [],
            'scope_type': target_type,
            'path': parsed.path or '/',
            'params': parse_qs(parsed.query),
        }

    # ── Step B: Hypothesis Generation ─────────────────────────────────

    def hypothesize(self, target_map: dict, intel_bundle: dict) -> list:
        return self.planner.generate_hypotheses(target_map, intel_bundle)

    # ── Step C: Goal Planning ─────────────────────────────────────────

    def plan(self, hypotheses: list) -> list:
        return self.planner.plan(hypotheses)

    # ── Step D: Autonomous Execution Loop ─────────────────────────────

    def execute_loop(self):
        """OBSERVE → THINK → ACT → REFLECT → ADAPT."""
        iteration = 0
        max_iterations = 200

        while self.planner.should_continue() and iteration < max_iterations:
            iteration += 1
            goal = self.planner.get_next_goal()
            if not goal:
                break

            # ── OBSERVE ──
            if not self._check_scope(goal.target_endpoint):
                self._skip_goal(goal, 'out of scope')
                continue

            if not self.planner.check_budget():
                self._skip_goal(goal, 'budget exhausted')
                self._agent_notes.append('Budget limit reached — stopping execution.')
                break

            # ── THINK ──
            if goal.retry_count >= goal.max_retries:
                self._skip_goal(goal, f'exceeded max retries ({goal.max_retries})')
                continue

            tool_key = self._select_tool(goal)
            params = self._build_params(goal)

            # ── ACT ──
            try:
                result = self._execute_goal(goal, tool_key, params)
                self.planner.record_requests(5)  # estimate
            except Exception as e:
                self._fail_goal(goal, str(e))
                continue

            # ── REFLECT ──
            self._process_result(goal, result)

            # ── ADAPT ──
            if result and result.get('finding'):
                self.pivot_detector.handle(result['finding'])
                new_goals = self.pivot_detector.get_new_goals()
                for ng in new_goals:
                    self.planner.push_goal(ng)
                    if self.verbose:
                        print(f"  {Colors.info(f'Pivot goal added: {ng.claim}')}")

    # ── tool selection ────────────────────────────────────────────────

    def _select_tool(self, goal: Goal) -> str:
        """Map goal's required_tools to available engine modules."""
        for tool in goal.required_tools:
            if tool in self.engine._modules:
                return tool
        # Fallback: use the first available tool
        if goal.required_tools:
            return goal.required_tools[0]
        return 'discovery'

    def _build_params(self, goal: Goal) -> dict:
        """Build parameters for goal execution."""
        return {
            'target': goal.target_endpoint,
            'vuln_class': goal.vuln_class,
            'claim': goal.claim,
        }

    def _execute_goal(self, goal: Goal, tool_key: str, params: dict) -> dict:
        """Execute the goal using the selected tool."""
        result = {'success': False, 'finding': None, 'data': {}}

        module = self.engine._modules.get(tool_key)
        target = params.get('target', '')

        if module and hasattr(module, 'test_url') and target:
            try:
                module.test_url(target)
                result['success'] = True
            except Exception as e:
                if self.verbose:
                    print(f"  {Colors.warning(f'Goal {goal.id} test_url error: {e}')}")

        elif module and hasattr(module, 'test') and target:
            parsed = urlparse(target)
            for param_name, param_vals in parse_qs(parsed.query).items():
                for val in param_vals:
                    try:
                        module.test(target, 'GET', param_name, val)
                        result['success'] = True
                    except Exception:
                        pass

        # Check if any new findings were added during execution
        pre_count = len(self.engine.findings)
        # Findings are added in real-time via engine.add_finding()
        if len(self.engine.findings) > pre_count:
            latest = self.engine.findings[-1]
            result['finding'] = {
                'technique': latest.technique,
                'url': latest.url,
                'evidence': latest.evidence,
                'payload': latest.payload,
            }

        return result

    def _process_result(self, goal: Goal, result: dict):
        """Process goal result — update planner memory and status."""
        if result.get('success'):
            self.planner.update_goal(goal.id, 'completed', result)
        else:
            goal.retry_count += 1
            if goal.retry_count >= goal.max_retries:
                self.planner.update_goal(goal.id, 'failed', result)
            else:
                goal.status = 'pending'  # retry

        # Update memory
        visited = self.planner.get_memory('visited') or []
        visited.append(goal.target_endpoint)
        self.planner.update_memory('visited', visited)

    # ── helpers ────────────────────────────────────────────────────────

    def _check_scope(self, target: str) -> bool:
        if not target:
            return True
        if hasattr(self.engine, 'scope'):
            return self.engine.scope.is_in_scope(target)
        return True

    def _skip_goal(self, goal: Goal, reason: str):
        self.planner.update_goal(goal.id, 'skipped', {'reason': reason})
        if self.verbose:
            print(f"  {Colors.warning(f'Goal {goal.id} skipped: {reason}')}")

    def _fail_goal(self, goal: Goal, reason: str):
        goal.retry_count += 1
        if goal.retry_count >= goal.max_retries:
            self.planner.update_goal(goal.id, 'failed', {'error': reason})
        else:
            goal.status = 'pending'
        if self.verbose:
            print(f"  {Colors.warning(f'Goal {goal.id} failed: {reason}')}")

    def _calc_coverage(self) -> float:
        total = len(self.planner.goals)
        if total == 0:
            return 0.0
        done = sum(1 for g in self.planner.goals if g.status in ('completed', 'skipped'))
        return round(done / total * 100, 1)

    def _build_intel_bundle(self, real_ip_result=None, waf_bypass_profile=None) -> dict:
        """Gather all available intelligence for hypothesis generation."""
        intel = {'tech_hints': [], 'cve_matches': [], 'endpoints': []}

        # Tech hints from context
        if hasattr(self.engine, 'context') and hasattr(self.engine.context, 'detected_tech'):
            intel['tech_hints'] = list(self.engine.context.detected_tech)

        if real_ip_result:
            intel['real_ip'] = real_ip_result.get('origin_ip')

        if waf_bypass_profile:
            intel['waf_profile'] = waf_bypass_profile

        return intel

    def _print_summary(self, result: dict, summary: dict):
        print(f"\n  {Colors.BOLD}Agent Scanner Summary:{Colors.RESET}")
        print(f"    Goals:     {summary.get('total', 0)} total,"
              f" {summary.get('completed', 0)} completed,"
              f" {summary.get('skipped', 0)} skipped,"
              f" {summary.get('failed', 0)} failed")
        print(f"    Pivots:    {len(result['pivots_found'])}")
        print(f"    Coverage:  {result['scan_coverage_pct']}%")
        if result['agent_notes']:
            for note in result['agent_notes'][:5]:
                print(f"    Note: {note}")
