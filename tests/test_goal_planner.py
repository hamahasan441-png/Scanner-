#!/usr/bin/env python3
"""Tests for core/goal_planner.py"""

import sys
import os
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _engine():
    e = MagicMock()
    e.config = {"verbose": False, "max_requests": 1000}
    e.requester = MagicMock()
    e.requester.total_requests = 0
    return e


class TestGoalDataclass(unittest.TestCase):
    def test_creation(self):
        from core.goal_planner import Goal

        g = Goal(
            id="GOAL_0",
            claim="test",
            confidence=0.8,
            target_endpoint="https://example.com",
            vuln_class="sqli",
            required_tools=["sqli"],
            priority=1.0,
        )
        self.assertEqual(g.id, "GOAL_0")
        self.assertEqual(g.status, "pending")
        self.assertEqual(g.retry_count, 0)
        self.assertEqual(g.max_retries, 2)

    def test_defaults(self):
        from core.goal_planner import Goal

        g = Goal()
        self.assertEqual(g.status, "pending")
        self.assertIsInstance(g.result, dict)
        self.assertIsInstance(g.required_tools, list)


class TestGoalPlanner(unittest.TestCase):
    def setUp(self):
        from core.goal_planner import GoalPlanner

        self.planner = GoalPlanner(_engine())

    def test_init(self):
        self.assertEqual(len(self.planner.goals), 0)

    def test_generate_hypotheses_empty(self):
        result = self.planner.generate_hypotheses({}, {})
        self.assertIsInstance(result, list)

    def test_generate_hypotheses_with_matches(self):
        target_map = {"primary": "https://example.com"}
        intel = {"tech_hints": ["wordpress", "php", "jwt"]}
        result = self.planner.generate_hypotheses(target_map, intel)
        self.assertGreater(len(result), 0)

    def test_plan_creates_base_goals(self):
        goals = self.planner.plan([])
        self.assertGreaterEqual(len(goals), 15)  # 15 base goals (v10.0)

    def test_plan_adds_hypothesis_goals(self):
        hypotheses = [
            {
                "claim": "test",
                "confidence": 0.8,
                "vuln_class": "sqli",
                "required_tools": ["sqli"],
                "target_endpoint": "https://example.com",
            }
        ]
        goals = self.planner.plan(hypotheses)
        self.assertGreater(len(goals), 15)

    def test_plan_sorted_by_priority(self):
        self.planner.plan([])
        for i in range(len(self.planner.goals) - 1):
            self.assertGreaterEqual(self.planner.goals[i].priority, self.planner.goals[i + 1].priority)

    def test_get_next_goal_empty(self):
        self.assertIsNone(self.planner.get_next_goal())

    def test_get_next_goal_returns_highest_priority(self):
        self.planner.plan([])
        goal = self.planner.get_next_goal()
        self.assertIsNotNone(goal)
        self.assertEqual(goal.status, "running")

    def test_update_goal(self):
        self.planner.plan([])
        goal = self.planner.get_next_goal()
        self.planner.update_goal(goal.id, "completed", {"data": "ok"})
        self.assertEqual(goal.status, "completed")

    def test_push_goal(self):
        from core.goal_planner import Goal

        g = Goal(
            id="NEW", claim="new", confidence=0.9, target_endpoint="t", vuln_class="v", required_tools=[], priority=10.0
        )
        self.planner.push_goal(g)
        self.assertEqual(self.planner.goals[0].id, "NEW")

    def test_should_continue_false_when_empty(self):
        self.assertFalse(self.planner.should_continue())

    def test_should_continue_true_with_pending(self):
        self.planner.plan([])
        self.assertTrue(self.planner.should_continue())

    def test_memory_operations(self):
        self.planner.update_memory("key1", "val1")
        self.assertEqual(self.planner.get_memory("key1"), "val1")
        self.assertIsNone(self.planner.get_memory("missing"))

    def test_budget(self):
        self.assertTrue(self.planner.check_budget())
        self.planner.record_requests(5)
        self.assertEqual(self.planner._requests_used, 5)

    def test_get_summary(self):
        self.planner.plan([])
        summary = self.planner.get_summary()
        self.assertIn("total", summary)
        self.assertIn("pending", summary)
        self.assertIn("completed", summary)
        self.assertGreater(summary["total"], 0)


if __name__ == "__main__":
    unittest.main()
