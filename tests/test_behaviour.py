"""Unit tests for Behaviour Monitoring Engine in AGENT SHIELD."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from backend.behaviour_monitor import BehaviourMonitoringEngine
from backend.database import DatabaseManager
from data.seed_data import seed_database


class TestBehaviourMonitor(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test_behaviour.db"
        self.db = DatabaseManager(self.db_path)
        seed_database(self.db, force_reseed=True)
        self.behaviour = BehaviourMonitoringEngine(self.db)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_normal_activity_evaluated_as_normal(self) -> None:
        res = self.behaviour.evaluate(
            agent_id="agent-support-01",
            tool_name="read_customer_records",
            resource="customers",
            action="read",
            arguments={"limit": 2},
            is_sensitive_tool=False,
            policy_allowed=True,
            simulated_hour=14,
        )
        self.assertEqual(res.status, "NORMAL")
        self.assertFalse(res.ml_is_anomaly)
        self.assertFalse(res.metrics["off_hours_activity"])
        self.assertFalse(res.metrics["unseen_resource_category"])

    def test_unseen_resource_category_flagged(self) -> None:
        # Support agent only has 'customers' in its baseline
        res = self.behaviour.evaluate(
            agent_id="agent-support-01",
            tool_name="read_payroll_records",
            resource="payroll",
            action="read",
            arguments={"limit": 2},
            is_sensitive_tool=True,
            policy_allowed=False,
            simulated_hour=14,
        )
        self.assertTrue(res.metrics["unseen_resource_category"])
        self.assertTrue(any("unseen resource category" in r.lower() for r in res.reasons))

    def test_off_hours_flagged_with_simulated_hour(self) -> None:
        # Normal hours are 08:00 - 20:00
        res = self.behaviour.evaluate(
            agent_id="agent-support-01",
            tool_name="read_customer_records",
            resource="customers",
            action="read",
            arguments={"limit": 1},
            is_sensitive_tool=False,
            policy_allowed=True,
            simulated_hour=3,  # 03:00 is off-hours
        )
        self.assertTrue(res.metrics["off_hours_activity"])
        self.assertTrue(any("off-hours" in r.lower() for r in res.reasons))


if __name__ == "__main__":
    unittest.main()
