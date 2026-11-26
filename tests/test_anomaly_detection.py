"""Unit tests for Scikit-Learn Isolation Forest Anomaly Detection in AGENT SHIELD."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from backend.behaviour_monitor import BehaviourMonitoringEngine, _SKLEARN_AVAILABLE
from backend.database import DatabaseManager
from data.seed_data import seed_database


class TestIsolationForestAnomalyDetection(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test_if.db"
        self.db = DatabaseManager(self.db_path)
        seed_database(self.db, force_reseed=True)
        self.behaviour = BehaviourMonitoringEngine(self.db)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_actual_sklearn_isolation_forest_is_active(self) -> None:
        # Mandatory requirement: Scikit-learn must be active
        self.assertTrue(_SKLEARN_AVAILABLE, "scikit-learn must be installed and active")
        info = self.behaviour.get_model_info("agent-support-01")
        self.assertTrue(info["sklearn_active"])
        self.assertEqual(info["detector_mode"], "sklearn_isolation_forest")
        self.assertEqual(info["contamination"], 0.05)
        self.assertGreaterEqual(info["baseline_sample_count"], 250)

    def test_isolation_forest_flags_off_hours_anomaly(self) -> None:
        res = self.behaviour.evaluate(
            agent_id="agent-support-01",
            tool_name="read_customer_records",
            resource="customers",
            action="read",
            arguments={"limit": 2},
            is_sensitive_tool=False,
            policy_allowed=True,
            simulated_hour=3,  # off-hours
        )
        self.assertTrue(res.ml_is_anomaly)
        self.assertLess(res.anomaly_score, 0.0)  # decision_function convention: negative = anomaly
        self.assertGreater(res.ml_severity_points, 0.0)

    def test_isolation_forest_flags_excessive_record_volume_anomaly(self) -> None:
        # Normal records max is 8. Requesting 30 records is far beyond the normal baseline envelope.
        res = self.behaviour.evaluate(
            agent_id="agent-support-01",
            tool_name="read_customer_records",
            resource="customers",
            action="read",
            arguments={"limit": 30},
            is_sensitive_tool=False,
            policy_allowed=True,
            simulated_hour=14,
        )
        self.assertTrue(res.ml_is_anomaly)
        self.assertLess(res.anomaly_score, 0.0)

    def test_trusted_baseline_never_poisoned_by_untrusted_requests(self) -> None:
        # Baseline must remain immutable from runtime requests
        baseline_before = self.behaviour.get_agent_baseline("agent-support-01")
        sample_count_before = baseline_before["baseline_sample_count"]

        # Run several anomalous requests
        for _ in range(5):
            self.behaviour.evaluate(
                agent_id="agent-support-01",
                tool_name="read_customer_records",
                resource="customers",
                action="read",
                arguments={"limit": 50},
                is_sensitive_tool=False,
                policy_allowed=True,
                simulated_hour=2,
            )

        baseline_after = self.behaviour.get_agent_baseline("agent-support-01")
        self.assertEqual(baseline_after["baseline_sample_count"], sample_count_before)
        self.assertEqual(baseline_after["trusted_source"], "synthetic_normal_baseline_v1")


if __name__ == "__main__":
    unittest.main()
