"""Unit tests for Explainable Risk Engine in AGENT SHIELD."""
from __future__ import annotations

import unittest

from backend.behaviour_monitor import BehaviourAssessment
from backend.policy_engine import PolicyEvaluation
from backend.risk_engine import RiskAssessmentEngine


class TestRiskEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RiskAssessmentEngine()

    def test_low_risk_for_authorized_normal_request(self) -> None:
        pol = PolicyEvaluation(allowed=True, requires_approval=False, reason="Permitted")
        beh = BehaviourAssessment(status="NORMAL", ml_is_anomaly=False, ml_severity_points=0.0)
        res = self.engine.assess(
            authenticated=True,
            resource="customers",
            action="read",
            arguments={"limit": 2},
            policy=pol,
            behaviour=beh,
        )
        self.assertLessEqual(res.score, 24.0)
        self.assertEqual(res.level, "LOW")
        self.assertIn("not a calibrated attack probability", res.disclaimer.lower())

    def test_high_risk_for_denied_sensitive_resource(self) -> None:
        pol = PolicyEvaluation(allowed=False, requires_approval=False, reason="Denied by policy")
        beh = BehaviourAssessment(status="NORMAL", ml_is_anomaly=False, ml_severity_points=0.0)
        res = self.engine.assess(
            authenticated=True,
            resource="payroll",
            action="read",
            arguments={},
            policy=pol,
            behaviour=beh,
        )
        self.assertGreaterEqual(res.score, 70.0)
        self.assertIn(res.level, ("HIGH", "CRITICAL"))
        self.assertTrue(any("denied" in f.lower() for f in res.factors))

    def test_ml_anomaly_points_contribute_transparently(self) -> None:
        pol = PolicyEvaluation(allowed=True, requires_approval=False, reason="Permitted")
        beh_normal = BehaviourAssessment(status="NORMAL", ml_is_anomaly=False, ml_severity_points=0.0)
        res_normal = self.engine.assess(
            authenticated=True,
            resource="customers",
            action="read",
            arguments={},
            policy=pol,
            behaviour=beh_normal,
        )

        beh_anomaly = BehaviourAssessment(
            status="MONITOR",
            ml_is_anomaly=True,
            anomaly_score=-0.08,
            ml_severity_points=21.2,
        )
        res_anomaly = self.engine.assess(
            authenticated=True,
            resource="customers",
            action="read",
            arguments={},
            policy=pol,
            behaviour=beh_anomaly,
        )
        self.assertGreater(res_anomaly.score, res_normal.score)
        self.assertGreater(res_anomaly.breakdown["ml_isolation_forest"], 0.0)


if __name__ == "__main__":
    unittest.main()
