"""FastAPI Integration & End-to-End API Tests for AGENT SHIELD.

Compatible with BOTH `pytest` and Python's standard `unittest` runner.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from agents.runtime import DEMO_AGENT_CREDENTIALS
from backend.app import create_app


class TestAPIIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test_api.db"
        self.app = create_app(db_path=self.db_path)
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_health_overview_baselines_and_frontend_served(self) -> None:
        h = self.client.get("/api/health")
        self.assertEqual(h.status_code, 200)
        self.assertEqual(h.json()["status"], "ok")

        ov = self.client.get("/api/dashboard/overview")
        self.assertEqual(ov.status_code, 200)
        body = ov.json()
        self.assertEqual(body["total_agents"], 3)
        self.assertEqual(body["synthetic_db_counts"]["customers"], 100)
        self.assertEqual(body["synthetic_db_counts"]["loans"], 50)
        self.assertEqual(body["synthetic_db_counts"]["payments"], 200)
        self.assertEqual(body["synthetic_db_counts"]["employees"], 30)
        self.assertTrue(body["audit_chain_valid"])

        bl = self.client.get("/api/behaviour/baselines")
        self.assertEqual(bl.status_code, 200)
        self.assertEqual(len(bl.json()["baselines"]), 3)

        idx = self.client.get("/")
        self.assertEqual(idx.status_code, 200)
        self.assertIn("AGENT SHIELD", idx.text)

    def test_create_custom_agent_and_execute_via_gateway(self) -> None:
        create_res = self.client.post(
            "/api/agents",
            json={
                "name": "Compliance Auditor",
                "role": "Risk Reviewer",
                "description": "Reads synthetic loan records for compliance checks.",
                "system_instructions": "Only read loan records.",
                "available_tools": ["read_loan_records"],
                "initial_permissions": [
                    {"resource": "loans", "action": "read", "effect": "ALLOW"}
                ],
            },
        )
        self.assertEqual(create_res.status_code, 201)
        agent = create_res.json()["agent"]
        api_key = agent["api_key"]
        self.assertTrue(api_key.startswith("agsh_"))
        self.assertIn("baseline", agent)

        # Allowed request during normal operating hours via X-Agent-Key header
        allow_res = self.client.post(
            "/api/gateway/execute",
            headers={"X-Agent-Key": api_key},
            json={"tool_name": "read_loan_records", "arguments": {"limit": 3}, "simulated_hour": 14},
        )
        self.assertEqual(allow_res.status_code, 200)
        allow_body = allow_res.json()
        self.assertEqual(allow_body["decision"], "ALLOW")
        self.assertTrue(allow_body["executed"])
        self.assertEqual(allow_body["data"]["record_count"], 3)
        self.assertEqual(len(allow_body["pipeline_trace"]), 8)

        # Unauthorized payroll request -> BLOCK
        block_res = self.client.post(
            "/api/gateway/execute",
            headers={"X-Agent-Key": api_key},
            json={"tool_name": "read_payroll_records", "arguments": {"limit": 2}, "simulated_hour": 14},
        )
        self.assertEqual(block_res.status_code, 200)
        self.assertEqual(block_res.json()["decision"], "BLOCK")
        self.assertFalse(block_res.json()["executed"])

        # Deactivate agent -> subsequent request BLOCKED
        status_res = self.client.patch(
            f"/api/agents/{agent['agent_id']}/status",
            json={"status": "inactive"},
        )
        self.assertEqual(status_res.status_code, 200)
        after_deact = self.client.post(
            "/api/gateway/execute",
            headers={"X-Agent-Key": api_key},
            json={"tool_name": "read_loan_records", "arguments": {"limit": 1}, "simulated_hour": 14},
        )
        self.assertEqual(after_deact.json()["decision"], "BLOCK")
        self.assertFalse(after_deact.json()["executed"])

    def test_playground_all_9_scenarios_via_http(self) -> None:
        sc_list = self.client.get("/api/playground/scenarios")
        self.assertEqual(sc_list.status_code, 200)
        self.assertEqual(len(sc_list.json()["scenarios"]), 9)

        for sid in range(1, 10):
            r = self.client.post("/api/playground/run", json={"scenario_id": sid, "params": {}})
            self.assertEqual(r.status_code, 200, f"Scenario {sid} HTTP failed: {r.text}")
            data = r.json()
            self.assertTrue(data["passed"], f"Scenario {sid} failed: {data}")

    def test_identity_not_derived_from_untrusted_body_field(self) -> None:
        r = self.client.post(
            "/api/gateway/execute",
            headers={"X-Agent-Key": DEMO_AGENT_CREDENTIALS["agent-support-01"]},
            json={
                "tool_name": "read_payment_records",
                "arguments": {"limit": 2},
                "untrusted_agent_id": "agent-payment-01",
                "simulated_hour": 14,
            },
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["authenticated_agent"], "agent-support-01")
        self.assertEqual(body["decision"], "BLOCK")
        self.assertFalse(body["executed"])


if __name__ == "__main__":
    unittest.main()
