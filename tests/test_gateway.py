"""Unit tests for Central Runtime Security Gateway in AGENT SHIELD."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agents.runtime import DEMO_AGENT_CREDENTIALS
from backend.database import DatabaseManager
from backend.gateway import SecurityGateway
from data.seed_data import seed_database


class TestSecurityGateway(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test_gateway.db"
        self.db = DatabaseManager(self.db_path)
        seed_database(self.db, force_reseed=True)
        self.gateway = SecurityGateway(self.db)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_gateway_authenticates_via_credential_header(self) -> None:
        res = self.gateway.handle_tool_request(
            credential=DEMO_AGENT_CREDENTIALS["agent-support-01"],
            tool_name="read_customer_records",
            arguments={"limit": 1},
            simulated_hour=14,
        )
        self.assertEqual(res["decision"], "ALLOW")
        self.assertEqual(res["authenticated_agent"], "agent-support-01")
        self.assertTrue(res["executed"])
        self.assertIsNotNone(res["data"])

    def test_gateway_blocks_invalid_credential_fail_closed(self) -> None:
        res = self.gateway.handle_tool_request(
            credential="agsh_forged_invalid_credential_string",
            tool_name="read_customer_records",
            arguments={"limit": 1},
            simulated_hour=14,
        )
        self.assertEqual(res["decision"], "BLOCK")
        self.assertFalse(res["executed"])
        self.assertIsNone(res["data"])
        self.assertEqual(res["authenticated_agent"], "UNAUTHENTICATED")

    def test_gateway_blocks_unknown_tool_fail_closed(self) -> None:
        res = self.gateway.handle_tool_request(
            credential=DEMO_AGENT_CREDENTIALS["agent-support-01"],
            tool_name="drop_all_database_tables",
            arguments={},
            simulated_hour=14,
        )
        self.assertEqual(res["decision"], "BLOCK")
        self.assertFalse(res["executed"])

    def test_gateway_never_trusts_untrusted_body_id(self) -> None:
        res = self.gateway.handle_tool_request(
            credential=DEMO_AGENT_CREDENTIALS["agent-support-01"],
            tool_name="read_payment_records",
            arguments={"limit": 1},
            untrusted_agent_id="agent-payment-01",
            simulated_hour=14,
        )
        # Identity must resolve to agent-support-01 (from credential) and be blocked from payments
        self.assertEqual(res["authenticated_agent"], "agent-support-01")
        self.assertEqual(res["decision"], "BLOCK")
        self.assertFalse(res["executed"])

    def test_pipeline_trace_stages_returned(self) -> None:
        res = self.gateway.handle_tool_request(
            credential=DEMO_AGENT_CREDENTIALS["agent-support-01"],
            tool_name="read_customer_records",
            arguments={"limit": 2},
            simulated_hour=14,
        )
        trace = res["pipeline_trace"]
        self.assertEqual(len(trace), 8)
        stage_names = [s["stage"] for s in trace]
        self.assertIn("1. Authentication", stage_names)
        self.assertIn("2. Permission Registry & Policy", stage_names)
        self.assertIn("3. Behaviour Baseline & Isolation Forest", stage_names)
        self.assertIn("4. Explainable Risk Assessment", stage_names)
        self.assertIn("5. Enforcement Decision", stage_names)
        self.assertIn("6. Protected Tool Execution", stage_names)
        self.assertIn("7. Tamper-Evident SHA-256 Audit", stage_names)
        self.assertIn("8. Alerts & Approval Queue", stage_names)


if __name__ == "__main__":
    unittest.main()
