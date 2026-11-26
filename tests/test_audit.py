"""Unit tests for Tamper-Evident SHA-256 Audit Engine in AGENT SHIELD."""
from __future__ import annotations

import concurrent.futures
import tempfile
import unittest
from pathlib import Path

from backend.audit_engine import AuditEngine, GENESIS_HASH
from backend.database import DatabaseManager


class TestAuditEngine(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test_audit.db"
        self.db = DatabaseManager(self.db_path)
        self.db.init_schema()
        self.audit = AuditEngine(self.db)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_hash_chain_genesis_and_linking(self) -> None:
        e1 = self.audit.record_event(
            event_id="evt-001",
            authenticated_agent="agent-support-01",
            agent_name="Support Agent",
            requested_resource="customers",
            requested_action="read",
            tool_name="read_customer_records",
            auth_result="AUTHENTICATED",
            policy_result="ALLOW",
            behaviour_result="NORMAL",
            risk_score=10.0,
            final_decision="ALLOW",
            execution_result="EXECUTED",
            details={},
        )
        self.assertEqual(e1["prev_hash"], GENESIS_HASH)
        self.assertEqual(len(e1["current_hash"]), 64)

        e2 = self.audit.record_event(
            event_id="evt-002",
            authenticated_agent="agent-payment-01",
            agent_name="Payment Agent",
            requested_resource="payments",
            requested_action="execute",
            tool_name="request_simulated_payment",
            auth_result="AUTHENTICATED",
            policy_result="ALLOW",
            behaviour_result="MONITOR",
            risk_score=45.0,
            final_decision="REQUIRE_APPROVAL",
            execution_result="PENDING_APPROVAL",
            details={},
        )
        self.assertEqual(e2["prev_hash"], e1["current_hash"])

        # Chain verification must pass
        verify = self.audit.verify_chain()
        self.assertTrue(verify["valid"])
        self.assertEqual(verify["total_records"], 2)

    def test_tamper_detection_on_modified_record(self) -> None:
        e1 = self.audit.record_event(
            event_id="evt-101",
            authenticated_agent="agent-support-01",
            agent_name="Support Agent",
            requested_resource="customers",
            requested_action="read",
            tool_name="read_customer_records",
            auth_result="AUTHENTICATED",
            policy_result="ALLOW",
            behaviour_result="NORMAL",
            risk_score=15.0,
            final_decision="ALLOW",
            execution_result="EXECUTED",
            details={},
        )
        e2 = self.audit.record_event(
            event_id="evt-102",
            authenticated_agent="agent-support-01",
            agent_name="Support Agent",
            requested_resource="payroll",
            requested_action="read",
            tool_name="read_payroll_records",
            auth_result="AUTHENTICATED",
            policy_result="DENY",
            behaviour_result="ANOMALOUS_BLOCK",
            risk_score=85.0,
            final_decision="BLOCK",
            execution_result="NOT_EXECUTED",
            details={},
        )

        self.assertTrue(self.audit.verify_chain()["valid"])

        # Tamper with evt-101 in database
        with self.db.write_transaction() as conn:
            conn.execute(
                "UPDATE audit_logs SET final_decision = 'BLOCK' WHERE event_id = 'evt-101'"
            )

        # Verification must now fail immediately
        verify_tampered = self.audit.verify_chain()
        self.assertFalse(verify_tampered["valid"])
        self.assertGreaterEqual(verify_tampered["broken_count"], 1)
        self.assertEqual(verify_tampered["broken_events"][0]["event_id"], "evt-101")

    def test_concurrency_safe_audit_writes(self) -> None:
        def write_audit(idx: int) -> None:
            self.audit.record_event(
                event_id=f"evt-conc-{idx:03d}",
                authenticated_agent="agent-support-01",
                agent_name="Support Agent",
                requested_resource="customers",
                requested_action="read",
                tool_name="read_customer_records",
                auth_result="AUTHENTICATED",
                policy_result="ALLOW",
                behaviour_result="NORMAL",
                risk_score=float(idx),
                final_decision="ALLOW",
                execution_result="EXECUTED",
                details={},
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(write_audit, i) for i in range(20)]
            concurrent.futures.wait(futures)

        verify = self.audit.verify_chain()
        self.assertTrue(verify["valid"])
        self.assertEqual(verify["total_records"], 20)


if __name__ == "__main__":
    unittest.main()
