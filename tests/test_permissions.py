"""Unit tests for Persistent Permission Registry in AGENT SHIELD."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from backend.database import DatabaseManager
from backend.policy_engine import PolicyEngine
from data.seed_data import seed_database


class TestPermissionRegistry(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test_perms.db"
        self.db = DatabaseManager(self.db_path)
        seed_database(self.db, force_reseed=True)
        self.policy = PolicyEngine(self.db)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_default_permissions_seeded(self) -> None:
        support_perms = self.policy.list_permissions(agent_id="agent-support-01")
        self.assertTrue(any(p["resource"] == "customers" and p["effect"] == "ALLOW" for p in support_perms))

        # Support agent has no permission on payroll
        res = self.policy.evaluate(
            agent_id="agent-support-01",
            agent_available_tools=["read_customer_records"],
            tool_name="read_payroll_records",
            resource="payroll",
            action="read",
            arguments={},
        )
        self.assertFalse(res.allowed)
        self.assertIn("no active permission", res.reason.lower())

    def test_explicit_deny_overrides_allow(self) -> None:
        # Initially Support agent is allowed to read customers
        res1 = self.policy.evaluate(
            agent_id="agent-support-01",
            agent_available_tools=["read_customer_records"],
            tool_name="read_customer_records",
            resource="customers",
            action="read",
            arguments={"limit": 1},
        )
        self.assertTrue(res1.allowed)

        # Upsert explicit DENY
        self.policy.upsert_permission(
            agent_id="agent-support-01",
            resource="customers",
            action="read",
            effect="DENY",
        )

        res2 = self.policy.evaluate(
            agent_id="agent-support-01",
            agent_available_tools=["read_customer_records"],
            tool_name="read_customer_records",
            resource="customers",
            action="read",
            arguments={"limit": 1},
        )
        self.assertFalse(res2.allowed)
        self.assertIn("explicit deny", res2.reason.lower())

    def test_approval_threshold_triggers_requires_approval(self) -> None:
        # Payment agent has approval threshold at 5000
        under = self.policy.evaluate(
            agent_id="agent-payment-01",
            agent_available_tools=["request_simulated_payment"],
            tool_name="request_simulated_payment",
            resource="payments",
            action="execute",
            arguments={"amount": 2500.0},
        )
        self.assertTrue(under.allowed)
        self.assertFalse(under.requires_approval)

        above = self.policy.evaluate(
            agent_id="agent-payment-01",
            agent_available_tools=["request_simulated_payment"],
            tool_name="request_simulated_payment",
            resource="payments",
            action="execute",
            arguments={"amount": 15000.0},
        )
        self.assertTrue(above.allowed)
        self.assertTrue(above.requires_approval)

    def test_permission_revocation(self) -> None:
        perms = self.policy.list_permissions(agent_id="agent-loan-01")
        loan_read = next(p for p in perms if p["resource"] == "loans" and p["action"] == "read")
        
        # Revoke
        deleted = self.policy.revoke_permission(loan_read["permission_id"])
        self.assertTrue(deleted)

        res = self.policy.evaluate(
            agent_id="agent-loan-01",
            agent_available_tools=["read_loan_records"],
            tool_name="read_loan_records",
            resource="loans",
            action="read",
            arguments={},
        )
        self.assertFalse(res.allowed)


if __name__ == "__main__":
    unittest.main()
