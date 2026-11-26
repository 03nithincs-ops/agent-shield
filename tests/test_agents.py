"""Unit tests for Agent Manager and Simulated Agents in AGENT SHIELD."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agents.manager import AgentManager
from backend.auth import AuthService
from backend.database import DatabaseManager
from data.seed_data import seed_database


class TestAgentManager(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test_agents.db"
        self.db = DatabaseManager(self.db_path)
        seed_database(self.db, force_reseed=True)
        self.manager = AgentManager(self.db)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_default_simulated_agents_exist(self) -> None:
        agents = self.manager.list_agents()
        agent_ids = {a["agent_id"] for a in agents}
        self.assertIn("agent-support-01", agent_ids)
        self.assertIn("agent-payment-01", agent_ids)
        self.assertIn("agent-loan-01", agent_ids)

        support = self.manager.get_agent("agent-support-01")
        self.assertIsNotNone(support)
        self.assertEqual(support["role"], "Customer Support")
        self.assertEqual(support["status"], "active")
        self.assertIn("read_customer_records", support["available_tools"])

    def test_create_custom_agent_and_credential_hashing(self) -> None:
        agent = self.manager.create_agent(
            name="Fraud Analyst Agent",
            role="Fraud Detection",
            description="Simulated agent detecting financial fraud.",
            system_instructions="Review payments and customer accounts.",
            available_tools=["read_payment_records", "read_customer_records"],
            initial_permissions=[
                {"resource": "payments", "action": "read", "effect": "ALLOW"},
                {"resource": "customers", "action": "read", "effect": "ALLOW"},
            ],
        )
        self.assertIn("api_key", agent)
        raw_key = agent["api_key"]
        self.assertTrue(raw_key.startswith("agsh_"))

        # Verify key is hashed in DB, never plaintext
        with self.db.read_connection() as conn:
            row = conn.execute(
                "SELECT credential_hash, credential_prefix FROM agents WHERE agent_id = ?",
                (agent["agent_id"],),
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertNotEqual(row["credential_hash"], raw_key)
            self.assertEqual(row["credential_hash"], AuthService.hash_credential(raw_key))

    def test_agent_status_toggle(self) -> None:
        updated = self.manager.set_status("agent-support-01", "inactive")
        self.assertEqual(updated["status"], "inactive")

        fetched = self.manager.get_agent("agent-support-01")
        self.assertEqual(fetched["status"], "inactive")

        updated_active = self.manager.set_status("agent-support-01", "active")
        self.assertEqual(updated_active["status"], "active")

    def test_agent_credential_rotation(self) -> None:
        with self.db.read_connection() as conn:
            old_hash = conn.execute(
                "SELECT credential_hash FROM agents WHERE agent_id = 'agent-support-01'"
            ).fetchone()["credential_hash"]

        rotated = self.manager.rotate_credential("agent-support-01")
        new_key = rotated["api_key"]
        self.assertTrue(new_key.startswith("agsh_"))

        with self.db.read_connection() as conn:
            new_hash = conn.execute(
                "SELECT credential_hash FROM agents WHERE agent_id = 'agent-support-01'"
            ).fetchone()["credential_hash"]

        self.assertNotEqual(new_hash, old_hash)
        self.assertEqual(new_hash, AuthService.hash_credential(new_key))


if __name__ == "__main__":
    unittest.main()
