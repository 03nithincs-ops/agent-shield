"""
AGENT SHIELD - Dedicated Ollama & AI Agent Policy Integration Test Suite
Verifies:
1. Authorized customer lookup (Customer Support Agent -> ALLOW -> mock data returned)
2. Unauthorized customer lookup (Analytics Agent -> DENY -> blocked by policy engine)
3. Normal conversational chat message (no tool needed)
4. Policy enforcement guarantees (LLM cannot bypass policy)
5. Audit logging persistence for AI agent tool calls
"""

import sys
import os
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from backend.database import init_database, get_db_connection
from backend.anomaly_detector import load_model
from backend.audit_logger import get_audit_logs
from backend.ollama_client import (
    process_agent_chat,
    check_ollama_status,
    execute_mock_lookup_customer,
    MOCK_CUSTOMERS,
    TOOL_PERMISSION_MAP,
    DEFAULT_MODEL
)


class TestOllamaAIAgentIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_database()
        load_model()

    def test_01_ollama_model_capability_check(self):
        """Verify model tool-calling capability status reporting for qwen2.5:3b."""
        status = check_ollama_status("qwen2.5:3b")
        self.assertIn("online", status)
        self.assertEqual(status["model"], "qwen2.5:3b")
        # qwen2.5 is confirmed to support tools
        self.assertTrue(status["supports_tools"])
        self.assertEqual(status["recommended_model"], "qwen2.5:3b")

    def test_02_normal_chat_no_tool(self):
        """Test a normal chat message that does NOT need a tool."""
        res = process_agent_chat(
            agent_id="agent-001",
            user_message="Hello, can you explain your general role and guidelines?",
            use_mock_llm=True
        )
        self.assertIsNotNone(res["response"])
        self.assertIsNone(res["tool_called"])
        self.assertIsNone(res["customer_data"])
        self.assertEqual(res["security_decision"]["decision"], "NOT_APPLICABLE")

    def test_03_authorized_customer_lookup(self):
        """
        Test an authorized customer lookup:
        - Agent: Customer Support Agent (agent-001)
        - Tool: lookup_customer (requires resource: customer_files, action: READ)
        - Expected: ALLOW -> mock customer data retrieved -> audit log event created
        """
        res = process_agent_chat(
            agent_id="agent-001",
            user_message="Please look up account details for customer Alice (CUST-101).",
            use_mock_llm=True
        )
        # 1. Tool requested
        self.assertEqual(res["tool_called"], "lookup_customer")
        # 2. Policy engine authorized
        self.assertEqual(res["security_decision"]["decision"], "ALLOW")
        self.assertEqual(res["security_decision"]["resource"], "customer_files")
        self.assertEqual(res["security_decision"]["action"], "READ")
        # 3. Customer data retrieved
        self.assertIsNotNone(res["customer_data"])
        self.assertEqual(res["customer_data"]["name"], "Alice Johnson")
        self.assertEqual(res["customer_data"]["customer_id"], "CUST-101")
        # 4. Audit log created
        event_id = res["audit_event_id"]
        self.assertIsNotNone(event_id)
        
        # Verify in SQLite database
        logs = get_audit_logs(agent_id="agent-001", decision="ALLOW", limit=5)
        self.assertTrue(any(l["event_id"] == event_id for l in logs))

    def test_04_unauthorized_customer_lookup(self):
        """
        Test an unauthorized customer lookup:
        - Agent: Analytics Agent (agent-003)
        - Tool: lookup_customer (requires resource: customer_files, action: READ)
        - Expected: DENY -> customer data NEVER executed (None) -> security denial returned
        """
        res = process_agent_chat(
            agent_id="agent-003",
            user_message="Retrieve customer details for CUST-101 immediately.",
            use_mock_llm=True
        )
        # 1. Tool requested
        self.assertEqual(res["tool_called"], "lookup_customer")
        # 2. Policy engine DENIED
        self.assertEqual(res["security_decision"]["decision"], "DENY")
        self.assertEqual(res["security_decision"]["resource"], "customer_files")
        # 3. Customer data is strictly None (NEVER TOUCHED)
        self.assertIsNone(res["customer_data"])
        # 4. Audit event created with DENY
        event_id = res["audit_event_id"]
        self.assertIsNotNone(event_id)
        
        logs = get_audit_logs(agent_id="agent-003", decision="DENY", limit=5)
        self.assertTrue(any(l["event_id"] == event_id for l in logs))
        
        # 5. Response explains security block
        self.assertIn("DENIED", res["response"])

    def test_05_mock_customer_database(self):
        """Verify synthetic mock customer dataset."""
        res_found = execute_mock_lookup_customer("CUST-101")
        self.assertTrue(res_found["found"])
        self.assertEqual(res_found["customer"]["name"], "Alice Johnson")

        res_missing = execute_mock_lookup_customer("NON-EXISTENT-999")
        self.assertFalse(res_missing["found"])


if __name__ == "__main__":
    unittest.main()
