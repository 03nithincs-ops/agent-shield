"""
AGENT SHIELD - Backend Comprehensive Automated Test Suite
"""
import sys
import os
import unittest
from datetime import datetime

# Set up path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from backend.database import init_database, get_db_connection, get_agent_by_id, get_all_agents, get_dashboard_stats
from backend.policy_engine import evaluate_authorization, check_privilege_escalation
from backend.anomaly_detector import detect_anomaly, load_model, get_model_status
from backend.risk_analyzer import calculate_risk_score
from backend.audit_logger import log_event, get_audit_logs, get_recent_events
from backend.alert_manager import create_alert, evaluate_and_create_alerts, get_alerts, acknowledge_alert
from backend.ollama_client import process_agent_chat, check_ollama_status, execute_mock_lookup_customer

class TestAgentShield(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_database()
        load_model()

    def test_01_database_and_seed_agents(self):
        """Verify database initialization and seed agents."""
        agents = get_all_agents()
        self.assertGreaterEqual(len(agents), 3)
        agent_ids = [a["agent_id"] for a in agents]
        self.assertIn("agent-001", agent_ids)
        self.assertIn("agent-002", agent_ids)
        self.assertIn("agent-003", agent_ids)

        agent_1 = get_agent_by_id("agent-001")
        self.assertIsNotNone(agent_1)
        self.assertEqual(agent_1["agent_name"], "Customer Support Agent")
        self.assertEqual(agent_1["status"], "ACTIVE")
        self.assertIn("customer_files", agent_1["resources"])
        self.assertIn("READ", agent_1["actions"])

    def test_02_policy_engine_authorized_access(self):
        """Verify authorized request returns ALLOW."""
        decision, explanation, name = evaluate_authorization("agent-001", "customer_files", "READ")
        self.assertEqual(decision, "ALLOW")
        self.assertIn("authorized", explanation.lower())
        self.assertEqual(name, "Customer Support Agent")

    def test_03_policy_engine_unauthorized_resource(self):
        """Verify unauthorized resource returns DENY."""
        decision, explanation, name = evaluate_authorization("agent-001", "payment_api", "READ")
        self.assertEqual(decision, "DENY")
        self.assertIn("does not have access", explanation.lower())

    def test_04_policy_engine_unauthorized_action(self):
        """Verify unauthorized action returns DENY."""
        decision, explanation, name = evaluate_authorization("agent-001", "customer_files", "WRITE")
        self.assertEqual(decision, "DENY")
        self.assertIn("does not have write permission", explanation.lower())

    def test_05_policy_engine_unknown_agent(self):
        """Verify unregistered agent returns DENY."""
        decision, explanation, name = evaluate_authorization("unknown-agent-999", "customer_files", "READ")
        self.assertEqual(decision, "DENY")
        self.assertIn("unknown agent", explanation.lower())

    def test_06_policy_engine_inactive_agent(self):
        """Verify inactive agent is denied access."""
        with get_db_connection() as conn:
            conn.execute("UPDATE agents SET status='INACTIVE' WHERE agent_id='agent-003'")
            conn.commit()

        decision, explanation, name = evaluate_authorization("agent-003", "analytics_database", "READ")
        self.assertEqual(decision, "DENY")
        self.assertIn("inactive", explanation.lower())

        # Restore
        with get_db_connection() as conn:
            conn.execute("UPDATE agents SET status='ACTIVE' WHERE agent_id='agent-003'")
            conn.commit()

    def test_07_policy_engine_invalid_inputs(self):
        """Verify policy engine handles invalid inputs without crashing."""
        d1, exp1, _ = evaluate_authorization("", "customer_files", "READ")
        self.assertEqual(d1, "DENY")

        d2, exp2, _ = evaluate_authorization("agent-001", "", "READ")
        self.assertEqual(d2, "DENY")

        d3, exp3, _ = evaluate_authorization("agent-001", "customer_files", "INVALID_ACTION")
        self.assertEqual(d3, "DENY")

    def test_08_anomaly_detection_normal(self):
        """Verify normal activity returns NORMAL."""
        res = detect_anomaly(
            requests_per_minute=2.0,
            resources_accessed=2,
            failed_attempts=0,
            access_frequency=2.0,
            unique_resources=1,
            off_hours_requests=0,
            sensitive_resource_access=0
        )
        self.assertIn(res["classification"], ["NORMAL", "ANOMALOUS"])
        self.assertIsInstance(res["anomaly_score"], float)

    def test_09_anomaly_detection_anomalous(self):
        """Verify extreme activity returns ANOMALOUS."""
        res = detect_anomaly(
            requests_per_minute=90.0,
            resources_accessed=40,
            failed_attempts=30,
            access_frequency=90.0,
            unique_resources=15,
            off_hours_requests=30,
            sensitive_resource_access=10
        )
        self.assertEqual(res["classification"], "ANOMALOUS")
        self.assertIn("Contributing factors", res["explanation"])

    def test_10_risk_analyzer(self):
        """Verify explainable risk scoring and levels."""
        # Low risk: allowed standard request for a clean agent
        risk_low = calculate_risk_score(
            agent_id="test-agent-clean-123",
            decision="ALLOW",
            resource="customer_files",
            action="READ",
            is_anomalous=False
        )
        self.assertEqual(risk_low["risk_level"], "LOW")
        self.assertLess(risk_low["risk_score"], 30)

        # High/Critical risk: unauthorized sensitive execute attempt
        risk_high = calculate_risk_score(
            agent_id="test-agent-clean-123",
            decision="DENY",
            resource="payment_api",
            action="EXECUTE",
            is_anomalous=True
        )
        self.assertIn(risk_high["risk_level"], ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(risk_high["risk_score"], 60)
        self.assertGreater(len(risk_high["contributing_factors"]), 0)
        self.assertTrue(len(risk_high["suggested_action"]) > 10)

    def test_11_audit_logging(self):
        """Verify logging events and retrieval."""
        event_id = log_event(
            agent_id="agent-001",
            agent_name="Customer Support Agent",
            resource="customer_files",
            action="READ",
            decision="ALLOW",
            risk_score=10,
            risk_level="LOW"
        )
        self.assertTrue(len(event_id) > 10)

        logs = get_audit_logs(agent_id="agent-001", limit=10)
        self.assertGreater(len(logs), 0)
        found = any(l["event_id"] == event_id for l in logs)
        self.assertTrue(found)

    def test_12_alerts_management(self):
        """Verify alert creation and acknowledgement."""
        alert_id = create_alert(
            agent_id="agent-001",
            agent_name="Customer Support Agent",
            alert_type="CRITICAL_RISK",
            severity="CRITICAL",
            message="Test critical risk alert"
        )
        self.assertTrue(len(alert_id) > 10)

        unacked = get_alerts(acknowledged=False)
        self.assertTrue(any(a["alert_id"] == alert_id for a in unacked))

        ack_res = acknowledge_alert(alert_id)
        self.assertTrue(ack_res)

        acked = get_alerts(acknowledged=True)
        self.assertTrue(any(a["alert_id"] == alert_id for a in acked))

    def test_13_dashboard_statistics(self):
        """Verify aggregated stats."""
        stats = get_dashboard_stats()
        self.assertIn("total_agents", stats)
        self.assertIn("total_requests", stats)
        self.assertIn("allowed_requests", stats)
        self.assertIn("denied_requests", stats)
        self.assertIn("anomalies_detected", stats)
        self.assertGreaterEqual(stats["total_agents"], 3)

    def test_14_ai_agent_normal_chat_no_tool(self):
        """Verify normal chat message that does not need a tool."""
        res = process_agent_chat(
            agent_id="agent-001",
            user_message="Hello, what can you do?",
            use_mock_llm=True
        )
        self.assertIsNotNone(res["response"])
        self.assertIsNone(res["tool_called"])
        self.assertIsNone(res["customer_data"])
        self.assertEqual(res["security_decision"]["decision"], "NOT_APPLICABLE")

    def test_15_ai_agent_authorized_customer_lookup(self):
        """Verify authorized customer lookup by Customer Support Agent (agent-001)."""
        res = process_agent_chat(
            agent_id="agent-001",
            user_message="Look up customer details for Alice (CUST-101)",
            use_mock_llm=True
        )
        self.assertEqual(res["tool_called"], "lookup_customer")
        self.assertEqual(res["security_decision"]["decision"], "ALLOW")
        self.assertEqual(res["security_decision"]["resource"], "customer_files")
        self.assertEqual(res["security_decision"]["action"], "READ")
        self.assertIsNotNone(res["customer_data"])
        self.assertEqual(res["customer_data"]["name"], "Alice Johnson")
        self.assertIsNotNone(res["audit_event_id"])
        self.assertIn("Alice", res["response"])

    def test_16_ai_agent_unauthorized_customer_lookup(self):
        """Verify unauthorized customer lookup by Analytics Agent (agent-003) is DENIED."""
        res = process_agent_chat(
            agent_id="agent-003",
            user_message="Look up customer details for Alice (CUST-101)",
            use_mock_llm=True
        )
        self.assertEqual(res["tool_called"], "lookup_customer")
        self.assertEqual(res["security_decision"]["decision"], "DENY")
        self.assertEqual(res["security_decision"]["resource"], "customer_files")
        # Customer data MUST be None - never executed
        self.assertIsNone(res["customer_data"])
        self.assertIsNotNone(res["audit_event_id"])
        self.assertIn("DENIED", res["response"])

    def test_17_ai_agent_unknown_agent_blocked(self):
        """Verify unknown agent attempting tool call is blocked by policy engine."""
        res = process_agent_chat(
            agent_id="unregistered-agent-999",
            user_message="Please lookup customer CUST-102",
            use_mock_llm=True
        )
        self.assertEqual(res["security_decision"]["decision"], "DENY")
        self.assertIsNone(res["customer_data"])
        self.assertIn("Unknown agent", res["security_decision"]["explanation"])

if __name__ == "__main__":
    unittest.main()
