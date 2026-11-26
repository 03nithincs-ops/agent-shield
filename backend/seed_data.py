"""
AGENT SHIELD - Synthetic Baseline Data Seeder
Populates realistic historical agent requests and security events across the past 24 hours.

Usage:
    python backend/seed_data.py
"""

import sys
import os
import random
import uuid
import json
from datetime import datetime, timezone, timedelta

# Set up path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from backend.database import get_db_connection, init_database
from backend.policy_engine import evaluate_authorization
from backend.anomaly_detector import detect_anomaly, load_model
from backend.risk_analyzer import calculate_risk_score
from backend.alert_manager import evaluate_and_create_alerts


def seed_historical_activity(num_events: int = 50):
    """Seed realistic historical activity events over the past 24 hours."""
    print(f"🌱 Seeding {num_events} realistic historical events across last 24 hours...")
    
    init_database()
    load_model()
    
    agents = [
        {"id": "agent-001", "name": "Customer Support Agent", "type": "Support"},
        {"id": "agent-002", "name": "Payment Agent", "type": "Financial"},
        {"id": "agent-003", "name": "Analytics Agent", "type": "Analytics"}
    ]
    
    scenarios = [
        # Normal customer support
        ("agent-001", "Customer Support Agent", "customer_files", "READ"),
        ("agent-001", "Customer Support Agent", "support_database", "READ"),
        ("agent-001", "Customer Support Agent", "customer_files", "READ"),
        
        # Payment agent normal
        ("agent-002", "Payment Agent", "transaction_database", "READ"),
        ("agent-002", "Payment Agent", "payment_api", "EXECUTE"),
        ("agent-002", "Payment Agent", "transaction_database", "READ"),
        
        # Analytics agent normal
        ("agent-003", "Analytics Agent", "analytics_database", "READ"),
        ("agent-003", "Analytics Agent", "reports", "WRITE"),
        ("agent-003", "Analytics Agent", "reports", "READ"),
        
        # Suspicious / Unauthorized attempts
        ("agent-001", "Customer Support Agent", "payment_api", "EXECUTE"),
        ("agent-001", "Customer Support Agent", "transaction_database", "READ"),
        ("agent-003", "Analytics Agent", "payment_api", "READ"),
        ("agent-001", "Customer Support Agent", "customer_files", "WRITE"),
    ]
    
    now = datetime.now(timezone.utc)
    
    with get_db_connection() as conn:
        for i in range(num_events):
            # Select scenario (85% authorized, 15% unauthorized)
            if random.random() < 0.82:
                sample = random.choice(scenarios[:9])
            else:
                sample = random.choice(scenarios[9:])
            
            agent_id, agent_name, resource, action = sample
            
            # Timestamp spaced out over the last 24 hours
            minutes_ago = random.randint(5, 1400)
            event_time = (now - timedelta(minutes=minutes_ago)).isoformat()
            
            # Policy evaluation
            decision, explanation, _ = evaluate_authorization(agent_id, resource, action)
            denial_reason = explanation if decision == "DENY" else None
            
            # Simulated anomaly flags for some events
            is_anom = (decision == "DENY" and random.random() < 0.35) or (random.random() < 0.08)
            anomaly_class = "ANOMALOUS" if is_anom else "NORMAL"
            anomaly_score = round(random.uniform(-0.45, -0.15), 4) if is_anom else round(random.uniform(0.1, 0.45), 4)
            
            # Risk score calculation
            risk = calculate_risk_score(
                agent_id=agent_id,
                decision=decision,
                resource=resource,
                action=action,
                is_anomalous=is_anom,
                anomaly_score=anomaly_score,
                agent_name=agent_name
            )
            
            event_id = str(uuid.uuid4())
            
            # Insert audit log
            conn.execute("""
                INSERT INTO audit_logs (
                    event_id, timestamp, agent_id, agent_name,
                    resource, action, decision, denial_reason,
                    anomaly_classification, anomaly_score,
                    risk_score, risk_level, risk_factors,
                    suggested_action, request_metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id, event_time, agent_id, agent_name,
                resource, action, decision, denial_reason,
                anomaly_class, anomaly_score,
                risk["risk_score"], risk["risk_level"],
                json.dumps(risk.get("contributing_factors", [])),
                risk.get("suggested_action"),
                json.dumps({"source": "baseline_activity_generator"})
            ))
            
            # Generate alert for critical/high risk events
            if risk["risk_level"] in ("CRITICAL", "HIGH") or (decision == "DENY" and "payment" in resource):
                alert_id = str(uuid.uuid4())
                severity = "CRITICAL" if risk["risk_level"] == "CRITICAL" else "HIGH"
                conn.execute("""
                    INSERT INTO alerts (
                        alert_id, timestamp, agent_id, agent_name,
                        alert_type, severity, message, details, is_acknowledged
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_id, event_time, agent_id, agent_name,
                    "SECURITY_VIOLATION" if decision == "DENY" else "HIGH_RISK",
                    severity,
                    f"Security signal: {agent_name} attempted {action} on {resource} (Risk: {risk['risk_score']})",
                    json.dumps({"resource": resource, "action": action, "risk_score": risk["risk_score"]}),
                    1 if minutes_ago > 300 else 0  # older alerts acknowledged
                ))
        
        conn.commit()
    
    print(f"✅ Successfully seeded historical activity.")


if __name__ == "__main__":
    seed_historical_activity(45)
