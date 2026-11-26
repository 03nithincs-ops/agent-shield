"""
AGENT SHIELD - Alert Manager
Generates and manages security alerts based on threat conditions.
"""

import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Optional, List
from .database import get_db_connection

logger = logging.getLogger(__name__)


def create_alert(
    agent_id: str,
    agent_name: str,
    alert_type: str,
    severity: str,
    message: str,
    details: Optional[dict] = None
) -> str:
    """Create a new security alert and return its ID."""
    alert_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO alerts (
                    alert_id, timestamp, agent_id, agent_name,
                    alert_type, severity, message, details, is_acknowledged
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
            """, (
                alert_id, timestamp, agent_id, agent_name,
                alert_type, severity.upper(), message,
                json.dumps(details) if details else None
            ))
            conn.commit()
        
        logger.warning(f"ALERT [{severity}]: {message} | Agent: {agent_id}")
        return alert_id
    
    except Exception as e:
        logger.error(f"Alert creation error: {e}", exc_info=True)
        return alert_id


def evaluate_and_create_alerts(
    agent_id: str,
    agent_name: str,
    decision: str,
    resource: str,
    action: str,
    risk_score: int,
    risk_level: str,
    is_anomalous: bool,
    is_privilege_escalation: bool = False
) -> List[str]:
    """
    Evaluate conditions and create alerts as needed.
    Returns list of created alert IDs.
    """
    alert_ids = []
    
    try:
        with get_db_connection() as conn:
            # Alert 1: Critical risk
            if risk_level == "CRITICAL":
                alert_id = create_alert(
                    agent_id, agent_name,
                    "CRITICAL_RISK",
                    "CRITICAL",
                    f"Critical risk detected for agent '{agent_name}' (Score: {risk_score}/100)",
                    {"resource": resource, "action": action, "risk_score": risk_score}
                )
                alert_ids.append(alert_id)
            
            # Alert 2: Privilege escalation attempt
            if is_privilege_escalation and decision == "DENY":
                alert_id = create_alert(
                    agent_id, agent_name,
                    "PRIVILEGE_ESCALATION",
                    "HIGH",
                    f"Privilege escalation attempt by '{agent_name}': {action} on {resource}",
                    {"resource": resource, "action": action}
                )
                alert_ids.append(alert_id)
            
            # Alert 3: Repeated unauthorized attempts
            recent_denials = conn.execute("""
                SELECT COUNT(*) FROM audit_logs
                WHERE agent_id = ? AND decision = 'DENY'
                AND timestamp > datetime('now', '-10 minutes')
            """, (agent_id,)).fetchone()[0]
            
            if recent_denials >= 5:
                # Only create alert if not already alerted in last 5 min
                existing = conn.execute("""
                    SELECT COUNT(*) FROM alerts
                    WHERE agent_id = ? AND alert_type = 'REPEATED_UNAUTHORIZED'
                    AND timestamp > datetime('now', '-5 minutes')
                """, (agent_id,)).fetchone()[0]
                
                if existing == 0:
                    alert_id = create_alert(
                        agent_id, agent_name,
                        "REPEATED_UNAUTHORIZED",
                        "HIGH",
                        f"Repeated unauthorized attempts by '{agent_name}': {recent_denials} denials in 10 minutes",
                        {"denied_count": recent_denials}
                    )
                    alert_ids.append(alert_id)
            
            # Alert 4: Anomalous activity
            if is_anomalous:
                # Check if anomaly alert already exists recently
                existing = conn.execute("""
                    SELECT COUNT(*) FROM alerts
                    WHERE agent_id = ? AND alert_type = 'ANOMALOUS_ACTIVITY'
                    AND timestamp > datetime('now', '-5 minutes')
                """, (agent_id,)).fetchone()[0]
                
                if existing == 0:
                    alert_id = create_alert(
                        agent_id, agent_name,
                        "ANOMALOUS_ACTIVITY",
                        "MEDIUM",
                        f"Anomalous activity detected for agent '{agent_name}'",
                        {"resource": resource, "action": action}
                    )
                    alert_ids.append(alert_id)
            
            # Alert 5: Suspicious request frequency
            requests_last_minute = conn.execute("""
                SELECT COUNT(*) FROM audit_logs
                WHERE agent_id = ?
                AND timestamp > datetime('now', '-1 minute')
            """, (agent_id,)).fetchone()[0]
            
            if requests_last_minute > 20:
                existing = conn.execute("""
                    SELECT COUNT(*) FROM alerts
                    WHERE agent_id = ? AND alert_type = 'HIGH_FREQUENCY'
                    AND timestamp > datetime('now', '-5 minutes')
                """, (agent_id,)).fetchone()[0]
                
                if existing == 0:
                    alert_id = create_alert(
                        agent_id, agent_name,
                        "HIGH_FREQUENCY",
                        "MEDIUM",
                        f"High frequency requests from '{agent_name}': {requests_last_minute} req/min",
                        {"requests_per_minute": requests_last_minute}
                    )
                    alert_ids.append(alert_id)
    
    except Exception as e:
        logger.error(f"Alert evaluation error: {e}", exc_info=True)
    
    return alert_ids


def get_alerts(
    acknowledged: Optional[bool] = None,
    severity: Optional[str] = None,
    limit: int = 50
) -> List[dict]:
    """Retrieve alerts with optional filters."""
    try:
        with get_db_connection() as conn:
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            
            if acknowledged is not None:
                query += " AND is_acknowledged = ?"
                params.append(1 if acknowledged else 0)
            
            if severity:
                query += " AND severity = ?"
                params.append(severity.upper())
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            rows = conn.execute(query, params).fetchall()
            result = []
            for row in rows:
                d = dict(row)
                try:
                    d["details"] = json.loads(d["details"]) if d.get("details") else {}
                except Exception:
                    d["details"] = {}
                result.append(d)
            
            return result
    
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return []


def acknowledge_alert(alert_id: str) -> bool:
    """Mark an alert as acknowledged."""
    try:
        with get_db_connection() as conn:
            conn.execute(
                "UPDATE alerts SET is_acknowledged = 1 WHERE alert_id = ?",
                (alert_id,)
            )
            conn.commit()
            return True
    except Exception as e:
        logger.error(f"Error acknowledging alert: {e}")
        return False
