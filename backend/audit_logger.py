"""
AGENT SHIELD - Audit Logger
Records every agent request and security event in SQLite.
"""

import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Optional, List
from .database import get_db_connection

logger = logging.getLogger(__name__)


def log_event(
    agent_id: str,
    agent_name: str,
    resource: str,
    action: str,
    decision: str,
    denial_reason: Optional[str] = None,
    anomaly_classification: Optional[str] = None,
    anomaly_score: Optional[float] = None,
    risk_score: Optional[int] = None,
    risk_level: Optional[str] = None,
    risk_factors: Optional[list] = None,
    suggested_action: Optional[str] = None,
    request_metadata: Optional[dict] = None
) -> str:
    """Log an audit event and return the event ID."""
    event_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO audit_logs (
                    event_id, timestamp, agent_id, agent_name,
                    resource, action, decision, denial_reason,
                    anomaly_classification, anomaly_score,
                    risk_score, risk_level, risk_factors,
                    suggested_action, request_metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id, timestamp, agent_id, agent_name,
                resource, action, decision, denial_reason,
                anomaly_classification, anomaly_score,
                risk_score, risk_level,
                json.dumps(risk_factors) if risk_factors else None,
                suggested_action,
                json.dumps(request_metadata) if request_metadata else None
            ))
            conn.commit()
        
        logger.info(f"Audit event logged: {event_id} | {agent_id} | {decision}")
        return event_id
    
    except Exception as e:
        logger.error(f"Audit logging error: {e}", exc_info=True)
        return event_id  # Return the ID even if logging failed


def get_audit_logs(
    agent_id: Optional[str] = None,
    decision: Optional[str] = None,
    risk_level: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[dict]:
    """Retrieve audit logs with optional filters."""
    try:
        with get_db_connection() as conn:
            query = "SELECT * FROM audit_logs WHERE 1=1"
            params = []
            
            if agent_id:
                query += " AND agent_id = ?"
                params.append(agent_id)
            
            if decision:
                query += " AND decision = ?"
                params.append(decision.upper())
            
            if risk_level:
                query += " AND risk_level = ?"
                params.append(risk_level.upper())
            
            if date_from:
                query += " AND timestamp >= ?"
                params.append(date_from)
            
            if date_to:
                query += " AND timestamp <= ?"
                params.append(date_to)
            
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            rows = conn.execute(query, params).fetchall()
            result = []
            for row in rows:
                d = dict(row)
                # Parse JSON fields
                try:
                    d["risk_factors"] = json.loads(d["risk_factors"]) if d.get("risk_factors") else []
                except Exception:
                    d["risk_factors"] = []
                try:
                    d["request_metadata"] = json.loads(d["request_metadata"]) if d.get("request_metadata") else {}
                except Exception:
                    d["request_metadata"] = {}
                result.append(d)
            
            return result
    
    except Exception as e:
        logger.error(f"Error fetching audit logs: {e}", exc_info=True)
        return []


def get_audit_log_count(
    agent_id: Optional[str] = None,
    decision: Optional[str] = None,
    risk_level: Optional[str] = None
) -> int:
    """Get total count of matching audit log entries."""
    try:
        with get_db_connection() as conn:
            query = "SELECT COUNT(*) FROM audit_logs WHERE 1=1"
            params = []
            
            if agent_id:
                query += " AND agent_id = ?"
                params.append(agent_id)
            if decision:
                query += " AND decision = ?"
                params.append(decision.upper())
            if risk_level:
                query += " AND risk_level = ?"
                params.append(risk_level.upper())
            
            return conn.execute(query, params).fetchone()[0]
    except Exception:
        return 0


def get_recent_events(limit: int = 10) -> List[dict]:
    """Get the most recent audit events."""
    try:
        with get_db_connection() as conn:
            rows = conn.execute("""
                SELECT event_id, timestamp, agent_id, agent_name,
                       resource, action, decision, risk_score, risk_level,
                       anomaly_classification, denial_reason
                FROM audit_logs
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Error fetching recent events: {e}")
        return []
