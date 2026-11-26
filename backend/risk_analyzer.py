"""
AGENT SHIELD - Risk Analyzer
Calculates explainable risk scores (0-100) based on security signals.
"""

import logging
from typing import List, Tuple, Optional
from .database import get_db_connection

logger = logging.getLogger(__name__)

SENSITIVE_RESOURCES = {
    "payment_api", "transaction_database", "financial_records",
    "user_credentials", "admin_panel", "system_config", "secret_vault"
}


def calculate_risk_score(
    agent_id: str,
    decision: str,
    resource: str,
    action: str,
    is_anomalous: bool = False,
    anomaly_score: Optional[float] = None,
    agent_name: str = "Unknown"
) -> dict:
    """
    Calculate an explainable risk score (0-100) based on security signals.
    
    Risk contributors:
    - Unauthorized access attempt: +35
    - Sensitive resource targeted: +20
    - Anomaly detection flag: +15
    - Repeated denied requests (last hour): +5 per denial, up to +20
    - High frequency requests: +10
    - Privilege escalation pattern: +25
    """
    score = 0
    factors = []
    
    try:
        with get_db_connection() as conn:
            # Factor 1: Unauthorized access attempt
            if decision == "DENY":
                score += 35
                factors.append("Unauthorized access attempt detected")
            
            # Factor 2: Sensitive resource targeted
            if resource.lower() in SENSITIVE_RESOURCES:
                score += 20
                factors.append(f"Sensitive resource targeted: {resource}")
            
            # Factor 3: Anomaly detection
            if is_anomalous:
                score += 15
                factors.append("Activity classified as anomalous by Isolation Forest")
            
            # Factor 4: Repeated denied requests (last hour)
            recent_denials = conn.execute("""
                SELECT COUNT(*) FROM audit_logs
                WHERE agent_id = ? AND decision = 'DENY'
                AND timestamp > datetime('now', '-1 hour')
            """, (agent_id,)).fetchone()[0]
            
            if recent_denials >= 1:
                denial_score = min(recent_denials * 5, 20)
                score += denial_score
                if recent_denials >= 3:
                    factors.append(f"Repeated denied requests: {recent_denials} in the last hour")
            
            # Factor 5: High request frequency (last minute)
            requests_last_min = conn.execute("""
                SELECT COUNT(*) FROM audit_logs
                WHERE agent_id = ?
                AND timestamp > datetime('now', '-1 minute')
            """, (agent_id,)).fetchone()[0]
            
            if requests_last_min > 15:
                score += 10
                factors.append(f"High request frequency: {requests_last_min} requests/minute")
            
            # Factor 6: Privilege escalation pattern
            # Detecting when a support/low-privilege agent tries EXECUTE on sensitive resources
            agent = conn.execute(
                "SELECT agent_type FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            
            if agent:
                agent_type = agent["agent_type"].lower()
                is_escalation = (
                    decision == "DENY" and
                    action == "EXECUTE" and
                    resource.lower() in SENSITIVE_RESOURCES
                )
                if is_escalation:
                    score += 25
                    factors.append(f"Privilege escalation attempt: {action} on {resource}")
                elif (decision == "DENY" and
                      "support" in agent_type and
                      resource.lower() in SENSITIVE_RESOURCES):
                    score += 15
                    factors.append(f"Support agent attempting access to restricted resource: {resource}")
    
    except Exception as e:
        logger.error(f"Risk calculation error: {e}", exc_info=True)
        # On DB error, use inputs only
        if decision == "DENY":
            score += 35
            factors.append("Unauthorized access attempt")
        if resource.lower() in SENSITIVE_RESOURCES:
            score += 20
            factors.append(f"Sensitive resource: {resource}")
    
    # Cap at 100
    score = min(int(score), 100)
    
    # Determine risk level
    if score < 30:
        level = "LOW"
    elif score < 60:
        level = "MEDIUM"
    elif score < 80:
        level = "HIGH"
    else:
        level = "CRITICAL"
    
    # Build explanation
    if not factors:
        explanation = f"No significant risk indicators detected. Activity appears legitimate."
        suggested_action = "No action required. Continue monitoring."
    else:
        explanation = (
            f"Risk assessment for {agent_name} (Score: {score}/100 - {level}):\n" +
            "\n".join(f"• {f}" for f in factors)
        )
        
        if level == "CRITICAL":
            suggested_action = (
                "IMMEDIATE ACTION REQUIRED: Review agent permissions, investigate all recent "
                "activity, and consider temporarily deactivating this agent."
            )
        elif level == "HIGH":
            suggested_action = (
                "Review agent permissions and audit recent activity. "
                "Consider restricting agent access scope."
            )
        elif level == "MEDIUM":
            suggested_action = (
                "Monitor agent activity closely. Review access patterns "
                "and verify permissions are appropriate."
            )
        else:
            suggested_action = "Continue standard monitoring."
    
    return {
        "agent_id": agent_id,
        "risk_score": score,
        "risk_level": level,
        "contributing_factors": factors,
        "explanation": explanation,
        "suggested_action": suggested_action
    }
