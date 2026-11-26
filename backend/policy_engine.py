"""
AGENT SHIELD - Runtime Policy Engine
Backend authorization enforcement. Never trust frontend decisions.
"""

import logging
from datetime import datetime
from typing import Tuple, Optional
from .database import get_db_connection, get_agent_by_id

logger = logging.getLogger(__name__)

SENSITIVE_RESOURCES = {
    "payment_api", "transaction_database", "financial_records",
    "user_credentials", "admin_panel", "system_config", "secret_vault"
}

VALID_ACTIONS = {"READ", "WRITE", "EXECUTE"}


def evaluate_authorization(
    agent_id: str,
    resource: str,
    action: str
) -> Tuple[str, str, Optional[str]]:
    """
    Core authorization evaluation. Returns (decision, explanation, agent_name).
    
    Authorization pipeline:
    1. Validate inputs
    2. Check agent exists
    3. Check agent is active
    4. Check resource permission
    5. Check action permission
    """
    try:
        # Step 1: Input validation
        if not agent_id or not agent_id.strip():
            return "DENY", "Missing or empty agent ID", "UNKNOWN"
        
        if not resource or not resource.strip():
            return "DENY", "Missing or empty resource", "UNKNOWN"
        
        if not action or action.upper() not in VALID_ACTIONS:
            return "DENY", f"Invalid action: {action}. Must be READ, WRITE, or EXECUTE", "UNKNOWN"
        
        agent_id = agent_id.strip()
        resource = resource.strip().lower()
        action = action.upper()
        
        # Step 2: Check agent exists
        with get_db_connection() as conn:
            agent = conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            
            if not agent:
                logger.warning(f"Policy DENY: Unknown agent '{agent_id}'")
                return "DENY", f"Unknown agent ID: {agent_id}. Agent not registered.", "UNKNOWN"
            
            agent_name = agent["agent_name"]
            
            # Step 3: Check agent is active
            if agent["status"] != "ACTIVE":
                logger.warning(f"Policy DENY: Inactive agent '{agent_id}'")
                return "DENY", f"Agent '{agent_name}' is {agent['status']}. Access denied.", agent_name
            
            # Step 4 & 5: Check resource and action permissions
            permission = conn.execute("""
                SELECT * FROM permissions
                WHERE agent_id = ? AND resource = ? AND action = ?
            """, (agent_id, resource, action)).fetchone()
            
            if not permission:
                # Check if agent has the resource but not the action
                resource_exists = conn.execute("""
                    SELECT * FROM permissions WHERE agent_id = ? AND resource = ?
                """, (agent_id, resource)).fetchone()
                
                if resource_exists:
                    allowed_actions = conn.execute("""
                        SELECT action FROM permissions WHERE agent_id = ? AND resource = ?
                    """, (agent_id, resource)).fetchall()
                    allowed = [r["action"] for r in allowed_actions]
                    reason = (
                        f"Agent '{agent_name}' does not have {action} permission on "
                        f"'{resource}'. Allowed actions: {', '.join(allowed)}."
                    )
                else:
                    reason = (
                        f"Agent '{agent_name}' does not have access to resource '{resource}'."
                    )
                
                logger.warning(f"Policy DENY: {reason}")
                return "DENY", reason, agent_name
            
            # All checks passed
            explanation = (
                f"Agent '{agent_name}' is authorized to {action} resource '{resource}'."
            )
            logger.info(f"Policy ALLOW: {explanation}")
            return "ALLOW", explanation, agent_name
    
    except Exception as e:
        logger.error(f"Policy engine error: {e}", exc_info=True)
        # On any internal error, default to DENY (fail-secure)
        return "DENY", "Authorization service error. Access denied for security.", "UNKNOWN"


def check_privilege_escalation(agent_id: str, resource: str, action: str) -> bool:
    """
    Detect if this request looks like a privilege escalation attempt.
    Returns True if escalation is suspected.
    """
    sensitive = resource.lower() in SENSITIVE_RESOURCES
    
    try:
        with get_db_connection() as conn:
            agent = conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            
            if not agent:
                return False
            
            # Check if agent type warrants escalation warning
            agent_type = agent["agent_type"].lower() if agent else ""
            
            # Support agent accessing payment/financial resources
            if "support" in agent_type and resource in {"payment_api", "transaction_database"}:
                return True
            
            # Any agent trying EXECUTE on admin-level resources
            if action == "EXECUTE" and resource in {"admin_panel", "system_config", "secret_vault"}:
                return True
            
            # Check recent denied attempts on sensitive resources
            recent_denials = conn.execute("""
                SELECT COUNT(*) FROM audit_logs
                WHERE agent_id = ? AND decision = 'DENY' AND resource = ?
                AND timestamp > datetime('now', '-10 minutes')
            """, (agent_id, resource)).fetchone()[0]
            
            if recent_denials >= 3 and sensitive:
                return True
    
    except Exception as e:
        logger.error(f"Privilege escalation check error: {e}")
    
    return False


def get_agent_recent_stats(agent_id: str) -> dict:
    """Get recent request statistics for an agent."""
    try:
        with get_db_connection() as conn:
            stats = {}
            
            stats["total_requests"] = conn.execute(
                "SELECT COUNT(*) FROM audit_logs WHERE agent_id = ?", (agent_id,)
            ).fetchone()[0]
            
            stats["recent_denied"] = conn.execute("""
                SELECT COUNT(*) FROM audit_logs
                WHERE agent_id = ? AND decision = 'DENY'
                AND timestamp > datetime('now', '-1 hour')
            """, (agent_id,)).fetchone()[0]
            
            stats["requests_last_minute"] = conn.execute("""
                SELECT COUNT(*) FROM audit_logs
                WHERE agent_id = ?
                AND timestamp > datetime('now', '-1 minute')
            """, (agent_id,)).fetchone()[0]
            
            stats["sensitive_access"] = conn.execute("""
                SELECT COUNT(*) FROM audit_logs
                WHERE agent_id = ? AND decision = 'DENY'
                AND resource IN ('payment_api', 'transaction_database', 'admin_panel', 'system_config')
                AND timestamp > datetime('now', '-1 hour')
            """, (agent_id,)).fetchone()[0]
            
            return stats
    except Exception as e:
        logger.error(f"Error getting agent stats: {e}")
        return {
            "total_requests": 0, "recent_denied": 0,
            "requests_last_minute": 0, "sensitive_access": 0
        }
