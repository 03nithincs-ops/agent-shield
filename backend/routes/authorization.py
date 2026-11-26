"""
AGENT SHIELD - FastAPI Routes: Authorization & Core Operations
"""

from fastapi import APIRouter, HTTPException
from datetime import datetime, timezone

from ..schemas import AuthorizationRequest, AuthorizationResponse
from ..policy_engine import evaluate_authorization, check_privilege_escalation, get_agent_recent_stats
from ..anomaly_detector import detect_anomaly, load_model
from ..risk_analyzer import calculate_risk_score
from ..audit_logger import log_event
from ..alert_manager import evaluate_and_create_alerts
from ..database import get_db_connection

router = APIRouter(prefix="/authorize", tags=["Authorization"])


@router.post("/", response_model=dict)
async def authorize_request(request: AuthorizationRequest):
    """
    Core authorization endpoint. 
    Evaluates permissions, detects anomalies, calculates risk, and logs everything.
    """
    agent_id = request.agent_id.strip()
    resource = request.resource.strip().lower()
    action = request.action.value
    
    # Step 1: Policy Engine Authorization (MUST happen first)
    decision, explanation, agent_name = evaluate_authorization(agent_id, resource, action)
    
    # Step 2: Check privilege escalation
    is_escalation = False
    if decision == "DENY":
        is_escalation = check_privilege_escalation(agent_id, resource, action)
    
    # Step 3: Get agent activity stats for anomaly detection
    stats = get_agent_recent_stats(agent_id)
    
    # Step 4: Anomaly Detection (independent of authorization)
    anomaly_result = detect_anomaly(
        requests_per_minute=stats.get("requests_last_minute", 0),
        resources_accessed=stats.get("total_requests", 0),
        failed_attempts=stats.get("recent_denied", 0),
        access_frequency=stats.get("requests_last_minute", 0),
        unique_resources=1,
        off_hours_requests=0,
        sensitive_resource_access=stats.get("sensitive_access", 0)
    )
    
    is_anomalous = anomaly_result["classification"] == "ANOMALOUS"
    
    # Step 5: Risk Assessment
    risk_result = calculate_risk_score(
        agent_id=agent_id,
        decision=decision,
        resource=resource,
        action=action,
        is_anomalous=is_anomalous,
        anomaly_score=anomaly_result.get("anomaly_score"),
        agent_name=agent_name
    )
    
    # Step 6: Audit Logging
    denial_reason = explanation if decision == "DENY" else None
    event_id = log_event(
        agent_id=agent_id,
        agent_name=agent_name,
        resource=resource,
        action=action,
        decision=decision,
        denial_reason=denial_reason,
        anomaly_classification=anomaly_result["classification"],
        anomaly_score=anomaly_result.get("anomaly_score"),
        risk_score=risk_result["risk_score"],
        risk_level=risk_result["risk_level"],
        risk_factors=risk_result.get("contributing_factors"),
        suggested_action=risk_result.get("suggested_action"),
        request_metadata=request.metadata
    )
    
    # Step 7: Alert Generation
    evaluate_and_create_alerts(
        agent_id=agent_id,
        agent_name=agent_name,
        decision=decision,
        resource=resource,
        action=action,
        risk_score=risk_result["risk_score"],
        risk_level=risk_result["risk_level"],
        is_anomalous=is_anomalous,
        is_privilege_escalation=is_escalation
    )
    
    # Step 8: Simulated Resource Operation (ONLY if ALLOWED)
    resource_operation = None
    if decision == "ALLOW":
        resource_operation = _simulate_resource_operation(resource, action, agent_name)
    
    return {
        "decision": decision,
        "event_id": event_id,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "resource": resource,
        "action": action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "explanation": explanation,
        "denial_reason": denial_reason,
        "is_privilege_escalation": is_escalation,
        "anomaly": {
            "classification": anomaly_result["classification"],
            "anomaly_score": anomaly_result.get("anomaly_score"),
            "explanation": anomaly_result.get("explanation", "")
        },
        "risk": {
            "score": risk_result["risk_score"],
            "level": risk_result["risk_level"],
            "factors": risk_result.get("contributing_factors", []),
            "explanation": risk_result.get("explanation", ""),
            "suggested_action": risk_result.get("suggested_action", "")
        },
        "resource_operation": resource_operation
    }


def _simulate_resource_operation(resource: str, action: str, agent_name: str) -> dict:
    """Simulate a resource operation (synthetic data only)."""
    simulated_data = {
        "customer_files": {
            "READ": {"records": 42, "data": "Synthetic customer support tickets retrieved."},
            "WRITE": {"status": "written", "data": "Synthetic customer record updated."},
        },
        "support_database": {
            "READ": {"tickets": 15, "data": "Synthetic support case history retrieved."},
            "WRITE": {"status": "written", "data": "Synthetic support record updated."},
        },
        "transaction_database": {
            "READ": {"transactions": 100, "data": "Synthetic transaction history retrieved."},
            "EXECUTE": {"status": "executed", "data": "Synthetic transaction query executed."},
        },
        "payment_api": {
            "READ": {"balance": "$50,000 (synthetic)", "data": "Synthetic balance check completed."},
            "EXECUTE": {"status": "simulated", "data": "Synthetic payment operation simulated."},
        },
        "analytics_database": {
            "READ": {"rows": 10000, "data": "Synthetic analytics dataset retrieved."},
            "WRITE": {"status": "written", "data": "Synthetic analytics results stored."},
        },
        "reports": {
            "READ": {"reports": 5, "data": "Synthetic reports retrieved."},
            "WRITE": {"status": "written", "data": "Synthetic report generated and stored."},
        }
    }
    
    resource_ops = simulated_data.get(resource, {})
    op = resource_ops.get(action, {
        "status": "simulated",
        "data": f"Synthetic {action} on {resource} completed."
    })
    
    return {
        "simulated": True,
        "resource": resource,
        "action": action,
        "result": op,
        "note": "This is a simulated operation using synthetic data only."
    }
