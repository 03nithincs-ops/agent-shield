"""
AGENT SHIELD - FastAPI Routes: Audit Logs, Alerts, Dashboard, Analytics
"""

from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import StreamingResponse
from typing import Optional
import csv
import io
from ..audit_logger import get_audit_logs, get_audit_log_count, get_recent_events
from ..alert_manager import get_alerts, acknowledge_alert
from ..database import get_dashboard_stats, get_db_connection
from ..anomaly_detector import detect_anomaly, get_model_status, load_model
from ..risk_analyzer import calculate_risk_score
from ..schemas import ActivityData, RiskAssessmentRequest

router = APIRouter(tags=["Analytics & Logs"])


# ── Dashboard ──────────────────────────────────────────────────────────────

@router.get("/dashboard/stats")
async def dashboard_stats():
    """Get live dashboard statistics from database."""
    try:
        return get_dashboard_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/activity-chart")
async def activity_chart():
    """Get request activity over last 24 hours for charting."""
    try:
        with get_db_connection() as conn:
            rows = conn.execute("""
                SELECT 
                    strftime('%Y-%m-%d %H:00', timestamp) as hour,
                    COUNT(*) as total,
                    SUM(CASE WHEN decision='ALLOW' THEN 1 ELSE 0 END) as allowed,
                    SUM(CASE WHEN decision='DENY' THEN 1 ELSE 0 END) as denied
                FROM audit_logs
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY hour
                ORDER BY hour
            """).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/agent-activity")
async def agent_activity():
    """Get per-agent request counts."""
    try:
        with get_db_connection() as conn:
            rows = conn.execute("""
                SELECT agent_name, COUNT(*) as requests,
                       SUM(CASE WHEN decision='ALLOW' THEN 1 ELSE 0 END) as allowed,
                       SUM(CASE WHEN decision='DENY' THEN 1 ELSE 0 END) as denied
                FROM audit_logs
                GROUP BY agent_id, agent_name
                ORDER BY requests DESC
                LIMIT 10
            """).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/risk-distribution")
async def risk_distribution():
    """Get risk level distribution."""
    try:
        with get_db_connection() as conn:
            rows = conn.execute("""
                SELECT risk_level, COUNT(*) as count
                FROM audit_logs
                WHERE risk_level IS NOT NULL
                GROUP BY risk_level
            """).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/recent-events")
async def recent_events(limit: int = Query(10, ge=1, le=100)):
    """Get recent audit events for dashboard."""
    try:
        return get_recent_events(limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Audit Logs ─────────────────────────────────────────────────────────────

@router.get("/audit-logs")
async def list_audit_logs(
    agent_id: Optional[str] = Query(None),
    decision: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Retrieve audit logs with filtering."""
    try:
        logs = get_audit_logs(agent_id, decision, risk_level, date_from, date_to, limit, offset)
        total = get_audit_log_count(agent_id, decision, risk_level)
        return {"logs": logs, "total": total, "limit": limit, "offset": offset}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/audit-logs/export")
async def export_audit_logs(
    agent_id: Optional[str] = Query(None),
    decision: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None)
):
    """Export audit logs as CSV."""
    try:
        logs = get_audit_logs(agent_id, decision, risk_level, limit=10000)
        
        output = io.StringIO()
        if logs:
            fieldnames = [k for k in logs[0].keys() if k != "request_metadata"]
            writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(logs)
        
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=agent_shield_audit_logs.csv"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Alerts ─────────────────────────────────────────────────────────────────

@router.get("/alerts")
async def list_alerts(
    acknowledged: Optional[bool] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500)
):
    """Get security alerts."""
    try:
        return get_alerts(acknowledged, severity, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/alerts/{alert_id}/acknowledge")
async def ack_alert(alert_id: str):
    """Acknowledge a security alert."""
    success = acknowledge_alert(alert_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found or already acknowledged.")
    return {"success": True, "alert_id": alert_id}


# ── Anomaly Detection ──────────────────────────────────────────────────────

@router.post("/anomaly/detect")
async def run_anomaly_detection(activity: ActivityData):
    """Run Isolation Forest anomaly detection on activity data."""
    try:
        result = detect_anomaly(
            requests_per_minute=activity.requests_per_minute,
            resources_accessed=activity.resources_accessed,
            failed_attempts=activity.failed_attempts,
            access_frequency=activity.access_frequency,
            unique_resources=activity.unique_resources,
            off_hours_requests=activity.off_hours_requests,
            sensitive_resource_access=activity.sensitive_resource_access
        )
        result["agent_id"] = activity.agent_id
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/anomaly/model-status")
async def model_status():
    """Get the status of the Isolation Forest model."""
    return get_model_status()


@router.post("/anomaly/train")
async def train_model_endpoint():
    """Trigger model training/retraining."""
    from ..anomaly_detector import train_model
    success = train_model()
    if not success:
        raise HTTPException(status_code=500, detail="Model training failed.")
    return {"success": True, "message": "Isolation Forest model trained successfully."}


# ── Risk Analysis ──────────────────────────────────────────────────────────

@router.post("/risk/assess")
async def assess_risk(request: RiskAssessmentRequest):
    """Calculate risk score for an agent."""
    try:
        result = calculate_risk_score(
            agent_id=request.agent_id,
            decision="DENY" if request.recent_denied > 0 else "ALLOW",
            resource="general",
            action="READ",
            is_anomalous=request.is_anomalous,
            anomaly_score=request.anomaly_score,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/risk/agent/{agent_id}")
async def get_agent_risk_history(agent_id: str):
    """Get risk score history for an agent."""
    try:
        with get_db_connection() as conn:
            rows = conn.execute("""
                SELECT timestamp, risk_score, risk_level, decision, resource, action
                FROM audit_logs
                WHERE agent_id = ? AND risk_score IS NOT NULL
                ORDER BY timestamp DESC
                LIMIT 50
            """, (agent_id,)).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
