"""Central Security Gateway for AGENT SHIELD.

Every protected agent tool request MUST pass through SecurityGateway.handle_tool_request().
End-to-end pipeline (AVISHKAR'26 Problem Statement 9):
1. Authentication (SHA-256 credential)
2. Tool & Argument Validation + Permission Registry & Policy Decision
3. Behaviour Baseline Comparison & Isolation Forest Anomaly Detection
4. Explainable Risk Assessment (0-100, distinct from attack probability)
5. Enforcement Decision (BLOCK / REQUIRE_APPROVAL / MONITOR / ALLOW; fail-closed)
6. Protected Operation Execution (only if permitted)
7. Tamper-Evident SHA-256 Audit Record
8. Security Alert / Approval Queue Update
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.approval_workflow import ApprovalWorkflow
from backend.audit_engine import AuditEngine
from backend.auth import AuthService
from backend.behaviour_monitor import BehaviourAssessment, BehaviourMonitoringEngine
from backend.database import DatabaseManager
from backend.enforcement_engine import EnforcementEngine
from backend.policy_engine import PolicyEngine, PolicyEvaluation
from backend.risk_engine import RiskAssessmentEngine
from backend.tool_registry import ProtectedToolRegistry


class SecurityGateway:
    """Central runtime security gateway intercepting all protected AI agent tool calls."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self.auth = AuthService(db)
        self.policy = PolicyEngine(db)
        self.behaviour = BehaviourMonitoringEngine(db)
        self.risk = RiskAssessmentEngine()
        self.enforcement = EnforcementEngine()
        self.tools = ProtectedToolRegistry(db)
        self.audit = AuditEngine(db)
        self.approvals = ApprovalWorkflow(
            db=db,
            auth=self.auth,
            policy=self.policy,
            behaviour=self.behaviour,
            risk=self.risk,
            tools=self.tools,
            audit=self.audit,
        )

    def _create_alert(
        self,
        *,
        event_id: str,
        agent_id: str,
        agent_name: str,
        severity: str,
        category: str,
        decision: str,
        risk_score: float,
        title: str,
        reasons: List[str],
    ) -> str:
        alert_id = f"alt-{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc).isoformat()
        with self.db.write_transaction() as conn:
            conn.execute(
                """
                INSERT INTO security_alerts (
                    alert_id, event_id, agent_id, agent_name,
                    severity, category, decision, risk_score,
                    title, reasons, acknowledged, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    alert_id,
                    event_id,
                    agent_id,
                    agent_name,
                    severity,
                    category,
                    decision,
                    round(float(risk_score), 2),
                    title,
                    json.dumps(reasons),
                    now,
                ),
            )
        return alert_id

    def handle_tool_request(
        self,
        *,
        credential: Optional[str],
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        prompt_context: Optional[str] = None,
        simulated_hour: Optional[int] = None,
        untrusted_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Intercept, evaluate, enforce, and audit a protected tool request.

        Note: `untrusted_agent_id` is explicitly ignored for identity resolution;
        identity is derived strictly from `credential`.
        """
        args = arguments if isinstance(arguments, dict) else {}
        event_id = f"evt-{uuid.uuid4().hex[:12]}"

        # Step 1: Authenticate agent strictly from credential
        auth_res = self.auth.authenticate_agent(credential)
        agent_id = auth_res.agent.agent_id if auth_res.agent else "UNAUTHENTICATED"
        agent_name = auth_res.agent.name if auth_res.agent else "Unauthenticated Caller"

        # Step 2: Validate tool name & arguments
        val_ok, val_reason, tool_def = self.tools.validate_request(tool_name, args)
        resource = tool_def.resource if tool_def else "unknown"
        action = tool_def.action if tool_def else "unknown"

        # Step 3: Live Permission Registry & Policy Evaluation
        if auth_res.authenticated and auth_res.agent and val_ok and tool_def:
            policy_res = self.policy.evaluate(
                agent_id=agent_id,
                agent_available_tools=auth_res.agent.available_tools,
                tool_name=tool_name,
                resource=resource,
                action=action,
                arguments=args,
                prompt_context=prompt_context,
            )
        elif not auth_res.authenticated:
            policy_res = PolicyEvaluation(
                allowed=False,
                requires_approval=False,
                reason="Skipped policy check because authentication failed.",
            )
        else:
            policy_res = PolicyEvaluation(
                allowed=False,
                requires_approval=False,
                reason=f"Tool/argument validation failed: {val_reason}",
            )

        # Step 4: Per-Agent Behaviour Baseline Comparison & Isolation Forest Anomaly Detection
        if auth_res.authenticated and auth_res.agent:
            try:
                beh_res = self.behaviour.evaluate(
                    agent_id=agent_id,
                    tool_name=tool_name,
                    resource=resource,
                    action=action,
                    arguments=args,
                    is_sensitive_tool=bool(tool_def.sensitive) if tool_def else True,
                    policy_allowed=policy_res.allowed,
                    simulated_hour=simulated_hour,
                )
            except Exception as exc:
                beh_res = BehaviourAssessment(
                    status="ANOMALOUS_BLOCK",
                    reasons=[f"Behaviour monitoring service failure (fail-closed): {exc}"],
                )
        else:
            beh_res = BehaviourAssessment(
                status="NORMAL",
                reasons=["Unauthenticated request"],
            )

        # Step 5: Explainable Risk Assessment (0-100, distinct from attack probability)
        risk_res = self.risk.assess(
            authenticated=auth_res.authenticated,
            resource=resource,
            action=action,
            arguments=args,
            policy=policy_res,
            behaviour=beh_res,
        )

        # Step 6: Enforcement Decision (ML anomaly can NEVER override explicit permission denial)
        enf = self.enforcement.decide(
            auth=auth_res,
            validation_ok=val_ok,
            validation_reason=val_reason,
            policy=policy_res,
            behaviour=beh_res,
            risk=risk_res,
        )

        # Step 7: Execute or hold ONLY if enforcement permits AND audit logging succeeds (fail-closed)
        execution_payload: Optional[Dict[str, Any]] = None
        approval_record: Optional[Dict[str, Any]] = None
        execution_status = "NOT_EXECUTED"
        record_ids: List[str] = []

        if enf.decision == "REQUIRE_APPROVAL":
            execution_status = "PENDING_APPROVAL"
            approval_record = self.approvals.create_request(
                event_id=event_id,
                agent_id=agent_id,
                agent_name=agent_name,
                tool_name=tool_name,
                resource=resource,
                action=action,
                arguments=args,
                reason="; ".join(enf.reasons),
                risk_score=risk_res.score,
            )

        try:
            if enf.should_execute:
                execution_payload = self.tools.execute_tool(tool_name, args, agent_id)
                record_ids = execution_payload.get("record_ids", [])
                execution_status = (
                    f"EXECUTED ({execution_payload.get('record_count', 0)} record(s))"
                )
            audit_meta = self.audit.record_event(
                event_id=event_id,
                authenticated_agent=agent_id,
                agent_name=agent_name,
                requested_resource=resource,
                requested_action=action,
                tool_name=tool_name,
                auth_result="AUTHENTICATED" if auth_res.authenticated else f"FAILED: {auth_res.reason}",
                policy_result=("ALLOW" if policy_res.allowed else "DENY") + f": {policy_res.reason}",
                behaviour_result=f"{beh_res.status} | ML_outlier={beh_res.ml_is_anomaly} ({beh_res.anomaly_score})",
                risk_score=risk_res.score,
                final_decision=enf.decision,
                execution_result=execution_status,
                details={
                    "arguments": args,
                    "prompt_context_present": bool(prompt_context),
                    "untrusted_agent_id_ignored": untrusted_agent_id,
                    "risk_level": risk_res.level,
                    "risk_breakdown": risk_res.breakdown,
                    "risk_factors": risk_res.factors,
                    "risk_disclaimer": risk_res.disclaimer,
                    "behaviour_metrics": beh_res.metrics,
                    "detector_mode": beh_res.detector_mode,
                    "anomaly_score": beh_res.anomaly_score,
                    "ml_is_anomaly": beh_res.ml_is_anomaly,
                    "reasons": enf.reasons,
                    "record_ids": record_ids,
                    "approval_id": approval_record["approval_id"] if approval_record else None,
                },
            )
        except Exception as exc:
            return {
                "event_id": event_id,
                "decision": "BLOCK",
                "executed": False,
                "fail_closed": True,
                "authenticated_agent": agent_id,
                "agent_name": agent_name,
                "tool_name": tool_name,
                "resource": resource,
                "action": action,
                "risk_score": 100.0,
                "risk_level": "CRITICAL",
                "risk_breakdown": {
                    "resource_action_sensitivity": 0.0,
                    "policy_and_injection": 100.0,
                    "behaviour_rules": 0.0,
                    "ml_isolation_forest": 0.0,
                },
                "risk_disclaimer": risk_res.disclaimer,
                "reasons": [f"Mandatory security/audit pipeline failure (fail-closed): {exc}"],
                "data": None,
                "approval_request": None,
                "audit": None,
            }

        # Step 8: Record activity log (trusted baselines are NEVER retrained from incoming traffic)
        if auth_res.authenticated:
            self.behaviour.record_activity(
                agent_id=agent_id,
                tool_name=tool_name,
                resource=resource,
                action=action,
                record_ids=record_ids,
                decision=enf.decision,
                authorized=policy_res.allowed,
                sensitive_op=bool(tool_def.sensitive) if tool_def else False,
                risk_score=risk_res.score,
                details={"event_id": event_id, "reasons": enf.reasons},
            )

        # Step 9: Create security alert if flagged
        alert_id: Optional[str] = None
        if enf.create_alert:
            if not auth_res.authenticated:
                category = "AUTHENTICATION_FAILURE"
                title = f"Authentication Failure on {tool_name}"
            elif policy_res.injection_detected:
                category = "PROMPT_INJECTION"
                title = f"Prompt Injection Blocked ({agent_name})"
            elif enf.decision == "REQUIRE_APPROVAL":
                category = "APPROVAL_REQUIRED"
                title = f"Approval Required: {tool_name} by {agent_name}"
            elif beh_res.status in ("MONITOR", "ANOMALOUS_BLOCK"):
                category = "BEHAVIOUR_ANOMALY"
                title = f"Behaviour / ML Anomaly ({enf.decision}) by {agent_name}"
            else:
                category = "UNAUTHORIZED_ACCESS"
                title = f"Unauthorized Access Blocked: {agent_name} -> {resource}:{action}"

            alert_id = self._create_alert(
                event_id=event_id,
                agent_id=agent_id,
                agent_name=agent_name,
                severity=enf.alert_severity,
                category=category,
                decision=enf.decision,
                risk_score=risk_res.score,
                title=title,
                reasons=enf.reasons,
            )

        pipeline_trace = [
            {"stage": "1. Authentication", "outcome": "PASS" if auth_res.authenticated else "FAIL", "detail": f"{agent_id} ({auth_res.reason})"},
            {"stage": "2. Permission Registry & Policy", "outcome": "ALLOW" if policy_res.allowed else "DENY", "detail": policy_res.reason},
            {
                "stage": "3. Behaviour Baseline & Isolation Forest",
                "outcome": beh_res.status,
                "detail": f"detector={beh_res.detector_mode}, ml_outlier={beh_res.ml_is_anomaly}, score={beh_res.anomaly_score}",
            },
            {
                "stage": "4. Explainable Risk Assessment",
                "outcome": f"{risk_res.score}/100 ({risk_res.level})",
                "detail": f"breakdown={risk_res.breakdown}",
            },
            {"stage": "5. Enforcement Decision", "outcome": enf.decision, "detail": "; ".join(enf.reasons)},
            {"stage": "6. Protected Tool Execution", "outcome": execution_status, "detail": f"executed={bool(execution_payload and execution_payload.get('executed'))}"},
            {"stage": "7. Tamper-Evident SHA-256 Audit", "outcome": "RECORDED", "detail": f"hash={audit_meta['current_hash'][:16]}..."},
            {"stage": "8. Alerts & Approval Queue", "outcome": alert_id or "NONE", "detail": f"approval={approval_record['approval_id'] if approval_record else 'none'}"},
        ]

        return {
            "event_id": event_id,
            "decision": enf.decision,
            "executed": bool(execution_payload and execution_payload.get("executed")),
            "authenticated_agent": agent_id,
            "agent_name": agent_name,
            "tool_name": tool_name,
            "resource": resource,
            "action": action,
            "risk_score": risk_res.score,
            "risk_level": risk_res.level,
            "risk_breakdown": risk_res.breakdown,
            "risk_factors": risk_res.factors,
            "risk_disclaimer": risk_res.disclaimer,
            "reasons": enf.reasons,
            "behaviour": {
                "status": beh_res.status,
                "metrics": beh_res.metrics,
                "baseline_profile": beh_res.baseline_profile,
                "rule_reasons": beh_res.rule_reasons,
                "ml_reasons": beh_res.ml_reasons,
                "ml_is_anomaly": beh_res.ml_is_anomaly,
                "anomaly_score": beh_res.anomaly_score,
                "ml_severity_points": beh_res.ml_severity_points,
                "detector_mode": beh_res.detector_mode,
            },
            "pipeline_trace": pipeline_trace,
            "data": execution_payload,
            "approval_request": approval_record,
            "alert_id": alert_id,
            "audit": audit_meta,
        }

    def list_alerts(self, limit: int = 100, unacknowledged_only: bool = False) -> List[Dict[str, Any]]:
        query = "SELECT * FROM security_alerts WHERE 1=1"
        params: List[Any] = []
        if unacknowledged_only:
            query += " AND acknowledged = 0"
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self.db.read_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        out = []
        for r in rows:
            item = dict(r)
            try:
                item["reasons"] = json.loads(item["reasons"])
            except Exception:
                pass
            item["acknowledged"] = bool(item["acknowledged"])
            out.append(item)
        return out

    def acknowledge_alert(self, alert_id: str) -> bool:
        with self.db.write_transaction() as conn:
            cur = conn.execute(
                "UPDATE security_alerts SET acknowledged = 1 WHERE alert_id = ?", (alert_id,)
            )
            return cur.rowcount > 0
