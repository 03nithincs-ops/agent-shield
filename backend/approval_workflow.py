"""Approval Workflow Engine for AGENT SHIELD.

Holds sensitive requests (e.g., high-value simulated payments) in PENDING status without
early execution. Upon administrator approval, re-validates agent active status, live
permissions, behaviour, and risk BEFORE executing the protected tool.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.audit_engine import AuditEngine
from backend.auth import AuthService
from backend.behaviour_monitor import BehaviourMonitoringEngine
from backend.database import DatabaseManager
from backend.policy_engine import PolicyEngine
from backend.risk_engine import RiskAssessmentEngine
from backend.tool_registry import ProtectedToolRegistry


class ApprovalWorkflow:
    """Manages pending approval requests and post-approval revalidation + execution."""

    def __init__(
        self,
        db: DatabaseManager,
        auth: AuthService,
        policy: PolicyEngine,
        behaviour: BehaviourMonitoringEngine,
        risk: RiskAssessmentEngine,
        tools: ProtectedToolRegistry,
        audit: AuditEngine,
    ) -> None:
        self.db = db
        self.auth = auth
        self.policy = policy
        self.behaviour = behaviour
        self.risk = risk
        self.tools = tools
        self.audit = audit

    def create_request(
        self,
        *,
        event_id: str,
        agent_id: str,
        agent_name: str,
        tool_name: str,
        resource: str,
        action: str,
        arguments: Dict[str, Any],
        reason: str,
        risk_score: float,
    ) -> Dict[str, Any]:
        approval_id = f"apr-{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc).isoformat()
        with self.db.write_transaction() as conn:
            conn.execute(
                """
                INSERT INTO approval_requests (
                    approval_id, event_id, agent_id, agent_name,
                    tool_name, resource, action, arguments, reason,
                    risk_score, status, requested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)
                """,
                (
                    approval_id,
                    event_id,
                    agent_id,
                    agent_name,
                    tool_name,
                    resource,
                    action,
                    json.dumps(arguments, default=str),
                    reason,
                    round(float(risk_score), 2),
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        item = dict(row)
        item["arguments"] = json.loads(item["arguments"])
        return item

    def list_requests(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM approval_requests WHERE 1=1"
        params: List[Any] = []
        if status:
            query += " AND status = ?"
            params.append(status.upper())
        query += " ORDER BY requested_at DESC"
        with self.db.read_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        results = []
        for r in rows:
            item = dict(r)
            try:
                item["arguments"] = json.loads(item["arguments"])
            except Exception:
                pass
            if item.get("execution_result"):
                try:
                    item["execution_result"] = json.loads(item["execution_result"])
                except Exception:
                    pass
            results.append(item)
        return results

    def approve_request(
        self, approval_id: str, reviewer: str = "admin", notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """Revalidate agent status, live permissions, behaviour & risk before executing."""
        with self.db.read_connection() as conn:
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE approval_id = ?", (approval_id,)
            ).fetchone()

        if row is None:
            raise ValueError(f"Approval request '{approval_id}' not found.")
        req = dict(row)
        if req["status"] != "PENDING":
            raise ValueError(f"Approval request '{approval_id}' is already {req['status']}.")

        arguments = json.loads(req["arguments"])
        now = datetime.now(timezone.utc).isoformat()

        # Revalidation Step 1: Agent still exists and is active
        agent_row = self.auth.get_agent_by_id(req["agent_id"])
        if not agent_row or agent_row["status"] != "active":
            reason = "Revalidation failed: agent is inactive or no longer exists."
            return self._finalize_blocked_revalidation(req, reviewer, notes, now, reason)

        avail_tools = json.loads(agent_row["available_tools"]) if agent_row["available_tools"] else []

        # Revalidation Step 2: Tool & arguments still valid
        val_ok, val_reason, tool_def = self.tools.validate_request(req["tool_name"], arguments)
        if not val_ok or tool_def is None:
            return self._finalize_blocked_revalidation(req, reviewer, notes, now, f"Revalidation failed: {val_reason}")

        # Revalidation Step 3: Live policy check (ensures permission wasn't revoked while pending)
        pol = self.policy.evaluate(
            agent_id=req["agent_id"],
            agent_available_tools=avail_tools,
            tool_name=req["tool_name"],
            resource=tool_def.resource,
            action=tool_def.action,
            arguments=arguments,
        )
        if not pol.allowed or pol.error or pol.injection_detected:
            return self._finalize_blocked_revalidation(
                req, reviewer, notes, now, f"Revalidation blocked by Policy Engine: {pol.reason}"
            )

        # Revalidation Step 4: Behaviour & Risk check
        beh = self.behaviour.evaluate(
            agent_id=req["agent_id"],
            tool_name=req["tool_name"],
            resource=tool_def.resource,
            action=tool_def.action,
            arguments=arguments,
            is_sensitive_tool=tool_def.sensitive,
            policy_allowed=True,
        )
        risk = self.risk.assess(
            authenticated=True,
            resource=tool_def.resource,
            action=tool_def.action,
            arguments=arguments,
            policy=pol,
            behaviour=beh,
        )
        if beh.status == "ANOMALOUS_BLOCK":
            return self._finalize_blocked_revalidation(
                req, reviewer, notes, now, f"Revalidation blocked by Behaviour Monitor: {'; '.join(beh.reasons)}"
            )

        # Revalidation passed -> Execute protected tool
        exec_output = self.tools.execute_tool(req["tool_name"], arguments, req["agent_id"])

        audit_meta = self.audit.record_event(
            authenticated_agent=req["agent_id"],
            agent_name=req["agent_name"],
            requested_resource=req["resource"],
            requested_action=req["action"],
            tool_name=req["tool_name"],
            auth_result="REVALIDATED_ACTIVE",
            policy_result=f"REVALIDATED_ALLOW: {pol.reason}",
            behaviour_result=f"{beh.status}",
            risk_score=risk.score,
            final_decision="ALLOW",
            execution_result="EXECUTED_AFTER_ADMIN_APPROVAL",
            details={
                "approval_id": approval_id,
                "reviewer": reviewer,
                "notes": notes,
                "record_ids": exec_output.get("record_ids", []),
            },
        )

        self.behaviour.record_activity(
            agent_id=req["agent_id"],
            tool_name=req["tool_name"],
            resource=req["resource"],
            action=req["action"],
            record_ids=exec_output.get("record_ids", []),
            decision="ALLOW",
            authorized=True,
            sensitive_op=True,
            risk_score=risk.score,
            details={"approval_id": approval_id, "approved_by": reviewer},
        )

        with self.db.write_transaction() as conn:
            conn.execute(
                """
                UPDATE approval_requests
                SET status = 'EXECUTED', reviewed_by = ?, reviewed_at = ?,
                    review_notes = ?, execution_result = ?
                WHERE approval_id = ?
                """,
                (reviewer, now, notes or "Approved after revalidation.", json.dumps(exec_output, default=str), approval_id),
            )

        return {
            "approval_id": approval_id,
            "status": "EXECUTED",
            "reviewed_by": reviewer,
            "reviewed_at": now,
            "revalidated": True,
            "execution_result": exec_output,
            "audit_event": audit_meta,
        }

    def _finalize_blocked_revalidation(
        self,
        req: Dict[str, Any],
        reviewer: str,
        notes: Optional[str],
        now: str,
        reason: str,
    ) -> Dict[str, Any]:
        audit_meta = self.audit.record_event(
            authenticated_agent=req["agent_id"],
            agent_name=req["agent_name"],
            requested_resource=req["resource"],
            requested_action=req["action"],
            tool_name=req["tool_name"],
            auth_result="REVALIDATION_CHECKED",
            policy_result=reason,
            behaviour_result="BLOCKED_ON_REVALIDATION",
            risk_score=85.0,
            final_decision="BLOCK",
            execution_result="NOT_EXECUTED",
            details={"approval_id": req["approval_id"], "reviewer": reviewer, "reason": reason},
        )
        with self.db.write_transaction() as conn:
            conn.execute(
                """
                UPDATE approval_requests
                SET status = 'BLOCKED_ON_REVALIDATION', reviewed_by = ?, reviewed_at = ?,
                    review_notes = ?, execution_result = ?
                WHERE approval_id = ?
                """,
                (reviewer, now, f"{notes or ''} | {reason}".strip(" |"), json.dumps({"executed": False, "reason": reason}), req["approval_id"]),
            )
        return {
            "approval_id": req["approval_id"],
            "status": "BLOCKED_ON_REVALIDATION",
            "reviewed_by": reviewer,
            "reviewed_at": now,
            "revalidated": False,
            "reason": reason,
            "execution_result": {"executed": False, "reason": reason},
            "audit_event": audit_meta,
        }

    def reject_request(
        self, approval_id: str, reviewer: str = "admin", notes: Optional[str] = None
    ) -> Dict[str, Any]:
        with self.db.read_connection() as conn:
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        if row is None:
            raise ValueError(f"Approval request '{approval_id}' not found.")
        req = dict(row)
        if req["status"] != "PENDING":
            raise ValueError(f"Approval request '{approval_id}' is already {req['status']}.")

        now = datetime.now(timezone.utc).isoformat()
        audit_meta = self.audit.record_event(
            authenticated_agent=req["agent_id"],
            agent_name=req["agent_name"],
            requested_resource=req["resource"],
            requested_action=req["action"],
            tool_name=req["tool_name"],
            auth_result="ADMIN_REVIEW",
            policy_result="REJECTED_BY_ADMINISTRATOR",
            behaviour_result="N/A",
            risk_score=req["risk_score"],
            final_decision="BLOCK",
            execution_result="NOT_EXECUTED_REJECTED",
            details={"approval_id": approval_id, "reviewer": reviewer, "notes": notes},
        )
        with self.db.write_transaction() as conn:
            conn.execute(
                """
                UPDATE approval_requests
                SET status = 'REJECTED', reviewed_by = ?, reviewed_at = ?,
                    review_notes = ?, execution_result = ?
                WHERE approval_id = ?
                """,
                (reviewer, now, notes or "Rejected by administrator.", json.dumps({"executed": False}), approval_id),
            )
        return {
            "approval_id": approval_id,
            "status": "REJECTED",
            "reviewed_by": reviewer,
            "reviewed_at": now,
            "audit_event": audit_meta,
        }
