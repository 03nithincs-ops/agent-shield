"""FastAPI Security Gateway & Management API for AGENT SHIELD."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from agents.manager import AgentManager
from agents.runtime import DEMO_AGENT_CREDENTIALS, SimulatedAgentRuntime
from backend.config import (
    BEHAVIOUR_WINDOW_SECONDS,
    BLOCK_REQUEST_THRESHOLD,
    BLOCK_UNIQUE_RECORDS_THRESHOLD,
    DEFAULT_NORMAL_HOUR_END,
    DEFAULT_NORMAL_HOUR_START,
    DEFAULT_TIMEZONE,
    DOMAIN,
    EVENT_NAME,
    INSTITUTION,
    MONITOR_REQUEST_THRESHOLD,
    MONITOR_UNIQUE_RECORDS_THRESHOLD,
    PAYMENT_APPROVAL_THRESHOLD,
    PROBLEM_STATEMENT,
    PROBLEM_STATEMENT_ID,
    PROJECT_NAME,
    TAGLINE,
    TEAM_ID,
    TEAM_NAME,
    TEAM_SIZE,
)
from backend.database import DatabaseManager
from backend.gateway import SecurityGateway
from backend.schemas import (
    AgentCreateRequest,
    AgentStatusUpdateRequest,
    ApprovalDecisionRequest,
    GatewayToolRequest,
    PermissionUpsertRequest,
    ScenarioRunRequest,
)
from data.seed_data import seed_database

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

SCENARIO_CATALOG = [
    {
        "scenario_id": 1,
        "title": "Authorized Customer Access",
        "expected": "ALLOW",
        "agent": "Support Agent",
        "description": "Support Agent reads a synthetic customer profile during normal hours using its verified SHA-256 API key.",
    },
    {
        "scenario_id": 2,
        "title": "Support Agent Attempts Payroll Access",
        "expected": "BLOCK",
        "agent": "Support Agent",
        "description": "Support Agent attempts to call read_payroll_records (unseen resource category + denied by Permission Registry).",
    },
    {
        "scenario_id": 3,
        "title": "Prompt Injection Requesting Restricted Data",
        "expected": "BLOCK",
        "agent": "Support Agent",
        "description": "Payload includes prompt injection attempting to override instructions and dump payroll salaries.",
    },
    {
        "scenario_id": 4,
        "title": "Abnormal High-Volume Record Access",
        "expected": "MONITOR / BLOCK",
        "agent": "Support Agent",
        "description": "Agent escalates bulk customer reads (5 -> 15 -> 30 records) crossing both rule thresholds and Isolation Forest baseline.",
    },
    {
        "scenario_id": 5,
        "title": "Sensitive Simulated Payment",
        "expected": "REQUIRE_APPROVAL",
        "agent": "Payment Agent",
        "description": "Payment Agent requests a $12,500 simulated transfer; held pending admin approval with zero early execution.",
    },
    {
        "scenario_id": 6,
        "title": "Permission Revoked During Active Session",
        "expected": "ALLOW -> BLOCK",
        "agent": "Loan Agent",
        "description": "Loan Agent reads loans, permission is revoked live in Permission Registry, and the next request is BLOCKED.",
    },
    {
        "scenario_id": 7,
        "title": "Invalid Auth / Identity Spoofing (Fail-Closed)",
        "expected": "BLOCK",
        "agent": "Unauthenticated",
        "description": "Caller sends forged API key with spoofed untrusted_agent_id; gateway fails closed and logs audit event.",
    },
    {
        "scenario_id": 8,
        "title": "Audit Record Tampering Detection",
        "expected": "HASH VERIFICATION FAILS",
        "agent": "Audit Engine",
        "description": "Modifies a historical audit log row and runs SHA-256 chain verification to prove tamper detection.",
    },
    {
        "scenario_id": 9,
        "title": "Off-Hours Activity & Isolation Forest Anomaly",
        "expected": "MONITOR (ML + Rule)",
        "agent": "Support Agent",
        "description": "Authorized customer read at 03:00 UTC outside trusted operating hours (08:00-20:00), flagged by rules + Isolation Forest with explainable risk breakdown.",
    },
]


def create_app(db_path: Optional[str | Path] = None) -> FastAPI:
    """Application factory enabling isolated test databases and clean production startup."""
    app = FastAPI(
        title="AGENT SHIELD — Runtime Security Gateway",
        description="Intelligent Runtime Authorization and Behaviour Monitoring for AI Agents (AVISHKAR'26 PS9)",
        version="1.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    db = DatabaseManager(db_path=db_path)
    seed_database(db, force_reseed=False)

    gateway = SecurityGateway(db)
    agent_manager = AgentManager(db)
    runtime = SimulatedAgentRuntime(gateway)

    app.state.db = db
    app.state.gateway = gateway
    app.state.agent_manager = agent_manager
    app.state.runtime = runtime

    # ---- Health & Overview Dashboard ----
    @app.get("/api/health")
    def health() -> Dict[str, Any]:
        return {
            "status": "ok",
            "service": "agent-shield-gateway",
            "project": PROJECT_NAME,
            "tagline": TAGLINE,
            "event": EVENT_NAME,
            "institution": INSTITUTION,
            "problem_statement": PROBLEM_STATEMENT,
            "problem_statement_id": PROBLEM_STATEMENT_ID,
            "team_id": TEAM_ID,
            "team_name": TEAM_NAME,
            "team_size": TEAM_SIZE,
            "agent_mode": "deterministic_python_simulated",
            "timezone": DEFAULT_TIMEZONE,
            "operating_window": f"{DEFAULT_NORMAL_HOUR_START:02d}:00–{DEFAULT_NORMAL_HOUR_END:02d}:00 ({DEFAULT_TIMEZONE})",
        }

    @app.get("/api/dashboard")
    @app.get("/api/dashboard/overview")
    def dashboard_overview() -> Dict[str, Any]:
        with db.read_connection() as conn:
            agents = [dict(r) for r in conn.execute("SELECT agent_id, name, role, status FROM agents").fetchall()]
            audits = [
                dict(r)
                for r in conn.execute(
                    "SELECT event_id, timestamp, authenticated_agent, agent_name, requested_resource, "
                    "requested_action, final_decision, risk_score FROM audit_logs ORDER BY seq_id DESC LIMIT 500"
                ).fetchall()
            ]
            pending_approvals = conn.execute(
                "SELECT COUNT(*) FROM approval_requests WHERE status = 'PENDING'"
            ).fetchone()[0]
            open_alerts = conn.execute(
                "SELECT COUNT(*) FROM security_alerts WHERE acknowledged = 0"
            ).fetchone()[0]
            db_counts = {
                "customers": conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0],
                "loans": conn.execute("SELECT COUNT(*) FROM loans").fetchone()[0],
                "payments": conn.execute("SELECT COUNT(*) FROM payments").fetchone()[0],
                "employees": conn.execute("SELECT COUNT(*) FROM employees").fetchone()[0],
                "payroll": conn.execute("SELECT COUNT(*) FROM payroll").fetchone()[0],
            }

        decision_counts = {"ALLOW": 0, "BLOCK": 0, "MONITOR": 0, "REQUIRE_APPROVAL": 0}
        avg_risk = 0.0
        resource_counts: Dict[str, int] = {}
        recent_risk_series: List[Dict[str, Any]] = []

        if audits:
            df = pd.DataFrame(audits)
            vc = df["final_decision"].value_counts().to_dict()
            for k in decision_counts:
                decision_counts[k] = int(vc.get(k, 0))
            avg_risk = round(float(df["risk_score"].mean()), 1)
            resource_counts = {str(k): int(v) for k, v in df["requested_resource"].value_counts().to_dict().items()}
            tail = audits[:15][::-1]
            recent_risk_series = [
                {
                    "event_id": r["event_id"],
                    "label": f"{r['agent_name'][:10]} ({r['requested_resource']})",
                    "risk_score": r["risk_score"],
                    "decision": r["final_decision"],
                }
                for r in tail
            ]

        chain_status = gateway.audit.verify_chain()

        return {
            "total_agents": len(agents),
            "active_agents": sum(1 for a in agents if a["status"] == "active"),
            "total_requests": len(audits),
            "decision_counts": decision_counts,
            "avg_risk_score": avg_risk,
            "pending_approvals": pending_approvals,
            "open_alerts": open_alerts,
            "audit_chain_valid": chain_status["valid"],
            "audit_total_records": chain_status["total_records"],
            "resource_counts": resource_counts,
            "recent_risk_series": recent_risk_series,
            "synthetic_db_counts": db_counts,
            "thresholds": {
                "window_seconds": BEHAVIOUR_WINDOW_SECONDS,
                "monitor_requests": MONITOR_REQUEST_THRESHOLD,
                "block_requests": BLOCK_REQUEST_THRESHOLD,
                "monitor_unique_records": MONITOR_UNIQUE_RECORDS_THRESHOLD,
                "block_unique_records": BLOCK_UNIQUE_RECORDS_THRESHOLD,
                "payment_approval_threshold": PAYMENT_APPROVAL_THRESHOLD,
                "timezone": DEFAULT_TIMEZONE,
                "normal_hours_start": DEFAULT_NORMAL_HOUR_START,
                "normal_hours_end": DEFAULT_NORMAL_HOUR_END,
                "operating_window": f"{DEFAULT_NORMAL_HOUR_START:02d}:00–{DEFAULT_NORMAL_HOUR_END:02d}:00 ({DEFAULT_TIMEZONE})",
            },
            "hackathon_identity": {
                "project": PROJECT_NAME,
                "tagline": TAGLINE,
                "event": EVENT_NAME,
                "institution": INSTITUTION,
                "problem_statement_id": PROBLEM_STATEMENT_ID,
                "problem_statement": PROBLEM_STATEMENT,
                "domain": DOMAIN,
                "team_id": TEAM_ID,
                "team_name": TEAM_NAME,
                "team_size": TEAM_SIZE,
                "timezone": DEFAULT_TIMEZONE,
                "operating_window": f"{DEFAULT_NORMAL_HOUR_START:02d}:00–{DEFAULT_NORMAL_HOUR_END:02d}:00 ({DEFAULT_TIMEZONE})",
            },
        }

    # ---- Protected Tools Catalog ----
    @app.get("/api/tools")
    def list_tools() -> Dict[str, Any]:
        return {"tools": gateway.tools.list_tools()}

    # ---- Agent Manager Endpoints ----
    @app.get("/api/agents")
    def list_agents() -> Dict[str, Any]:
        return {"agents": agent_manager.list_agents()}

    @app.post("/api/agents", status_code=201)
    def create_agent(req: AgentCreateRequest) -> Dict[str, Any]:
        valid_tool_names = set(gateway.tools.TOOLS.keys())
        invalid = [t for t in req.available_tools if t not in valid_tool_names]
        if invalid:
            raise HTTPException(status_code=400, detail=f"Invalid tool(s): {invalid}")
        agent = agent_manager.create_agent(
            name=req.name,
            role=req.role,
            description=req.description,
            system_instructions=req.system_instructions,
            available_tools=req.available_tools,
            initial_permissions=req.initial_permissions,
        )
        return {"agent": agent, "note": "Save the returned api_key now; only its SHA-256 hash is stored."}

    @app.get("/api/agents/{agent_id}")
    def get_agent(agent_id: str) -> Dict[str, Any]:
        agent = agent_manager.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
        return {"agent": agent}

    @app.patch("/api/agents/{agent_id}")
    @app.patch("/api/agents/{agent_id}/status")
    def update_agent_status(agent_id: str, req: AgentStatusUpdateRequest) -> Dict[str, Any]:
        try:
            agent = agent_manager.set_status(agent_id, req.status)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if not agent:
            raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
        return {"agent": agent}

    @app.post("/api/agents/{agent_id}/rotate-key")
    def rotate_agent_key(agent_id: str) -> Dict[str, Any]:
        agent = agent_manager.rotate_credential(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
        return {"agent": agent}

    # ---- Persistent Permission Registry Endpoints ----
    @app.get("/api/permissions")
    def list_permissions(agent_id: Optional[str] = Query(default=None)) -> Dict[str, Any]:
        return {"permissions": gateway.policy.list_permissions(agent_id=agent_id)}

    @app.post("/api/permissions")
    def upsert_permission(req: PermissionUpsertRequest) -> Dict[str, Any]:
        if not agent_manager.get_agent(req.agent_id):
            raise HTTPException(status_code=404, detail=f"Agent '{req.agent_id}' not found.")
        try:
            perm = gateway.policy.upsert_permission(
                agent_id=req.agent_id,
                resource=req.resource,
                action=req.action,
                effect=req.effect,
                max_amount=req.max_amount,
                requires_approval_above=req.requires_approval_above,
            )
            return {"permission": perm}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.delete("/api/permissions/{permission_id}")
    def revoke_permission(permission_id: str) -> Dict[str, Any]:
        deleted = gateway.policy.revoke_permission(permission_id)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"Permission '{permission_id}' not found.")
        return {"revoked": True, "permission_id": permission_id}

    # ---- Central Security Gateway Endpoint ----
    @app.post("/api/gateway/execute")
    def execute_gateway_tool(
        req: GatewayToolRequest,
        x_agent_key: Optional[str] = Header(default=None, alias="X-Agent-Key"),
    ) -> Dict[str, Any]:
        """Central Security Gateway endpoint.

        Agent identity is ALWAYS derived from the `X-Agent-Key` header credential,
        never from `untrusted_agent_id` in the request body.
        """
        return gateway.handle_tool_request(
            credential=x_agent_key,
            tool_name=req.tool_name,
            arguments=req.arguments,
            prompt_context=req.prompt_context,
            simulated_hour=req.simulated_hour,
            untrusted_agent_id=req.untrusted_agent_id,
        )

    # ---- Behaviour Monitoring & Trusted Baseline Endpoints ----
    @app.get("/api/behaviour/summary")
    def behaviour_summary() -> Dict[str, Any]:
        return {"agents": gateway.behaviour.get_agent_behaviour_summary()}

    @app.get("/api/behaviour/models/{agent_id}")
    def get_agent_model_telemetry(agent_id: str) -> Dict[str, Any]:
        """Expose per-agent Isolation Forest metadata, sample count, parameters, and status."""
        try:
            return gateway.behaviour.get_model_info(agent_id)
        except Exception as exc:
            raise HTTPException(status_code=404, detail=f"Model telemetry for '{agent_id}' unavailable: {exc}")

    @app.get("/api/behaviour/baselines")
    def behaviour_baselines() -> Dict[str, Any]:
        with db.read_connection() as conn:
            rows = conn.execute(
                """
                SELECT b.*, a.name AS agent_name, a.role AS agent_role
                FROM behaviour_baselines b
                JOIN agents a ON b.agent_id = a.agent_id
                ORDER BY b.agent_id
                """
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["normal_resources"] = json.loads(d["normal_resources"])
            out.append(d)
        return {"baselines": out}

    @app.get("/api/behaviour/events")
    @app.get("/api/behaviour/activity")
    def behaviour_activity(limit: int = Query(default=50, ge=1, le=200)) -> Dict[str, Any]:
        with db.read_connection() as conn:
            rows = conn.execute(
                """
                SELECT a.*, ag.name AS agent_name
                FROM activity_logs a
                LEFT JOIN agents ag ON a.agent_id = ag.agent_id
                ORDER BY a.timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        items = []
        for r in rows:
            d = dict(r)
            try:
                d["record_ids"] = json.loads(d["record_ids"])
                d["details"] = json.loads(d["details"])
            except Exception:
                pass
            items.append(d)
        return {"activity": items}

    # ---- Security Alerts Endpoints ----
    @app.get("/api/alerts")
    def list_alerts(
        limit: int = Query(default=100, ge=1, le=300),
        unacknowledged_only: bool = Query(default=False),
    ) -> Dict[str, Any]:
        return {"alerts": gateway.list_alerts(limit=limit, unacknowledged_only=unacknowledged_only)}

    @app.post("/api/alerts/{alert_id}/acknowledge")
    def acknowledge_alert(alert_id: str) -> Dict[str, Any]:
        ok = gateway.acknowledge_alert(alert_id)
        if not ok:
            raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
        return {"acknowledged": True, "alert_id": alert_id}

    # ---- Approval Workflow Endpoints ----
    @app.get("/api/approvals")
    def list_approvals(status: Optional[str] = Query(default=None)) -> Dict[str, Any]:
        return {"approvals": gateway.approvals.list_requests(status=status)}

    @app.post("/api/approvals/{approval_id}/approve")
    def approve_request(approval_id: str, req: ApprovalDecisionRequest) -> Dict[str, Any]:
        try:
            return gateway.approvals.approve_request(
                approval_id=approval_id, reviewer=req.reviewer, notes=req.notes
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/api/approvals/{approval_id}/reject")
    def reject_request(approval_id: str, req: ApprovalDecisionRequest) -> Dict[str, Any]:
        try:
            return gateway.approvals.reject_request(
                approval_id=approval_id, reviewer=req.reviewer, notes=req.notes
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    # ---- Audit Engine Endpoints ----
    @app.get("/api/audit")
    @app.get("/api/audit/logs")
    def list_audit_logs(
        limit: int = Query(default=100, ge=1, le=500),
        agent_id: Optional[str] = Query(default=None),
        decision: Optional[str] = Query(default=None),
    ) -> Dict[str, Any]:
        return {
            "logs": gateway.audit.list_logs(limit=limit, agent_id=agent_id, decision=decision),
            "chain": gateway.audit.verify_chain(),
        }

    @app.post("/api/audit/verify")
    @app.get("/api/audit/verify")
    def verify_audit_chain() -> Dict[str, Any]:
        return gateway.audit.verify_chain()

    # ---- Security Playground Endpoints ----
    @app.get("/api/playground/scenarios")
    def get_scenarios() -> Dict[str, Any]:
        return {"scenarios": SCENARIO_CATALOG, "demo_agents": list(DEMO_AGENT_CREDENTIALS.keys())}

    @app.get("/api/playground/demo-keys")
    def get_demo_keys() -> Dict[str, Any]:
        return {"demo_keys": DEMO_AGENT_CREDENTIALS}

    @app.post("/api/playground/run")
    def run_scenario(req: ScenarioRunRequest) -> Dict[str, Any]:
        try:
            return runtime.run_security_scenario(req.scenario_id, req.params)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/api/scenarios/{scenario_id}/execute")
    def execute_scenario_by_id(scenario_id: int) -> Dict[str, Any]:
        try:
            return runtime.run_security_scenario(scenario_id, {})
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/api/admin/reset-demo")
    def reset_demo() -> Dict[str, Any]:
        counts = seed_database(db, force_reseed=True)
        return {"reset": True, "counts": counts}

    # ---- Serve Frontend Static Assets ----
    if FRONTEND_DIR.exists():
        app.mount("/css", StaticFiles(directory=str(FRONTEND_DIR / "css")), name="css")
        app.mount("/js", StaticFiles(directory=str(FRONTEND_DIR / "js")), name="js")

        @app.get("/")
        def serve_index() -> FileResponse:
            return FileResponse(str(FRONTEND_DIR / "index.html"))

    return app


app = create_app()
