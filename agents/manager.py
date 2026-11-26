"""Agent Manager for AGENT SHIELD.

Handles creation, listing, activation/deactivation, credential issuance,
permission assignment, and trusted normal-behaviour baseline initialization.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.auth import AuthService
from backend.behaviour_monitor import BehaviourMonitoringEngine
from backend.config import DEFAULT_NORMAL_HOUR_END, DEFAULT_NORMAL_HOUR_START
from backend.database import DatabaseManager
from backend.policy_engine import PolicyEngine


class AgentManager:
    """Manages agent identities, credentials, tool configurations, and lifecycle status."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self.auth = AuthService(db)
        self.policy = PolicyEngine(db)
        self.behaviour = BehaviourMonitoringEngine(db)

    @staticmethod
    def _slugify(name: str) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        return slug[:24] or "agent"

    def create_agent(
        self,
        *,
        name: str,
        role: str,
        description: str,
        system_instructions: str,
        available_tools: List[str],
        initial_permissions: Optional[List[Dict[str, Any]]] = None,
        agent_id: Optional[str] = None,
        fixed_credential: Optional[str] = None,
        normal_hours_start: int = DEFAULT_NORMAL_HOUR_START,
        normal_hours_end: int = DEFAULT_NORMAL_HOUR_END,
    ) -> Dict[str, Any]:
        aid = agent_id or f"agent-{self._slugify(name)}-{uuid.uuid4().hex[:6]}"
        if fixed_credential:
            raw_token = fixed_credential
            cred_hash = AuthService.hash_credential(raw_token)
            cred_prefix = raw_token[:12] + "..."
        else:
            raw_token, cred_hash, cred_prefix = AuthService.generate_credential()

        now = datetime.now(timezone.utc).isoformat()
        with self.db.write_transaction() as conn:
            conn.execute(
                """
                INSERT INTO agents (
                    agent_id, name, role, description, system_instructions,
                    available_tools, credential_hash, credential_prefix,
                    status, agent_type, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 'deterministic_python_simulated', ?)
                """,
                (
                    aid,
                    name.strip(),
                    role.strip(),
                    description.strip(),
                    system_instructions.strip(),
                    json.dumps(available_tools),
                    cred_hash,
                    cred_prefix,
                    now,
                ),
            )

        created_perms = []
        normal_resources: List[str] = []
        for perm in initial_permissions or []:
            created_perms.append(
                self.policy.upsert_permission(
                    agent_id=aid,
                    resource=perm["resource"],
                    action=perm["action"],
                    effect=perm.get("effect", "ALLOW"),
                    max_amount=perm.get("max_amount"),
                    requires_approval_above=perm.get("requires_approval_above"),
                )
            )
            if perm.get("effect", "ALLOW").upper() == "ALLOW":
                normal_resources.append(perm["resource"])

        # Seed trusted per-agent normal-behaviour baseline (never learned from untrusted requests)
        baseline = self.behaviour.ensure_agent_baseline(
            agent_id=aid,
            normal_resources=sorted(set(normal_resources)) or ["customers"],
            normal_hours_start=normal_hours_start,
            normal_hours_end=normal_hours_end,
        )

        agent = self.get_agent(aid)
        assert agent is not None
        agent["api_key"] = raw_token
        agent["permissions"] = created_perms
        agent["baseline"] = baseline
        return agent

    def list_agents(self) -> List[Dict[str, Any]]:
        with self.db.read_connection() as conn:
            rows = conn.execute(
                """
                SELECT agent_id, name, role, description, system_instructions,
                       available_tools, credential_prefix, status, agent_type, created_at
                FROM agents
                ORDER BY created_at ASC
                """
            ).fetchall()
            perms_rows = conn.execute(
                "SELECT * FROM permissions ORDER BY agent_id, resource, action"
            ).fetchall()

        perms_by_agent: Dict[str, List[Dict[str, Any]]] = {}
        for p in perms_rows:
            d = dict(p)
            perms_by_agent.setdefault(d["agent_id"], []).append(d)

        result = []
        for r in rows:
            item = dict(r)
            item["available_tools"] = json.loads(item["available_tools"]) if item["available_tools"] else []
            item["permissions"] = perms_by_agent.get(item["agent_id"], [])
            result.append(item)
        return result

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        with self.db.read_connection() as conn:
            row = conn.execute(
                """
                SELECT agent_id, name, role, description, system_instructions,
                       available_tools, credential_prefix, status, agent_type, created_at
                FROM agents
                WHERE agent_id = ?
                """,
                (agent_id,),
            ).fetchone()
            if row is None:
                return None
            perms = [
                dict(p)
                for p in conn.execute(
                    "SELECT * FROM permissions WHERE agent_id = ? ORDER BY resource, action",
                    (agent_id,),
                ).fetchall()
            ]
        item = dict(row)
        item["available_tools"] = json.loads(item["available_tools"]) if item["available_tools"] else []
        item["permissions"] = perms
        return item

    def set_status(self, agent_id: str, status: str) -> Optional[Dict[str, Any]]:
        status_clean = status.lower().strip()
        if status_clean not in ("active", "inactive"):
            raise ValueError("Status must be 'active' or 'inactive'.")
        with self.db.write_transaction() as conn:
            cur = conn.execute(
                "UPDATE agents SET status = ? WHERE agent_id = ?",
                (status_clean, agent_id),
            )
            if cur.rowcount == 0:
                return None
        return self.get_agent(agent_id)

    def rotate_credential(self, agent_id: str) -> Optional[Dict[str, Any]]:
        raw_token, cred_hash, cred_prefix = AuthService.generate_credential()
        with self.db.write_transaction() as conn:
            cur = conn.execute(
                "UPDATE agents SET credential_hash = ?, credential_prefix = ? WHERE agent_id = ?",
                (cred_hash, cred_prefix, agent_id),
            )
            if cur.rowcount == 0:
                return None
        agent = self.get_agent(agent_id)
        if agent:
            agent["api_key"] = raw_token
        return agent
