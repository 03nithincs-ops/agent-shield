"""Tamper-evident Audit Engine with SHA-256 hash chaining and concurrency protection."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.database import DatabaseManager

GENESIS_HASH = "0" * 64


class AuditEngine:
    """Appends tamper-evident SHA-256 hash-chained audit records and verifies chain integrity."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    @staticmethod
    def _compute_hash(prev_hash: str, payload: Dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        raw = f"{prev_hash}|{canonical}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def record_event(
        self,
        *,
        authenticated_agent: str,
        agent_name: str,
        requested_resource: str,
        requested_action: str,
        tool_name: str,
        auth_result: str,
        policy_result: str,
        behaviour_result: str,
        risk_score: float,
        final_decision: str,
        execution_result: str,
        details: Optional[Dict[str, Any]] = None,
        event_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Atomically append an audit record protected by write_transaction lock."""
        eid = event_id or f"evt-{uuid.uuid4().hex[:12]}"
        ts = datetime.now(timezone.utc).isoformat()
        details_json = json.dumps(details or {}, sort_keys=True, default=str)

        payload_for_hash = {
            "event_id": eid,
            "timestamp": ts,
            "authenticated_agent": authenticated_agent,
            "agent_name": agent_name,
            "requested_resource": requested_resource,
            "requested_action": requested_action,
            "tool_name": tool_name,
            "auth_result": auth_result,
            "policy_result": policy_result,
            "behaviour_result": behaviour_result,
            "risk_score": round(float(risk_score), 2),
            "final_decision": final_decision,
            "execution_result": execution_result,
            "details": details_json,
        }

        with self.db.write_transaction() as conn:
            last = conn.execute(
                "SELECT current_hash FROM audit_logs ORDER BY seq_id DESC LIMIT 1"
            ).fetchone()
            prev_hash = last["current_hash"] if last else GENESIS_HASH
            current_hash = self._compute_hash(prev_hash, payload_for_hash)

            conn.execute(
                """
                INSERT INTO audit_logs (
                    event_id, timestamp, authenticated_agent, agent_name,
                    requested_resource, requested_action, tool_name,
                    auth_result, policy_result, behaviour_result,
                    risk_score, final_decision, execution_result,
                    details, prev_hash, current_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    eid,
                    ts,
                    authenticated_agent,
                    agent_name,
                    requested_resource,
                    requested_action,
                    tool_name,
                    auth_result,
                    policy_result,
                    behaviour_result,
                    round(float(risk_score), 2),
                    final_decision,
                    execution_result,
                    details_json,
                    prev_hash,
                    current_hash,
                ),
            )

        return {
            "event_id": eid,
            "timestamp": ts,
            "prev_hash": prev_hash,
            "current_hash": current_hash,
            "final_decision": final_decision,
        }

    def verify_chain(self) -> Dict[str, Any]:
        """Recompute SHA-256 hash chain across all audit records and detect any tampering."""
        with self.db.read_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY seq_id ASC"
            ).fetchall()

        expected_prev = GENESIS_HASH
        broken_events: List[Dict[str, Any]] = []

        for row in rows:
            payload = {
                "event_id": row["event_id"],
                "timestamp": row["timestamp"],
                "authenticated_agent": row["authenticated_agent"],
                "agent_name": row["agent_name"],
                "requested_resource": row["requested_resource"],
                "requested_action": row["requested_action"],
                "tool_name": row["tool_name"],
                "auth_result": row["auth_result"],
                "policy_result": row["policy_result"],
                "behaviour_result": row["behaviour_result"],
                "risk_score": round(float(row["risk_score"]), 2),
                "final_decision": row["final_decision"],
                "execution_result": row["execution_result"],
                "details": row["details"],
            }
            recomputed = self._compute_hash(row["prev_hash"], payload)
            prev_mismatch = row["prev_hash"] != expected_prev
            hash_mismatch = row["current_hash"] != recomputed

            if prev_mismatch or hash_mismatch:
                broken_events.append(
                    {
                        "seq_id": row["seq_id"],
                        "event_id": row["event_id"],
                        "prev_hash_mismatch": prev_mismatch,
                        "current_hash_mismatch": hash_mismatch,
                        "stored_hash": row["current_hash"],
                        "expected_hash": recomputed,
                    }
                )
            expected_prev = row["current_hash"]

        return {
            "valid": len(broken_events) == 0,
            "total_records": len(rows),
            "broken_count": len(broken_events),
            "broken_events": broken_events,
            "latest_hash": expected_prev if rows else GENESIS_HASH,
        }

    def list_logs(
        self,
        *,
        limit: int = 100,
        agent_id: Optional[str] = None,
        decision: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM audit_logs WHERE 1=1"
        params: List[Any] = []
        if agent_id:
            query += " AND authenticated_agent = ?"
            params.append(agent_id)
        if decision:
            query += " AND final_decision = ?"
            params.append(decision)
        query += " ORDER BY seq_id DESC LIMIT ?"
        params.append(limit)

        with self.db.read_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()

        result = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item["details"])
            except Exception:
                pass
            result.append(item)
        return result
