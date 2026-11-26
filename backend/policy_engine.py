"""Policy Engine for AGENT SHIELD.

Re-evaluates current database permissions on EVERY protected request so permission
revocation takes effect immediately. Also performs deterministic prompt-injection
and restricted-data exfiltration inspection at the gateway boundary.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.config import PAYMENT_APPROVAL_THRESHOLD, PAYMENT_MAX_AMOUNT
from backend.database import DatabaseManager


PROMPT_INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "Instruction override attempt"),
    (r"(bypass|override|disable)\s+(security|policy|gateway|permissions|auth)", "Security bypass attempt"),
    (r"(dump|export|exfiltrate|leak|reveal)\s+(all\s+)?(payroll|salaries|employees|database|credentials)", "Restricted data exfiltration pattern"),
    (r"act\s+as\s+(admin|root|superuser|system)", "Privilege escalation persona injection"),
    (r";\s*(drop|delete|union\s+select|alter)\s+", "SQL injection pattern"),
    (r"system\s*:\s*grant\s+", "Fake system directive injection"),
    (r"pretend\s+you\s+have\s+payroll\s+access", "Unauthorized scope escalation attempt"),
]


@dataclass
class PolicyEvaluation:
    allowed: bool
    requires_approval: bool
    reason: str
    injection_detected: bool = False
    matched_rule: Optional[Dict[str, Any]] = None
    flags: List[str] = field(default_factory=list)
    error: bool = False


class PolicyEngine:
    """Evaluates live RBAC/ABAC permissions and gateway-level prompt injection checks."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def inspect_for_prompt_injection(
        self, arguments: Dict[str, Any], prompt_context: Optional[str] = None
    ) -> List[str]:
        """Inspect prompt context and string arguments for injection/escalation patterns."""
        findings: List[str] = []
        texts_to_scan: List[str] = []
        if prompt_context:
            texts_to_scan.append(str(prompt_context))
        if arguments:
            texts_to_scan.append(json.dumps(arguments, default=str))

        combined = "\n".join(texts_to_scan)
        for pattern, label in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, combined, flags=re.IGNORECASE):
                findings.append(label)
        return findings

    def evaluate(
        self,
        *,
        agent_id: str,
        agent_available_tools: List[str],
        tool_name: str,
        resource: str,
        action: str,
        arguments: Dict[str, Any],
        prompt_context: Optional[str] = None,
    ) -> PolicyEvaluation:
        """Re-check live permissions in SQLite on every call. Fails closed on errors."""
        try:
            # 1. Gateway-level prompt injection inspection
            injection_findings = self.inspect_for_prompt_injection(arguments, prompt_context)
            if injection_findings:
                return PolicyEvaluation(
                    allowed=False,
                    requires_approval=False,
                    reason=f"Blocked by gateway prompt-injection filter: {', '.join(injection_findings)}.",
                    injection_detected=True,
                    flags=injection_findings,
                )

            # 2. Check live permissions table (never cached — immediate revocation)
            with self.db.read_connection() as conn:
                row = conn.execute(
                    """
                    SELECT * FROM permissions
                    WHERE agent_id = ? AND resource = ? AND action = ?
                    """,
                    (agent_id, resource, action),
                ).fetchone()

            if row is None:
                return PolicyEvaluation(
                    allowed=False,
                    requires_approval=False,
                    reason=f"No active permission grants '{agent_id}' to perform '{action}' on '{resource}'.",
                    flags=["missing_permission"],
                )

            rule = dict(row)
            if rule["effect"].upper() != "ALLOW":
                return PolicyEvaluation(
                    allowed=False,
                    requires_approval=False,
                    reason=f"Explicit DENY policy blocks '{agent_id}' from '{action}' on '{resource}'.",
                    matched_rule=rule,
                    flags=["explicit_deny"],
                )

            # 3. Check tool allowlist configured on agent (if configured)
            if agent_available_tools and tool_name not in agent_available_tools:
                return PolicyEvaluation(
                    allowed=False,
                    requires_approval=False,
                    reason=f"Tool '{tool_name}' is not enabled in agent '{agent_id}' tool configuration.",
                    matched_rule=rule,
                    flags=["tool_not_configured"],
                )

            # 4. Amount & approval thresholds for sensitive financial operations
            if resource == "payments" and action == "execute":
                amount = float(arguments.get("amount", 0.0))
                max_amt = rule["max_amount"] if rule["max_amount"] is not None else PAYMENT_MAX_AMOUNT
                approval_thresh = (
                    rule["requires_approval_above"]
                    if rule["requires_approval_above"] is not None
                    else PAYMENT_APPROVAL_THRESHOLD
                )
                if amount > max_amt:
                    return PolicyEvaluation(
                        allowed=False,
                        requires_approval=False,
                        reason=f"Simulated payment amount ${amount:,.2f} exceeds maximum policy limit (${max_amt:,.2f}).",
                        matched_rule=rule,
                        flags=["exceeds_max_amount"],
                    )
                if amount >= approval_thresh:
                    return PolicyEvaluation(
                        allowed=True,
                        requires_approval=True,
                        reason=(
                            f"Sensitive simulated payment (${amount:,.2f}) meets or exceeds "
                            f"approval threshold (${approval_thresh:,.2f})."
                        ),
                        matched_rule=rule,
                        flags=["requires_approval_payment_threshold"],
                    )

            return PolicyEvaluation(
                allowed=True,
                requires_approval=False,
                reason=f"Permitted by live policy rule ({rule['permission_id']}) for {resource}:{action}.",
                matched_rule=rule,
            )
        except Exception as exc:
            return PolicyEvaluation(
                allowed=False,
                requires_approval=False,
                reason=f"Policy engine failure (fail-closed): {exc}",
                error=True,
                flags=["policy_engine_error"],
            )

    def list_permissions(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = """
            SELECT p.*, a.name AS agent_name, a.role AS agent_role
            FROM permissions p
            JOIN agents a ON p.agent_id = a.agent_id
            WHERE 1=1
        """
        params: List[Any] = []
        if agent_id:
            query += " AND p.agent_id = ?"
            params.append(agent_id)
        query += " ORDER BY p.agent_id, p.resource, p.action"
        with self.db.read_connection() as conn:
            return [dict(r) for r in conn.execute(query, tuple(params)).fetchall()]

    def upsert_permission(
        self,
        *,
        agent_id: str,
        resource: str,
        action: str,
        effect: str = "ALLOW",
        max_amount: Optional[float] = None,
        requires_approval_above: Optional[float] = None,
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        effect_clean = effect.upper()
        if effect_clean not in ("ALLOW", "DENY"):
            raise ValueError("Effect must be ALLOW or DENY.")

        with self.db.write_transaction() as conn:
            existing = conn.execute(
                "SELECT permission_id FROM permissions WHERE agent_id = ? AND resource = ? AND action = ?",
                (agent_id, resource, action),
            ).fetchone()

            if existing:
                pid = existing["permission_id"]
                conn.execute(
                    """
                    UPDATE permissions
                    SET effect = ?, max_amount = ?, requires_approval_above = ?, updated_at = ?
                    WHERE permission_id = ?
                    """,
                    (effect_clean, max_amount, requires_approval_above, now, pid),
                )
            else:
                pid = f"perm-{uuid.uuid4().hex[:10]}"
                conn.execute(
                    """
                    INSERT INTO permissions (
                        permission_id, agent_id, resource, action, effect,
                        max_amount, requires_approval_above, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        pid,
                        agent_id,
                        resource,
                        action,
                        effect_clean,
                        max_amount,
                        requires_approval_above,
                        now,
                        now,
                    ),
                )
            row = conn.execute(
                "SELECT * FROM permissions WHERE permission_id = ?", (pid,)
            ).fetchone()
            return dict(row)

    def revoke_permission(self, permission_id: str) -> bool:
        with self.db.write_transaction() as conn:
            cur = conn.execute(
                "DELETE FROM permissions WHERE permission_id = ?", (permission_id,)
            )
            return cur.rowcount > 0

    def revoke_permission_by_tuple(self, agent_id: str, resource: str, action: str) -> bool:
        with self.db.write_transaction() as conn:
            cur = conn.execute(
                "DELETE FROM permissions WHERE agent_id = ? AND resource = ? AND action = ?",
                (agent_id, resource, action),
            )
            return cur.rowcount > 0
