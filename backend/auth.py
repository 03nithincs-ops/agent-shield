"""Authentication module for AGENT SHIELD.

Derives agent identity strictly from cryptographic API credentials (SHA-256 hashed),
never from untrusted agent_id fields supplied in request bodies.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from backend.config import ADMIN_API_KEY
from backend.database import DatabaseManager


@dataclass
class AuthenticatedAgent:
    agent_id: str
    name: str
    role: str
    status: str
    available_tools: List[str]
    agent_type: str


@dataclass
class AuthResult:
    authenticated: bool
    agent: Optional[AuthenticatedAgent]
    reason: str
    error: bool = False


class AuthService:
    """Handles credential generation, hashing, and strict credential-based authentication."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    @staticmethod
    def generate_credential() -> tuple[str, str, str]:
        """Return (raw_token, sha256_hash, display_prefix)."""
        raw_token = f"agsh_{secrets.token_urlsafe(24)}"
        cred_hash = AuthService.hash_credential(raw_token)
        prefix = raw_token[:12] + "..."
        return raw_token, cred_hash, prefix

    @staticmethod
    def hash_credential(raw_token: str) -> str:
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    @staticmethod
    def verify_admin_key(api_key: Optional[str]) -> bool:
        if not api_key:
            return False
        return hmac.compare_digest(api_key, ADMIN_API_KEY)

    def authenticate_agent(self, raw_token: Optional[str]) -> AuthResult:
        """Authenticate an agent purely from its credential token. Fails closed on any error."""
        if not raw_token or not isinstance(raw_token, str) or not raw_token.strip():
            return AuthResult(
                authenticated=False,
                agent=None,
                reason="Missing agent authentication credential.",
            )

        try:
            cred_hash = self.hash_credential(raw_token.strip())
            with self.db.read_connection() as conn:
                row = conn.execute(
                    """
                    SELECT agent_id, name, role, status, available_tools, agent_type
                    FROM agents
                    WHERE credential_hash = ?
                    """,
                    (cred_hash,),
                ).fetchone()

            if row is None:
                return AuthResult(
                    authenticated=False,
                    agent=None,
                    reason="Invalid agent credential.",
                )

            if row["status"] != "active":
                return AuthResult(
                    authenticated=False,
                    agent=None,
                    reason=f"Agent '{row['agent_id']}' is inactive ({row['status']}).",
                )

            tools = json.loads(row["available_tools"]) if row["available_tools"] else []
            agent = AuthenticatedAgent(
                agent_id=row["agent_id"],
                name=row["name"],
                role=row["role"],
                status=row["status"],
                available_tools=tools,
                agent_type=row["agent_type"],
            )
            return AuthResult(
                authenticated=True,
                agent=agent,
                reason="Authenticated via verified SHA-256 credential.",
            )
        except Exception as exc:
            # Fail closed on any authentication backend failure
            return AuthResult(
                authenticated=False,
                agent=None,
                reason=f"Authentication service failure (fail-closed): {exc}",
                error=True,
            )

    def get_agent_by_id(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Internal lookup used during approval revalidation."""
        with self.db.read_connection() as conn:
            row = conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
            return dict(row) if row else None
