"""Protected Resource & Tool Registry for AGENT SHIELD.

All protected financial database operations live here and are ONLY invoked by the
Security Gateway or Approval Workflow after authorization, policy, and risk checks pass.
Agents must never access SQLite or these functions directly.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.database import DatabaseManager


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    resource: str
    action: str
    description: str
    sensitive: bool
    required_args: Tuple[str, ...]
    optional_args: Tuple[str, ...]


class ProtectedToolRegistry:
    """Registry of protected financial tools with strict argument validation."""

    TOOLS: Dict[str, ToolDefinition] = {
        "read_customer_records": ToolDefinition(
            name="read_customer_records",
            resource="customers",
            action="read",
            description="Read synthetic customer profile and account records.",
            sensitive=False,
            required_args=(),
            optional_args=("customer_id", "limit", "account_tier"),
        ),
        "read_loan_records": ToolDefinition(
            name="read_loan_records",
            resource="loans",
            action="read",
            description="Read synthetic loan portfolio records.",
            sensitive=False,
            required_args=(),
            optional_args=("loan_id", "customer_id", "status", "limit"),
        ),
        "update_loan_record": ToolDefinition(
            name="update_loan_record",
            resource="loans",
            action="update",
            description="Update status or risk grade on a synthetic loan record.",
            sensitive=True,
            required_args=("loan_id",),
            optional_args=("status", "risk_grade", "remaining_balance"),
        ),
        "read_payment_records": ToolDefinition(
            name="read_payment_records",
            resource="payments",
            action="read",
            description="Read synthetic payment transaction history.",
            sensitive=False,
            required_args=(),
            optional_args=("payment_id", "customer_id", "status", "limit"),
        ),
        "request_simulated_payment": ToolDefinition(
            name="request_simulated_payment",
            resource="payments",
            action="execute",
            description="Create a strictly simulated payment record (never executes real banking transfers).",
            sensitive=True,
            required_args=("customer_id", "amount", "recipient"),
            optional_args=("payment_type", "currency", "memo"),
        ),
        "read_payroll_records": ToolDefinition(
            name="read_payroll_records",
            resource="payroll",
            action="read",
            description="Read restricted synthetic employee payroll records.",
            sensitive=True,
            required_args=(),
            optional_args=("employee_id", "limit"),
        ),
    }

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self._handlers: Dict[str, Callable[[Dict[str, Any], str], Dict[str, Any]]] = {
            "read_customer_records": self._read_customer_records,
            "read_loan_records": self._read_loan_records,
            "update_loan_record": self._update_loan_record,
            "read_payment_records": self._read_payment_records,
            "request_simulated_payment": self._request_simulated_payment,
            "read_payroll_records": self._read_payroll_records,
        }

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": t.name,
                "resource": t.resource,
                "action": t.action,
                "description": t.description,
                "sensitive": t.sensitive,
                "required_args": list(t.required_args),
                "optional_args": list(t.optional_args),
            }
            for t in self.TOOLS.values()
        ]

    def get_tool(self, tool_name: str) -> Optional[ToolDefinition]:
        return self.TOOLS.get(tool_name)

    def validate_request(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> Tuple[bool, str, Optional[ToolDefinition]]:
        """Validate tool existence, required/allowed keys, and argument types/bounds."""
        tool = self.TOOLS.get(tool_name)
        if tool is None:
            return False, f"Unknown or unregistered tool '{tool_name}'.", None

        if not isinstance(arguments, dict):
            return False, "Tool arguments must be a JSON object.", tool

        allowed = set(tool.required_args) | set(tool.optional_args)
        unknown = set(arguments.keys()) - allowed
        if unknown:
            return False, f"Unexpected argument(s) for '{tool_name}': {sorted(unknown)}.", tool

        missing = [k for k in tool.required_args if k not in arguments or arguments[k] in (None, "")]
        if missing:
            return False, f"Missing required argument(s) for '{tool_name}': {missing}.", tool

        if "limit" in arguments:
            try:
                lim = int(arguments["limit"])
                if lim < 1 or lim > 100:
                    return False, "Argument 'limit' must be between 1 and 100.", tool
            except (TypeError, ValueError):
                return False, "Argument 'limit' must be an integer.", tool

        if "amount" in arguments:
            try:
                amt = float(arguments["amount"])
                if amt <= 0:
                    return False, "Argument 'amount' must be positive.", tool
            except (TypeError, ValueError):
                return False, "Argument 'amount' must be a valid number.", tool

        if "remaining_balance" in arguments:
            try:
                bal = float(arguments["remaining_balance"])
                if bal < 0:
                    return False, "Argument 'remaining_balance' cannot be negative.", tool
            except (TypeError, ValueError):
                return False, "Argument 'remaining_balance' must be a valid number.", tool

        return True, "Tool and arguments validated.", tool

    def execute_tool(
        self, tool_name: str, arguments: Dict[str, Any], authenticated_agent_id: str
    ) -> Dict[str, Any]:
        """Execute a validated protected tool. Must only be called by SecurityGateway/ApprovalWorkflow."""
        handler = self._handlers.get(tool_name)
        if handler is None:
            raise ValueError(f"Tool '{tool_name}' is not registered.")
        return handler(arguments, authenticated_agent_id)

    def _read_customer_records(self, args: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
        limit = int(args.get("limit", 10))
        query = "SELECT * FROM customers WHERE 1=1"
        params: List[Any] = []
        if args.get("customer_id"):
            query += " AND customer_id = ?"
            params.append(str(args["customer_id"]))
        if args.get("account_tier"):
            query += " AND account_tier = ?"
            params.append(str(args["account_tier"]))
        query += " ORDER BY customer_id ASC LIMIT ?"
        params.append(limit)

        with self.db.read_connection() as conn:
            rows = [dict(r) for r in conn.execute(query, tuple(params)).fetchall()]
        return {
            "records": rows,
            "record_count": len(rows),
            "record_ids": [r["customer_id"] for r in rows],
            "executed": True,
        }

    def _read_loan_records(self, args: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
        limit = int(args.get("limit", 10))
        query = "SELECT * FROM loans WHERE 1=1"
        params: List[Any] = []
        if args.get("loan_id"):
            query += " AND loan_id = ?"
            params.append(str(args["loan_id"]))
        if args.get("customer_id"):
            query += " AND customer_id = ?"
            params.append(str(args["customer_id"]))
        if args.get("status"):
            query += " AND status = ?"
            params.append(str(args["status"]))
        query += " ORDER BY loan_id ASC LIMIT ?"
        params.append(limit)

        with self.db.read_connection() as conn:
            rows = [dict(r) for r in conn.execute(query, tuple(params)).fetchall()]
        return {
            "records": rows,
            "record_count": len(rows),
            "record_ids": [r["loan_id"] for r in rows],
            "executed": True,
        }

    def _update_loan_record(self, args: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
        loan_id = str(args["loan_id"])
        updates: List[str] = []
        params: List[Any] = []
        if "status" in args and args["status"]:
            allowed_statuses = {"active", "under_review", "approved", "delinquent", "closed"}
            if str(args["status"]) not in allowed_statuses:
                raise ValueError(f"Invalid loan status '{args['status']}'.")
            updates.append("status = ?")
            params.append(str(args["status"]))
        if "risk_grade" in args and args["risk_grade"]:
            updates.append("risk_grade = ?")
            params.append(str(args["risk_grade"]))
        if "remaining_balance" in args and args["remaining_balance"] is not None:
            updates.append("remaining_balance = ?")
            params.append(round(float(args["remaining_balance"]), 2))

        if not updates:
            raise ValueError("No updatable fields provided for loan record.")

        now = datetime.now(timezone.utc).isoformat()
        updates.append("updated_at = ?")
        params.append(now)
        params.append(loan_id)

        with self.db.write_transaction() as conn:
            cur = conn.execute(
                f"UPDATE loans SET {', '.join(updates)} WHERE loan_id = ?",
                tuple(params),
            )
            if cur.rowcount == 0:
                raise ValueError(f"Loan '{loan_id}' not found.")
            updated = dict(
                conn.execute("SELECT * FROM loans WHERE loan_id = ?", (loan_id,)).fetchone()
            )
        return {
            "record": updated,
            "record_count": 1,
            "record_ids": [loan_id],
            "executed": True,
        }

    def _read_payment_records(self, args: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
        limit = int(args.get("limit", 10))
        query = "SELECT * FROM payments WHERE 1=1"
        params: List[Any] = []
        if args.get("payment_id"):
            query += " AND payment_id = ?"
            params.append(str(args["payment_id"]))
        if args.get("customer_id"):
            query += " AND customer_id = ?"
            params.append(str(args["customer_id"]))
        if args.get("status"):
            query += " AND status = ?"
            params.append(str(args["status"]))
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self.db.read_connection() as conn:
            rows = [dict(r) for r in conn.execute(query, tuple(params)).fetchall()]
        return {
            "records": rows,
            "record_count": len(rows),
            "record_ids": [r["payment_id"] for r in rows],
            "executed": True,
        }

    def _request_simulated_payment(self, args: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
        """Creates a strictly simulated payment row in SQLite. Never performs real transfers."""
        customer_id = str(args["customer_id"])
        amount = round(float(args["amount"]), 2)
        recipient = str(args["recipient"])
        payment_type = str(args.get("payment_type", "simulated_transfer"))
        currency = str(args.get("currency", "USD"))
        payment_id = f"PAY-SIM-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc).isoformat()

        with self.db.write_transaction() as conn:
            cust = conn.execute(
                "SELECT customer_id FROM customers WHERE customer_id = ?",
                (customer_id,),
            ).fetchone()
            if cust is None:
                raise ValueError(f"Customer '{customer_id}' not found.")

            conn.execute(
                """
                INSERT INTO payments (
                    payment_id, customer_id, amount, currency,
                    payment_type, recipient, status, initiated_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payment_id,
                    customer_id,
                    amount,
                    currency,
                    payment_type,
                    recipient,
                    "simulated_completed",
                    agent_id,
                    now,
                ),
            )
            created = dict(
                conn.execute("SELECT * FROM payments WHERE payment_id = ?", (payment_id,)).fetchone()
            )
        return {
            "simulated_only": True,
            "record": created,
            "record_count": 1,
            "record_ids": [payment_id],
            "executed": True,
        }

    def _read_payroll_records(self, args: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
        limit = int(args.get("limit", 10))
        query = """
            SELECT p.*, e.full_name, e.department, e.job_title
            FROM payroll p
            JOIN employees e ON p.employee_id = e.employee_id
            WHERE 1=1
        """
        params: List[Any] = []
        if args.get("employee_id"):
            query += " AND p.employee_id = ?"
            params.append(str(args["employee_id"]))
        query += " ORDER BY p.payroll_id ASC LIMIT ?"
        params.append(limit)

        with self.db.read_connection() as conn:
            rows = [dict(r) for r in conn.execute(query, tuple(params)).fetchall()]
        return {
            "records": rows,
            "record_count": len(rows),
            "record_ids": [r["payroll_id"] for r in rows],
            "executed": True,
        }
