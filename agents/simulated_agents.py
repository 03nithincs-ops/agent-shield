"""Simulated Deterministic AI Agents for AGENT SHIELD.

Complying with AVISHKAR'26 Problem Statement 9:
- Clearly identified as simulated deterministic Python agents.
- No false claims of LLM integration.
- Demonstrates realistic autonomous agent tool invocation patterns.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class BaseSimulatedAgent:
    """Base class for Python-managed deterministic simulated agents."""

    def __init__(self, agent_id: str, name: str, role: str, credential: str) -> None:
        self.agent_id = agent_id
        self.name = name
        self.role = role
        self.credential = credential

    def build_tool_request(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        prompt_context: Optional[str] = None,
        simulated_hour: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Construct a standardized tool request for the Security Gateway."""
        return {
            "credential": self.credential,
            "tool_name": tool_name,
            "arguments": arguments,
            "prompt_context": prompt_context,
            "simulated_hour": simulated_hour,
        }


class SupportAgent(BaseSimulatedAgent):
    """Customer Support simulated agent authorized strictly for customer read operations."""

    def __init__(self, credential: str) -> None:
        super().__init__(
            agent_id="agent-support-01",
            name="Support Agent",
            role="Customer Support",
            credential=credential,
        )

    def request_customer_lookup(self, customer_id: str = "CUST-0001", limit: int = 1) -> Dict[str, Any]:
        return self.build_tool_request(
            tool_name="read_customer_records",
            arguments={"customer_id": customer_id, "limit": limit},
        )

    def request_payroll_attempt(self, limit: int = 5) -> Dict[str, Any]:
        """Simulate an unauthorized access attempt to restricted payroll data."""
        return self.build_tool_request(
            tool_name="read_payroll_records",
            arguments={"limit": limit},
        )


class PaymentAgent(BaseSimulatedAgent):
    """Payment Operations simulated agent authorized for payments and transfers."""

    def __init__(self, credential: str) -> None:
        super().__init__(
            agent_id="agent-payment-01",
            name="Payment Agent",
            role="Payments Operations",
            credential=credential,
        )

    def request_payment(self, customer_id: str, amount: float, recipient: str) -> Dict[str, Any]:
        return self.build_tool_request(
            tool_name="request_simulated_payment",
            arguments={
                "customer_id": customer_id,
                "amount": amount,
                "recipient": recipient,
            },
        )


class LoanAgent(BaseSimulatedAgent):
    """Loan Servicing simulated agent authorized for loan inspection and review updates."""

    def __init__(self, credential: str) -> None:
        super().__init__(
            agent_id="agent-loan-01",
            name="Loan Agent",
            role="Loan Servicing",
            credential=credential,
        )

    def request_loan_lookup(self, loan_id: Optional[str] = None, limit: int = 5) -> Dict[str, Any]:
        args = {"limit": limit}
        if loan_id:
            args["loan_id"] = loan_id
        return self.build_tool_request(
            tool_name="read_loan_records",
            arguments=args,
        )
