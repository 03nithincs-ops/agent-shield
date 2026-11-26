# AGENT SHIELD — Agent Tech Stack

This folder contains the simulated AI agent definitions and runtime manager for **AVISHKAR'26 Problem Statement 9**.

---

## 1. Simulated Agent Architecture

- **Simulated, Deterministic Agents:** All agents in this repository are deterministic Python-managed simulated agents. No external or local LLMs (Ollama, DeepSeek, OpenAI) are used or required.
- **Credential Model:** Every agent is issued a unique secret key (`agsh_...`). Only the cryptographic SHA-256 hash of the credential is stored in the database.
- **Identity Derivation:** The Security Gateway resolves agent identity strictly from the authenticated credential passed in `X-Agent-Key`. Any `agent_id` in the body is explicitly ignored.

---

## 2. Default Initial Agents

1. **Support Agent (`agent-support-01`)**
   - **Role:** Customer Support Specialist
   - **Allowed Scope:** Read synthetic customer records (`read_customer_records`)
   - **Prohibited:** Payroll, payment execution, employee records
2. **Payment Agent (`agent-payment-01`)**
   - **Role:** Payments Operations Lead
   - **Allowed Scope:** Read payments and request simulated payments (`read_payment_records`, `request_simulated_payment`)
   - **Constraint:** Payments exceeding $5,000 threshold require human approval
3. **Loan Agent (`agent-loan-01`)**
   - **Role:** Loan Servicing Officer
   - **Allowed Scope:** Read and update loan records (`read_loan_records`, `update_loan_record`)
   - **Prohibited:** Payroll, payment execution

---

## 3. Module Files

| File | Description |
|---|---|
| `manager.py` | Agent lifecycle management (dynamic agent creation, credential generation, status toggle, key rotation) |
| `runtime.py` | Runtime invocation harness executing simulated agent requests through the Security Gateway |
| `simulated_agents.py` | Agent classes (`SupportAgent`, `PaymentAgent`, `LoanAgent`) with request builders |
