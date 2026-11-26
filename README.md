# AGENT SHIELD README

# 🛡️ AGENT SHIELD
### Every Agent. Every Action. Under Control.

## Problem Statement

**AI Agent Authorization Monitoring and Permission Enforcement**

Domain: AI in Cybersecurity and FinTech

As AI agents become increasingly autonomous and embedded in critical systems, traditional access control mechanisms are insufficient. Organizations need a system that can:
- Monitor AI agent activities in real-time
- Enforce permissions at runtime before execution
- Detect anomalous behaviour using machine learning
- Provide explainable risk assessments
- Maintain tamper-resistant audit trails
- Alert administrators to suspicious activities

## Solution Overview

**Agent Shield** is a full-stack cybersecurity web application that provides end-to-end AI agent governance through six integrated modules:

1. **Agent Permission Registry** — Register and manage AI agents with granular permissions
2. **Runtime Policy Engine** — Backend authorization enforcement on every request
3. **Isolation Forest Anomaly Detection** — ML-powered behavioural anomaly detection
4. **Explainable Risk Scoring** — Transparent 0–100 risk assessments with contributing factors
5. **Comprehensive Audit Logs** — Every event logged, searchable, filterable, exportable
6. **Live Dashboard & Security Alerts** — Real-time metrics and automated alerting

---

## ⚠️ Important Disclaimer

This is a **demonstration prototype** built for a 24-hour hackathon using:
- **Simulated AI agents** (not real external AI systems)
- **Synthetic data only** (no real customer or financial data)
- **Simulated resource operations** (no actual APIs called)

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| Frontend | Streamlit |
| Backend | FastAPI (Python) |
| Database | SQLite |
| ML | Scikit-learn (Isolation Forest) |
| Data Processing | Pandas, NumPy |
| Visualization | Plotly |
| Validation | Pydantic v2 |
| Communication | REST API (JSON) |

---

## Architecture

```
AI Agent Simulator (Request Simulator Page)
        |
        v
Request Validation (Pydantic schemas)
        |
        v
Runtime Policy Engine (backend/policy_engine.py)
        |
        +---- DENY -----> Record Security Event -----> Alert Generation
        |
        +---- ALLOW ----> Simulated Resource Operation
                              |
                              v
                       Activity Collection
                              |
                              v
                       Isolation Forest
                       (backend/anomaly_detector.py)
                              |
                              v
                        Risk Analysis
                        (backend/risk_analyzer.py)
                              |
                              v
                         Audit Logs (SQLite)
                              |
                              v
                     Dashboard & Alerts (Streamlit)
```

**Key Principle:** Authorization happens on the backend before any resource operation. The frontend never makes authorization decisions.

---

## Database Schema

### agents
```sql
agent_id TEXT PRIMARY KEY
agent_name TEXT
agent_type TEXT
status TEXT  -- ACTIVE | INACTIVE
description TEXT
created_at TEXT
updated_at TEXT
```

### permissions
```sql
permission_id INTEGER PRIMARY KEY
agent_id TEXT (FK → agents)
resource TEXT
action TEXT  -- READ | WRITE | EXECUTE
created_at TEXT
UNIQUE(agent_id, resource, action)
```

### audit_logs
```sql
event_id TEXT PRIMARY KEY
timestamp TEXT
agent_id TEXT
agent_name TEXT
resource TEXT
action TEXT
decision TEXT  -- ALLOW | DENY
denial_reason TEXT
anomaly_classification TEXT
anomaly_score REAL
risk_score INTEGER
risk_level TEXT
risk_factors TEXT (JSON)
suggested_action TEXT
```

### alerts
```sql
alert_id TEXT PRIMARY KEY
timestamp TEXT
agent_id TEXT
agent_name TEXT
alert_type TEXT
severity TEXT  -- LOW | MEDIUM | HIGH | CRITICAL
message TEXT
details TEXT (JSON)
is_acknowledged INTEGER
```

### test_results
```sql
test_id TEXT PRIMARY KEY
test_name TEXT
test_scenario TEXT
test_input TEXT
expected_result TEXT
actual_result TEXT
status TEXT  -- PASS | FAIL | ERROR
error_details TEXT
execution_time_ms REAL
run_at TEXT
```

---

## Project Structure

```
agent_shield/
├── backend/
│   ├── __init__.py
│   ├── main.py           # FastAPI application
│   ├── database.py       # SQLite management + initialization
│   ├── schemas.py        # Pydantic validation models
│   ├── policy_engine.py  # Runtime authorization (fail-secure)
│   ├── anomaly_detector.py  # Isolation Forest ML model
│   ├── risk_analyzer.py  # Explainable risk scoring
│   ├── audit_logger.py   # Event logging
│   ├── alert_manager.py  # Security alerting
│   └── routes/
│       ├── agents.py      # Agent CRUD endpoints
│       ├── authorization.py  # Authorization endpoint
│       ├── analytics.py   # Dashboard, logs, risk endpoints
│       └── testing.py     # Automated security tests
├── frontend/
│   ├── __init__.py
│   ├── app.py            # Streamlit home page
│   ├── api_client.py     # Backend API client
│   ├── components/
│   │   └── ui.py         # Shared UI components + theming
│   └── pages/
│       ├── 1_Security_Overview.py
│       ├── 2_Agent_Management.py
│       ├── 3_Permission_Registry.py
│       ├── 4_Request_Simulator.py
│       ├── 5_Anomaly_Detection.py
│       ├── 6_Risk_Analysis.py
│       ├── 7_Audit_Logs.py
│       ├── 8_Alerts_Monitoring.py
│       ├── 9_Security_Testing.py
│       ├── 10_Settings.py
│       └── 11_AI_Agent_Chat.py   # Ollama (qwen2.5:3b) Local AI Agent Chat
├── ml/
│   └── train_model.py    # Standalone model training
├── data/                 # SQLite DB + ML model (auto-created)
├── requirements.txt
└── README.md
```

---

## Installation

### Prerequisites
- Python 3.9+
- pip

### Setup

```bash
# Clone or navigate to the project
cd agent_shield

# Install dependencies
pip install -r requirements.txt
```

---

## Running the Application

### Step 1: Start the Backend (FastAPI)

```bash
# From the agent_shield/ directory
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

The backend will:
- Initialize the SQLite database automatically
- Create the 3 initial sample agents
- Train the Isolation Forest model
- Start serving on http://localhost:8000

API documentation: http://localhost:8000/docs

### Step 2: Start the Frontend (Streamlit)

In a **new terminal**:

```bash
# From the agent_shield/ directory
streamlit run frontend/app.py
```

The frontend will open at http://localhost:8501

### Optional: Pre-train the ML Model

```bash
python ml/train_model.py
```

---

## Initial Sample Agents

| Agent | Type | Resources | Actions |
|-------|------|-----------|---------|
| Customer Support Agent (agent-001) | Support | customer_files, support_database | READ |
| Payment Agent (agent-002) | Financial | transaction_database, payment_api | READ, EXECUTE |
| Analytics Agent (agent-003) | Analytics | analytics_database, reports | READ, WRITE |

---

## Local AI Model Integration (Ollama + qwen2.5:3b)

Agent Shield integrates directly with a **free, 100% local AI model** via **Ollama** at `http://localhost:11434`.

- **Model:** `qwen2.5:3b` (Qwen 2.5 3-Billion parameters)
- **Tool Calling Support:** Native function calling supported
- **Security Invariant:** The LLM decides *when* to request tools, but the **Runtime Policy Engine makes the final authorization decision**. The LLM can never bypass permissions.
- **Available Tool:** `lookup_customer(customer_id)` (requires `customer_files:READ`)

### Exact Ollama Setup Commands

```bash
# 1. Download & Install Ollama from:
#    https://ollama.com

# 2. Pull and start the local model:
ollama run qwen2.5:3b

# 3. Ollama runs locally on http://localhost:11434 with zero API keys or external costs.
```

*Note: If Ollama is offline, Agent Shield automatically operates in resilient local fallback mode so testing and verification remain 100% functional.*

---

## Demo Scenarios

### Scenario A: Authorized Access
- Agent: Customer Support Agent
- Resource: customer_files, Action: READ
- Expected: ✅ ALLOW + simulated data returned

### Scenario B: Unauthorized Access
- Agent: Customer Support Agent
- Resource: payment_api, Action: EXECUTE
- Expected: 🚫 DENY + risk assessment + audit log

### Scenario C: High-Frequency Activity
- Agent: Any agent, Repeat Count: 10+
- Expected: Anomaly detection triggered, risk elevated

### Scenario D: Unknown Agent
- Agent ID: unknown-agent-999
- Expected: 🚫 DENY — agent not registered

### Scenario E: Privilege Escalation
- Agent: Customer Support Agent (support role)
- Resource: transaction_database, Action: EXECUTE
- Expected: 🚫 DENY + HIGH/CRITICAL risk + alert generated

### Scenario F: Permission Revocation
1. Deactivate Payment Agent in Agent Management
2. Run any request as Payment Agent
3. Expected: 🚫 DENY — inactive agent

---

## Security Testing

Navigate to **Security Testing Centre** and click **Run All Tests**.

18 automated test cases validate:
- Authorization decisions (ALLOW/DENY)
- Edge case handling (unknown agents, inactive agents, invalid inputs)
- Permission updates and revocation
- Anomaly detection
- Risk scoring
- Audit logging
- Dashboard metrics

Tests use isolated test data (`test-agent-temp-*`) and clean up automatically.

---

## Edge Case Handling

### Authorization Failures (Fail-Secure)
- Unknown agent → DENY
- Inactive agent → DENY regardless of permissions
- Invalid action → DENY
- Empty inputs → DENY
- Internal error → DENY (never bypass on error)

### ML Model Unavailable
- Authorization continues independently
- Anomaly classification marked as UNAVAILABLE
- Risk score computed without anomaly factor

### Database Errors
- Graceful error messages shown
- No silent failures
- Authorization defaults to DENY on error

---

## Risk Score Reference

| Score | Level | Meaning |
|-------|-------|---------|
| 0–29 | LOW | Normal operation |
| 30–59 | MEDIUM | Elevated — monitor |
| 60–79 | HIGH | Alert — investigate |
| 80–100 | CRITICAL | Immediate action required |

---

## Limitations

1. Single-node SQLite (not production-scale)
2. In-memory model reloading (not distributed)
3. Simulated agents only (no real AI agent integration)
4. Rate limiting is basic (not production-grade)
5. No authentication/authorization for the admin dashboard itself
6. Anomaly detection trained on synthetic data only

---

## Future Scope

1. Real AI agent integration via webhook/API
2. Distributed deployment with PostgreSQL
3. OAuth2/RBAC for admin dashboard
4. Real-time WebSocket alerts
5. Advanced ML models (LSTM for time-series anomaly detection)
6. Policy-as-Code with YAML/OPA integration
7. Cryptographically signed audit logs
8. Multi-tenant support
9. SIEM integration (Splunk, Elastic)
10. Automated remediation workflows

---

## Hackathon Demo Guide

**For judges — 5-minute demo flow:**

1. **Show Security Overview** — 6 live metrics, activity charts
2. **Agent Management** — Show 3 pre-configured agents
3. **Request Simulator**:
   - Run Scenario A → See ALLOW + simulated operation
   - Run Scenario B → See DENY + risk score
   - Run Scenario E → See privilege escalation alert
4. **Anomaly Detection** — Use "Suspicious Activity" preset → ANOMALOUS
5. **Risk Analysis** — Show risk history chart
6. **Audit Logs** — Browse complete event trail
7. **Alerts** — Show auto-generated security alerts
8. **Security Testing** — Run All Tests → Show PASS/FAIL results

---

*Built in 24 hours for a hackathon. Agent Shield demonstrates that AI agent governance is achievable with open-source technologies.*
