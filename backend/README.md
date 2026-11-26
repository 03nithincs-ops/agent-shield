# AGENT SHIELD — Backend Tech Stack
### FastAPI, SQLite, and Security Enforcement Engines

This folder contains the complete backend implementation for **AVISHKAR'26 Problem Statement 9**.

---

## 1. Architectural Role

The backend serves as the centralized security perimeter for all interactions between simulated AI agents and sensitive financial resources.

```
Incoming Request (X-Agent-Key Header)
  → auth.py (Authenticate credential via SHA-256 hash)
  → tool_registry.py (Validate tool name and arguments against schema)
  → policy_engine.py (Check Permission Registry; evaluate ALLOW vs DENY)
  → behaviour_monitor.py (Extract 5 sliding-window behavioural features)
  → anomaly_detector.py (Evaluate against per-agent Scikit-learn Isolation Forest)
  → risk_engine.py (Calculate 0–100 explainable multi-factor risk score)
  → enforcement_engine.py (Apply ALLOW / BLOCK / MONITOR / REQUIRE_APPROVAL)
  → approval_workflow.py (Hold sensitive transfers for human authorization)
  → database.py (Execute operation in SQLite only if permitted)
  → audit_engine.py (Write SHA-256 tamper-evident hash-chained audit record)
  → app.py (Return structured pipeline trace & response)
```

---

## 2. Module Index

| File | Responsibilities |
|---|---|
| `app.py` | FastAPI application factory, REST endpoints, CORS, static frontend mount |
| `gateway.py` | Central 12-step runtime security gateway orchestrating the full pipeline |
| `auth.py` | SHA-256 credential hashing, random token generation, credential verification |
| `policy_engine.py` | Persistent Permission Registry evaluation, explicit DENY precedence, prompt injection filter |
| `enforcement_engine.py` | Decides ALLOW, BLOCK, MONITOR, or REQUIRE_APPROVAL (fail-closed) |
| `behaviour_monitor.py` | Sliding-window activity telemetry, feature extraction in `Asia/Kolkata` timezone |
| `anomaly_detector.py` | Per-agent Scikit-learn Isolation Forest model training and scoring |
| `risk_engine.py` | 0–100 explainable risk score calculation with granular factor breakdown |
| `audit_engine.py` | SHA-256 hash-chained cryptographic audit trail and chain integrity verification |
| `approval_workflow.py` | Human-in-the-loop approval management with post-approval revalidation |
| `tool_registry.py` | Whitelist and execution harness for protected financial database operations |
| `database.py` | SQLite connection manager with thread-safe `IMMEDIATE` write transactions |
| `schemas.py` | Pydantic data models for API requests and responses |
| `config.py` | System thresholds, timezones, and operating parameters |
