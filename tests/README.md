# AGENT SHIELD — Automated Testing Tech Stack

This folder contains the complete automated test suite validating **AVISHKAR'26 Problem Statement 9** requirements.

---

## 1. Test Architecture

The test suite is built on Python's standard `unittest` framework and is also 100% compatible with `pytest`. It runs against real temporary SQLite databases and actual Scikit-learn Isolation Forest models.

---

## 2. Test Modules

| File | Focus Area | Tests Included |
|---|---|---|
| `test_agents.py` | Agent Management | Default agents exist, custom agent creation, credential SHA-256 hashing, status toggle, credential rotation |
| `test_permissions.py` | Permission Registry | Default permissions, explicit DENY precedence, approval threshold triggers, permission revocation |
| `test_gateway.py` | Security Gateway | Header authentication, fail-closed on bad credentials, untrusted body ID ignored, 8-stage pipeline trace |
| `test_behaviour.py` | Behaviour Monitoring | Normal activity evaluation, unseen resource category detection, off-hours detection in `Asia/Kolkata` |
| `test_anomaly_detection.py` | Isolation Forest | Active Scikit-learn model, off-hours anomaly flagging, volume anomaly flagging, baseline immutability (anti-poisoning) |
| `test_risk.py` | Risk Engine | Low risk for normal access, critical risk on denied sensitive operations, transparent ML anomaly point contribution |
| `test_audit.py` | Audit Logging | SHA-256 genesis and block linking, tamper detection on mutated rows, concurrency-safe atomic writes |
| `test_scenarios.py` / `test_security_scenarios.py` | Mandatory Scenarios | Full end-to-end execution of all 9 Problem Statement 9 scenarios |
| `test_api_integration.py` | REST API | FastAPI endpoints, health check, playground HTTP scenario runs, custom agent gateway execution |

---

## 3. Running the Tests

```powershell
# Run all modular unit tests:
python -m unittest tests.test_agents tests.test_permissions tests.test_gateway tests.test_behaviour tests.test_anomaly_detection tests.test_risk tests.test_audit tests.test_scenarios -v

# Run full discovery suite:
python -m unittest discover -s tests -v
```
