# AGENT SHIELD — REST API Documentation (AVISHKAR'26 Problem Statement 9)

Base URL (local): `http://127.0.0.1:8000`
Interactive OpenAPI / Swagger UI: `http://127.0.0.1:8000/docs`

---

## 1. Central Security Gateway

### `POST /api/gateway/execute`
Intercepts every simulated agent tool call through the 8-step security pipeline.

- **Header**: `X-Agent-Key: agsh_...` (identity derived strictly from SHA-256 hash; `untrusted_agent_id` in body is ignored)
- **Body**:
```json
{
  "tool_name": "read_customer_records",
  "arguments": { "customer_id": "CUST-0001", "limit": 2 },
  "prompt_context": null,
  "simulated_hour": 3
}
```
- **Response** includes:
  - `decision` (`ALLOW`, `BLOCK`, `MONITOR`, `REQUIRE_APPROVAL`), `executed`
  - `risk_score` (0–100), `risk_level`, `risk_breakdown` (`resource_action_sensitivity`, `policy_and_injection`, `behaviour_rules`, `ml_isolation_forest`), `risk_factors`, `risk_disclaimer`
  - `behaviour` (`status`, `metrics` across all 5 features, `baseline_profile`, `ml_is_anomaly`, `anomaly_score`, `ml_severity_points`, `detector_mode`)
  - `pipeline_trace` (8-step structured trace from Auth to Audit/Alerts)
  - `data`, `approval_request`, `alert_id`, `audit`

---

## 2. Permission Registry & Agent Management

- `GET /api/tools` — Lists registered protected financial tools.
- `GET /api/agents` | `POST /api/agents` | `GET /api/agents/{agent_id}`
- `PATCH /api/agents/{agent_id}/status` — Activate/deactivate agent immediately.
- `POST /api/agents/{agent_id}/rotate-key` — Rotate SHA-256 credential.
- `GET /api/permissions?agent_id=...` | `POST /api/permissions` | `DELETE /api/permissions/{permission_id}`

---

## 3. Behaviour Baselines, Monitoring, Alerts & Approvals

- `GET /api/behaviour/baselines` — Lists persisted per-agent trusted synthetic normal baselines (`normal_resources`, `normal_hours_start/end`, `baseline_sample_count`, `trusted_source`).
- `GET /api/behaviour/summary` — Per-agent sliding-window telemetry + baseline metadata + active detector mode.
- `GET /api/behaviour/activity?limit=60` — Activity log stream.
- `GET /api/alerts` | `POST /api/alerts/{alert_id}/acknowledge`
- `GET /api/approvals` | `POST /api/approvals/{approval_id}/approve` | `POST /api/approvals/{approval_id}/reject`

---

## 4. Audit Engine, Overview & Security Playground

- `GET /api/dashboard/overview` — Live KPIs, decision distribution, recent risk series, synthetic DB counts, audit chain validity.
- `GET /api/audit/logs` | `GET /api/audit/verify` — Tamper-evident SHA-256 audit logs & chain integrity verification.
- `GET /api/playground/scenarios` — Lists all 9 executable scenarios.
- `GET /api/playground/demo-keys` — Demo agent credentials for interactive Playground testing.
- `POST /api/playground/run` — Executes Scenario 1–9 through the live Security Gateway.
- `POST /api/admin/reset-demo` — Resets and reseeds the synthetic database.
