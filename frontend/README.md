# AGENT SHIELD — Frontend Tech Stack
### Security Operations Centre (SOC) Web Dashboard

This folder contains the complete user interface for **AVISHKAR'26 Problem Statement 9**.

---

## 1. Technologies Used

- **HTML5:** Semantic markup structured for a professional 8-page SOC console.
- **CSS3:** Custom responsive layout, dark cybersecurity palette (`#0B1120`, `#111827`, `#172235`, accent `#22D3EE`), status badges, and interactive controls. No bulky third-party CSS frameworks.
- **Vanilla JavaScript (ES6+):** Pure browser JavaScript with zero framework dependencies (React, Vue, or Angular not required).
- **Chart.js (4.4+):** Visualizing enforcement decision distributions and real-time risk trends.

---

## 2. The 8 Interactive Pages

1. **Overview Dashboard (`#page-overview`):**
   - KPI counters: Active Agents, Total Intercepted Requests, Allowed, Blocked, Monitored, Average Risk Score.
   - Real-time Chart.js doughnut chart of decision breakdowns and line chart of latest risk scores.
   - Database scope card showing synthetic record counts.
2. **Agent Creator (`#page-creator`):**
   - Form to dynamically register new AI agents with customizable roles, system instructions, and tool whitelists.
   - Generates unique SHA-256 hashed API keys (`agsh_...`).
3. **Agent Management (`#page-agents`):**
   - Tabular directory of registered agents.
   - Instant toggle for active / inactive state.
   - Credential rotation action.
4. **Permission Registry (`#page-permissions`):**
   - Interactive policy management matrix.
   - Grant or revoke permissions (ALLOW / DENY).
   - Set maximum amounts and approval threshold values.
5. **Behaviour Monitor (`#page-behaviour`):**
   - Live display of per-agent trusted normal baselines (sample counts, allowed hours, allowed categories).
   - Sliding-window telemetry (requests, unique records, failed auth, off-hours flag).
   - Stream of recent tool calls.
6. **Security Alerts & Approvals (`#page-alerts`):**
   - Approvals queue: Inspect pending high-value operations with one-click Approve / Reject.
   - Security alerts: Chronological alert stream with severity tags and explainable detection reasons.
7. **Audit Logs (`#page-audit`):**
   - Complete SHA-256 hash-chained audit log with previous hash and current hash.
   - One-click **"Verify Hash Chain"** button to check cryptographic integrity.
8. **Security Playground (`#page-playground`):**
   - 9 executable scenario cards representing all problem statement security scenarios.
   - Custom Gateway Request Tester to send real requests with headers and payloads.
   - 8-stage interactive pipeline trace visualizer and formatted JSON output.

---

## 3. Directory Layout

```
frontend/
├── index.html        # Single-page application holding all 8 SOC pages
├── css/
│   └── styles.css    # Professional dark cybersecurity SOC styling
└── js/
    ├── api.js        # REST client communicating with FastAPI backend
    ├── charts.js     # Chart.js initialization and live updates
    └── app.js        # Application controller, event listeners, and scenario execution
```
