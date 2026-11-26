# AGENT SHIELD — Machine Learning Tech Stack
### Scikit-Learn Isolation Forest Anomaly Detection

This folder contains the complete Machine Learning implementation for **AVISHKAR'26 Problem Statement 9**.

---

## 1. Overview & Problem Statement Compliance

- **Algorithm:** Actual Scikit-learn `IsolationForest(n_estimators=100, contamination=0.05, random_state=42)`
- **Per-Agent Modeling:** Each simulated AI agent (Support Agent, Payment Agent, Loan Agent, and custom agents) has an independently trained baseline model.
- **Baseline Sample Count:** >= 250 synthetic normal activity records generated with reproducible seeds derived from the agent ID (`agent_seed`).
- **Baseline Immutability:** Models are trained **strictly on trusted baseline distributions** and are **never** automatically updated or polluted from incoming untrusted runtime traffic (anti-poisoning guarantee).
- **Hard Invariant:** A normal ML score (`predict == 1`) can **never** override an explicit permission denial from the Permission Registry.

---

## 2. Monitored Behavioural Features

The pipeline tracks 5 core behavioural features:

1. `requests_in_window`: Request velocity in sliding 60-second window.
2. `projected_unique_records`: Number of unique customer/payment/loan/payroll records accessed.
3. `unseen_resource_flag`: Access to resource categories outside the agent's trusted baseline.
4. `failed_authz_in_window`: Number of permission denials or unverified attempts in sliding window.
5. `off_hours_flag`: Access outside trusted operating hours (default timezone: `Asia/Kolkata`).

---

## 3. Module Files

| File | Description |
|---|---|
| `isolation_forest.py` | Scikit-learn Isolation Forest wrapper with `fit()`, `predict()`, `decision_function()`, and telemetry |
| `baseline_generator.py` | Reproducible synthetic normal baseline generator (>= 250 samples per agent) |
| `feature_pipeline.py` | Feature extraction, standardization, and envelope deviation calculation |
| `model_evaluator.py` | Anomaly classifier translating decision scores into explainable risk points (0–30 pts) |
