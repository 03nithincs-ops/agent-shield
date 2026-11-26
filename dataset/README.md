# AGENT SHIELD — Synthetic Financial Dataset

This folder contains the complete fictional synthetic dataset generated for **AVISHKAR'26 Problem Statement 9** (AI Agent Authorization Monitoring and Permission Enforcement).

> **Privacy & Compliance Guarantee:** All records (names, account numbers, amounts, tax withholding, credit scores) are 100% synthetically generated via deterministic pseudorandom generators (`seed=2026`). No actual personal or real banking data is used.

---

## Dataset Files

| File | Records | Description | Primary Fields |
|---|---|---|---|
| `customers.csv` | 100 | Customer profile data | `customer_id`, `full_name`, `email`, `phone`, `account_tier`, `credit_score`, `balance`, `city`, `status` |
| `loans.csv` | 50 | Synthetic retail & commercial loans | `loan_id`, `customer_id`, `loan_type`, `principal_amount`, `remaining_balance`, `interest_rate`, `status`, `risk_grade` |
| `payments.csv` | 200 | Simulated ACH, wire, and card transfers | `payment_id`, `customer_id`, `amount`, `currency`, `payment_type`, `recipient`, `status`, `initiated_by` |
| `employees.csv` | 30 | Corporate employee profiles | `employee_id`, `full_name`, `department`, `job_title`, `email`, `hire_date`, `status` |
| `payroll.csv` | 30 | Restricted employee compensation data | `payroll_id`, `employee_id`, `pay_period`, `base_salary`, `bonus`, `tax_withheld`, `net_pay`, `bank_account_masked` |
| `agents.csv` | 3+ | Registered simulated AI agent identities | `agent_id`, `name`, `role`, `description`, `system_instructions`, `available_tools`, `credential_prefix`, `status` |
| `permissions.csv` | 5+ | Persistent Permission Registry rules | `permission_id`, `agent_id`, `resource`, `action`, `effect`, `max_amount`, `requires_approval_above` |
| `behaviour_baselines.csv`| 3+ | Trusted per-agent normal baselines | `agent_id`, `normal_resources`, `normal_hours_start`, `normal_hours_end`, `typical_req_per_window_max`, `typical_unique_records_max`, `baseline_sample_count` |
| `schema.sql` | — | Complete SQLite DDL table definitions | All `CREATE TABLE` and index statements |
| `export_dataset.py` | — | Python export script | Exports SQLite database tables to CSV format |

---

## Schema Overview

- **customers**: `CUST-0001` through `CUST-0100` (Balances: $450 to $95,000; Credit scores: 580 to 845)
- **loans**: `LOAN-0001` through `LOAN-0050` (Principals: $5,000 to $250,000; Interest: 3.5% to 14.2%)
- **payments**: `PAY-00001` through `PAY-00200` (Amounts: $25 to $8,500; Types: ACH, wire, bill pay)
- **payroll**: `PR-0001` through `PR-0030` (Base salary: $5,500 to $16,500; Masked bank accounts)
