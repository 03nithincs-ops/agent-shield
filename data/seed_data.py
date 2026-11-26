"""Synthetic Financial Database Initializer and Seeder for AGENT SHIELD.

Generates strictly fictional, reproducible data:
- 100 synthetic customers
- 50 synthetic loans
- 200 synthetic payments
- 30 synthetic employees & 30 payroll records
- 3 initial deterministic simulated agents (Support Agent, Payment Agent, Loan Agent)
  with least-privilege permissions and trusted per-agent normal-behaviour baselines.

No real personal or banking data is used.
"""
from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.manager import AgentManager
from agents.runtime import DEMO_AGENT_CREDENTIALS
from backend.database import DatabaseManager

FIRST_NAMES = [
    "Aarav", "Maya", "Liam", "Sophia", "Noah", "Priya", "Ethan", "Zara", "Lucas", "Ananya",
    "Mateo", "Chloe", "Oliver", "Nadia", "Daniel", "Elena", "Rohan", "Hannah", "Caleb", "Amara",
]
LAST_NAMES = [
    "Patel", "Chen", "Miller", "Garcia", "Nair", "Brooks", "Kim", "Rivera", "Singh", "Foster",
    "Alvarez", "Bennett", "Sharma", "Hayes", "Morales", "Reed", "Kulkarni", "Price", "Nguyen", "Ward",
]
CITIES = [
    "Austin", "Seattle", "Chicago", "Boston", "Denver", "Atlanta", "San Diego", "Portland", "Raleigh", "Minneapolis",
]
DEPARTMENTS = ["Engineering", "Finance", "Risk & Compliance", "Customer Support", "Operations", "Security"]
JOB_TITLES = [
    "Software Engineer", "Financial Analyst", "Compliance Officer",
    "Support Specialist", "Operations Lead", "Security Engineer",
]
RECIPIENTS = [
    "Northstar Utilities Co.", "Meridian Cloud Services", "Summit Logistics LLC",
    "Harborview Health Group", "Redwood Office Supply", "BluePeak Telecom",
]


def seed_database(db: DatabaseManager, force_reseed: bool = False) -> Dict[str, int]:
    """Initialize schema and populate synthetic financial tables + 3 default agents & baselines."""
    db.init_schema()
    rng = random.Random(2026)

    with db.read_connection() as conn:
        existing_customers = conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]

    if existing_customers > 0 and not force_reseed:
        with db.read_connection() as conn:
            return {
                "customers": conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0],
                "loans": conn.execute("SELECT COUNT(*) FROM loans").fetchone()[0],
                "payments": conn.execute("SELECT COUNT(*) FROM payments").fetchone()[0],
                "employees": conn.execute("SELECT COUNT(*) FROM employees").fetchone()[0],
                "payroll": conn.execute("SELECT COUNT(*) FROM payroll").fetchone()[0],
                "agents": conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0],
            }

    now = datetime.now(timezone.utc)

    with db.write_transaction() as conn:
        if force_reseed:
            for tbl in (
                "security_alerts",
                "approval_requests",
                "audit_logs",
                "activity_logs",
                "behaviour_baselines",
                "permissions",
                "agents",
                "payroll",
                "employees",
                "payments",
                "loans",
                "customers",
            ):
                conn.execute(f"DELETE FROM {tbl}")

        # 1. Generate 100 synthetic customers
        tiers = ["Standard", "Silver", "Gold", "Platinum"]
        customers = []
        for i in range(1, 101):
            cid = f"CUST-{i:04d}"
            fn = FIRST_NAMES[(i * 3) % len(FIRST_NAMES)]
            ln = LAST_NAMES[(i * 7) % len(LAST_NAMES)]
            full_name = f"{fn} {ln}"
            email = f"{fn.lower()}.{ln.lower()}.{i}@synthetic-fin.example"
            phone = f"+1-555-{100 + (i % 899):03d}-{1000 + (i * 37) % 8999:04d}"
            tier = rng.choice(tiers)
            credit_score = rng.randint(580, 845)
            balance = round(rng.uniform(450.0, 95000.0), 2)
            city = rng.choice(CITIES)
            created_at = (now - timedelta(days=rng.randint(30, 900))).isoformat()
            customers.append((cid, full_name, email, phone, tier, credit_score, balance, city, "active", created_at))

        conn.executemany(
            """
            INSERT INTO customers (
                customer_id, full_name, email, phone, account_tier,
                credit_score, balance, city, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            customers,
        )

        # 2. Generate 50 synthetic loans
        loan_types = ["Mortgage", "Auto", "Personal", "Small Business", "Education"]
        loan_statuses = ["active", "active", "active", "under_review", "delinquent", "closed"]
        risk_grades = ["A", "B", "C", "D"]
        loans = []
        for i in range(1, 51):
            lid = f"LOAN-{i:04d}"
            cid = f"CUST-{rng.randint(1, 100):04d}"
            ltype = rng.choice(loan_types)
            principal = round(rng.uniform(5000.0, 250000.0), 2)
            remaining = round(principal * rng.uniform(0.1, 0.95), 2)
            rate = round(rng.uniform(3.5, 14.2), 2)
            status = rng.choice(loan_statuses)
            grade = rng.choice(risk_grades)
            updated_at = (now - timedelta(days=rng.randint(1, 120))).isoformat()
            loans.append((lid, cid, ltype, principal, remaining, rate, status, grade, updated_at))

        conn.executemany(
            """
            INSERT INTO loans (
                loan_id, customer_id, loan_type, principal_amount,
                remaining_balance, interest_rate, status, risk_grade, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            loans,
        )

        # 3. Generate 200 synthetic payments
        pay_types = ["ach_simulation", "card_settlement", "bill_pay", "wire_simulation"]
        pay_statuses = ["settled", "settled", "settled", "pending", "reversed"]
        payments = []
        for i in range(1, 201):
            pid = f"PAY-{i:05d}"
            cid = f"CUST-{rng.randint(1, 100):04d}"
            amount = round(rng.uniform(25.0, 8500.0), 2)
            ptype = rng.choice(pay_types)
            recipient = rng.choice(RECIPIENTS)
            status = rng.choice(pay_statuses)
            created_at = (now - timedelta(days=rng.randint(0, 180), hours=rng.randint(0, 23))).isoformat()
            payments.append((pid, cid, amount, "USD", ptype, recipient, status, "seed_system", created_at))

        conn.executemany(
            """
            INSERT INTO payments (
                payment_id, customer_id, amount, currency,
                payment_type, recipient, status, initiated_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            payments,
        )

        # 4. Generate 30 synthetic employees & 30 payroll records
        employees = []
        payrolls = []
        for i in range(1, 31):
            eid = f"EMP-{i:03d}"
            fn = FIRST_NAMES[(i * 5) % len(FIRST_NAMES)]
            ln = LAST_NAMES[(i * 11) % len(LAST_NAMES)]
            full_name = f"{fn} {ln}"
            dept = DEPARTMENTS[i % len(DEPARTMENTS)]
            title = JOB_TITLES[i % len(JOB_TITLES)]
            email = f"{fn.lower()}.{ln.lower()}.{i}@corp-synth.example"
            hire_date = (now - timedelta(days=rng.randint(120, 1800))).date().isoformat()
            employees.append((eid, full_name, dept, title, email, hire_date, "active"))

            pr_id = f"PR-{i:04d}"
            base = round(rng.uniform(5500.0, 16500.0), 2)
            bonus = round(rng.choice([0.0, 0.0, 500.0, 1200.0, 2500.0]), 2)
            tax = round((base + bonus) * 0.24, 2)
            net = round(base + bonus - tax, 2)
            masked_acct = f"****-****-{1000 + i * 29:04d}"
            payrolls.append((pr_id, eid, "2026-11", base, bonus, tax, net, masked_acct, "disbursed"))

        conn.executemany(
            """
            INSERT INTO employees (employee_id, full_name, department, job_title, email, hire_date, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            employees,
        )
        conn.executemany(
            """
            INSERT INTO payroll (
                payroll_id, employee_id, pay_period, base_salary,
                bonus, tax_withheld, net_pay, bank_account_masked, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            payrolls,
        )

    # 5. Seed the 3 initial deterministic simulated agents + least-privilege permissions + trusted baselines
    mgr = AgentManager(db)
    mgr.create_agent(
        agent_id="agent-support-01",
        name="Support Agent",
        role="Customer Support",
        description="Deterministic Python-managed agent authorized solely to read synthetic customer records.",
        system_instructions="Read customer profiles to answer support inquiries. Never request payroll or payment execution.",
        available_tools=["read_customer_records"],
        initial_permissions=[
            {"resource": "customers", "action": "read", "effect": "ALLOW"},
        ],
        fixed_credential=DEMO_AGENT_CREDENTIALS["agent-support-01"],
        normal_hours_start=8,
        normal_hours_end=20,
    )
    mgr.create_agent(
        agent_id="agent-payment-01",
        name="Payment Agent",
        role="Payments Operations",
        description="Deterministic Python-managed agent authorized to read payments and request simulated payments.",
        system_instructions="Review payment history and submit simulated payment requests. High-value transfers require admin approval.",
        available_tools=["read_payment_records", "request_simulated_payment"],
        initial_permissions=[
            {"resource": "payments", "action": "read", "effect": "ALLOW"},
            {
                "resource": "payments",
                "action": "execute",
                "effect": "ALLOW",
                "max_amount": 100000.0,
                "requires_approval_above": 5000.0,
            },
        ],
        fixed_credential=DEMO_AGENT_CREDENTIALS["agent-payment-01"],
        normal_hours_start=8,
        normal_hours_end=20,
    )
    mgr.create_agent(
        agent_id="agent-loan-01",
        name="Loan Agent",
        role="Loan Servicing",
        description="Deterministic Python-managed agent authorized to read and update synthetic loan records.",
        system_instructions="Inspect loan accounts and update loan review status or risk grades within policy.",
        available_tools=["read_loan_records", "update_loan_record"],
        initial_permissions=[
            {"resource": "loans", "action": "read", "effect": "ALLOW"},
            {"resource": "loans", "action": "update", "effect": "ALLOW"},
        ],
        fixed_credential=DEMO_AGENT_CREDENTIALS["agent-loan-01"],
        normal_hours_start=8,
        normal_hours_end=20,
    )

    return {
        "customers": 100,
        "loans": 50,
        "payments": 200,
        "employees": 30,
        "payroll": 30,
        "agents": 3,
    }


if __name__ == "__main__":
    db_mgr = DatabaseManager()
    counts = seed_database(db_mgr, force_reseed=True)
    print("AGENT SHIELD synthetic database initialized:", counts)
