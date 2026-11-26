"""SQLite database management and schema initialization for AGENT SHIELD."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from backend.config import DEFAULT_DB_PATH

# Global re-entrant lock for write serialization on SQLite (protects audit hash chain & concurrent writes)
_DB_WRITE_LOCK = threading.RLock()


class DatabaseManager:
    """Manages SQLite connections, schema creation, and thread-safe transactions."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = _DB_WRITE_LOCK

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            isolation_level=None,  # explicit transaction control
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    @contextmanager
    def read_connection(self) -> Iterator[sqlite3.Connection]:
        conn = self.get_connection()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def write_transaction(self) -> Iterator[sqlite3.Connection]:
        """Thread-safe IMMEDIATE transaction to prevent concurrent-write race conditions."""
        with self._write_lock:
            conn = self.get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                yield conn
                if conn.in_transaction:
                    conn.execute("COMMIT;")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK;")
                raise
            finally:
                conn.close()

    def init_schema(self) -> None:
        """Create all required tables and indexes if they do not exist."""
        with self._write_lock:
            conn = self.get_connection()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS customers (
                        customer_id TEXT PRIMARY KEY,
                        full_name TEXT NOT NULL,
                        email TEXT NOT NULL,
                        phone TEXT NOT NULL,
                        account_tier TEXT NOT NULL,
                        credit_score INTEGER NOT NULL,
                        balance REAL NOT NULL,
                        city TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'active',
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS loans (
                        loan_id TEXT PRIMARY KEY,
                        customer_id TEXT NOT NULL,
                        loan_type TEXT NOT NULL,
                        principal_amount REAL NOT NULL,
                        remaining_balance REAL NOT NULL,
                        interest_rate REAL NOT NULL,
                        status TEXT NOT NULL,
                        risk_grade TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
                    );

                    CREATE TABLE IF NOT EXISTS payments (
                        payment_id TEXT PRIMARY KEY,
                        customer_id TEXT NOT NULL,
                        amount REAL NOT NULL,
                        currency TEXT NOT NULL DEFAULT 'USD',
                        payment_type TEXT NOT NULL,
                        recipient TEXT NOT NULL,
                        status TEXT NOT NULL,
                        initiated_by TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
                    );

                    CREATE TABLE IF NOT EXISTS employees (
                        employee_id TEXT PRIMARY KEY,
                        full_name TEXT NOT NULL,
                        department TEXT NOT NULL,
                        job_title TEXT NOT NULL,
                        email TEXT NOT NULL,
                        hire_date TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'active'
                    );

                    CREATE TABLE IF NOT EXISTS payroll (
                        payroll_id TEXT PRIMARY KEY,
                        employee_id TEXT NOT NULL,
                        pay_period TEXT NOT NULL,
                        base_salary REAL NOT NULL,
                        bonus REAL NOT NULL DEFAULT 0.0,
                        tax_withheld REAL NOT NULL,
                        net_pay REAL NOT NULL,
                        bank_account_masked TEXT NOT NULL,
                        status TEXT NOT NULL,
                        FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
                    );

                    CREATE TABLE IF NOT EXISTS agents (
                        agent_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        role TEXT NOT NULL,
                        description TEXT NOT NULL,
                        system_instructions TEXT NOT NULL,
                        available_tools TEXT NOT NULL,
                        credential_hash TEXT NOT NULL UNIQUE,
                        credential_prefix TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'active',
                        agent_type TEXT NOT NULL DEFAULT 'deterministic_python_simulated',
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS permissions (
                        permission_id TEXT PRIMARY KEY,
                        agent_id TEXT NOT NULL,
                        resource TEXT NOT NULL,
                        action TEXT NOT NULL,
                        effect TEXT NOT NULL DEFAULT 'ALLOW',
                        max_amount REAL,
                        requires_approval_above REAL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        UNIQUE(agent_id, resource, action),
                        FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS behaviour_baselines (
                        agent_id TEXT PRIMARY KEY,
                        normal_resources TEXT NOT NULL,
                        normal_hours_start INTEGER NOT NULL DEFAULT 8,
                        normal_hours_end INTEGER NOT NULL DEFAULT 20,
                        typical_req_per_window_max INTEGER NOT NULL DEFAULT 4,
                        typical_unique_records_max INTEGER NOT NULL DEFAULT 8,
                        baseline_sample_count INTEGER NOT NULL DEFAULT 250,
                        trusted_source TEXT NOT NULL DEFAULT 'synthetic_normal_baseline_v1',
                        model_status TEXT NOT NULL DEFAULT 'TRAINED (sklearn IsolationForest)',
                        model_type TEXT NOT NULL DEFAULT 'sklearn.ensemble.IsolationForest',
                        trained_at TEXT,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS activity_logs (
                        activity_id TEXT PRIMARY KEY,
                        agent_id TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        resource TEXT NOT NULL,
                        action TEXT NOT NULL,
                        record_ids TEXT NOT NULL,
                        record_count INTEGER NOT NULL DEFAULT 0,
                        decision TEXT NOT NULL,
                        authorized INTEGER NOT NULL DEFAULT 0,
                        sensitive_op INTEGER NOT NULL DEFAULT 0,
                        risk_score REAL NOT NULL DEFAULT 0.0,
                        timestamp TEXT NOT NULL,
                        details TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS audit_logs (
                        seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        timestamp TEXT NOT NULL,
                        authenticated_agent TEXT NOT NULL,
                        agent_name TEXT NOT NULL,
                        requested_resource TEXT NOT NULL,
                        requested_action TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        auth_result TEXT NOT NULL,
                        policy_result TEXT NOT NULL,
                        behaviour_result TEXT NOT NULL,
                        risk_score REAL NOT NULL,
                        final_decision TEXT NOT NULL,
                        execution_result TEXT NOT NULL,
                        details TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        current_hash TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS approval_requests (
                        approval_id TEXT PRIMARY KEY,
                        event_id TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        agent_name TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        resource TEXT NOT NULL,
                        action TEXT NOT NULL,
                        arguments TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        risk_score REAL NOT NULL,
                        status TEXT NOT NULL DEFAULT 'PENDING',
                        requested_at TEXT NOT NULL,
                        reviewed_by TEXT,
                        reviewed_at TEXT,
                        review_notes TEXT,
                        execution_result TEXT,
                        FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                    );

                    CREATE TABLE IF NOT EXISTS security_alerts (
                        alert_id TEXT PRIMARY KEY,
                        event_id TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        agent_name TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        category TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        risk_score REAL NOT NULL,
                        title TEXT NOT NULL,
                        reasons TEXT NOT NULL,
                        acknowledged INTEGER NOT NULL DEFAULT 0,
                        created_at TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_activity_agent_ts ON activity_logs(agent_id, timestamp);
                    CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_logs(authenticated_agent);
                    CREATE INDEX IF NOT EXISTS idx_alerts_ts ON security_alerts(created_at);
                    CREATE INDEX IF NOT EXISTS idx_approvals_status ON approval_requests(status);
                    """
                )
                for col_stmt in (
                    "ALTER TABLE behaviour_baselines ADD COLUMN model_status TEXT NOT NULL DEFAULT 'TRAINED (sklearn IsolationForest)'",
                    "ALTER TABLE behaviour_baselines ADD COLUMN model_type TEXT NOT NULL DEFAULT 'sklearn.ensemble.IsolationForest'",
                    "ALTER TABLE behaviour_baselines ADD COLUMN trained_at TEXT",
                ):
                    try:
                        conn.execute(col_stmt)
                    except Exception:
                        pass
            finally:
                conn.close()
