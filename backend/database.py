"""
AGENT SHIELD - Database Module
Manages SQLite database creation, connections, and initialization.
"""

import sqlite3
import os
import logging
from datetime import datetime, timezone
from contextlib import contextmanager

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "agent_shield.db")

def get_db_path():
    return DB_PATH

@contextmanager
def get_db_connection():
    """Context manager for database connections with error handling."""
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {e}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()


def init_database():
    """Initialize database schema and seed initial data."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Agents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                agent_name TEXT NOT NULL,
                agent_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CONSTRAINT chk_status CHECK (status IN ('ACTIVE', 'INACTIVE'))
            )
        """)
        
        # Permissions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS permissions (
                permission_id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                resource TEXT NOT NULL,
                action TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE,
                CONSTRAINT chk_action CHECK (action IN ('READ', 'WRITE', 'EXECUTE')),
                UNIQUE(agent_id, resource, action)
            )
        """)
        
        # Audit logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                resource TEXT NOT NULL,
                action TEXT NOT NULL,
                decision TEXT NOT NULL,
                denial_reason TEXT,
                anomaly_classification TEXT,
                anomaly_score REAL,
                risk_score INTEGER,
                risk_level TEXT,
                risk_factors TEXT,
                suggested_action TEXT,
                request_metadata TEXT,
                CONSTRAINT chk_decision CHECK (decision IN ('ALLOW', 'DENY'))
            )
        """)
        
        # Alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT,
                is_acknowledged INTEGER DEFAULT 0,
                CONSTRAINT chk_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
            )
        """)
        
        # Test results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS test_results (
                test_id TEXT PRIMARY KEY,
                test_name TEXT NOT NULL,
                test_scenario TEXT NOT NULL,
                test_input TEXT NOT NULL,
                expected_result TEXT NOT NULL,
                actual_result TEXT,
                status TEXT,
                error_details TEXT,
                execution_time_ms REAL,
                run_at TEXT NOT NULL,
                CONSTRAINT chk_status CHECK (status IN ('PASS', 'FAIL', 'ERROR', 'PENDING'))
            )
        """)
        
        conn.commit()
        logger.info("Database schema initialized.")
        
        # Seed initial agents
        _seed_initial_data(cursor, conn)


def _seed_initial_data(cursor, conn):
    """Insert initial sample agents if they don't exist."""
    now = datetime.now(timezone.utc).isoformat()
    
    initial_agents = [
        {
            "agent_id": "agent-001",
            "agent_name": "Customer Support Agent",
            "agent_type": "Support",
            "status": "ACTIVE",
            "description": "Handles customer support requests and reads customer data.",
            "resources": ["customer_files", "support_database"],
            "actions": ["READ"]
        },
        {
            "agent_id": "agent-002",
            "agent_name": "Payment Agent",
            "agent_type": "Financial",
            "status": "ACTIVE",
            "description": "Processes payment transactions and executes financial operations.",
            "resources": ["transaction_database", "payment_api"],
            "actions": ["READ", "EXECUTE"]
        },
        {
            "agent_id": "agent-003",
            "agent_name": "Analytics Agent",
            "agent_type": "Analytics",
            "status": "ACTIVE",
            "description": "Generates analytics reports and writes analysis data.",
            "resources": ["analytics_database", "reports"],
            "actions": ["READ", "WRITE"]
        }
    ]
    
    for agent in initial_agents:
        # Check if agent already exists
        existing = cursor.execute(
            "SELECT agent_id FROM agents WHERE agent_id = ?", (agent["agent_id"],)
        ).fetchone()
        
        if not existing:
            cursor.execute("""
                INSERT INTO agents (agent_id, agent_name, agent_type, status, description, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (agent["agent_id"], agent["agent_name"], agent["agent_type"],
                  agent["status"], agent["description"], now, now))
            
            for resource in agent["resources"]:
                for action in agent["actions"]:
                    cursor.execute("""
                        INSERT OR IGNORE INTO permissions (agent_id, resource, action, created_at)
                        VALUES (?, ?, ?, ?)
                    """, (agent["agent_id"], resource, action, now))
    
    conn.commit()
    logger.info("Initial agent data seeded.")

def get_all_agents():
    """Retrieve all agents with their permissions."""
    with get_db_connection() as conn:
        agents = conn.execute("""
            SELECT a.*, GROUP_CONCAT(DISTINCT p.resource) as resources,
                   GROUP_CONCAT(DISTINCT p.action) as actions
            FROM agents a
            LEFT JOIN permissions p ON a.agent_id = p.agent_id
            GROUP BY a.agent_id
        """).fetchall()
        return [dict(a) for a in agents]

def get_agent_by_id(agent_id: str):
    """Retrieve a single agent with permissions."""
    with get_db_connection() as conn:
        agent = conn.execute("""
            SELECT * FROM agents WHERE agent_id = ?
        """, (agent_id,)).fetchone()
        
        if not agent:
            return None
        
        agent_dict = dict(agent)
        
        permissions = conn.execute("""
            SELECT resource, action FROM permissions WHERE agent_id = ?
        """, (agent_id,)).fetchall()
        
        agent_dict["permissions"] = [dict(p) for p in permissions]
        agent_dict["resources"] = list(set(p["resource"] for p in permissions))
        agent_dict["actions"] = list(set(p["action"] for p in permissions))
        
        return agent_dict

def get_dashboard_stats():
    """Get aggregated stats for dashboard."""
    with get_db_connection() as conn:
        stats = {}
        
        stats["total_agents"] = conn.execute(
            "SELECT COUNT(*) FROM agents WHERE status='ACTIVE'"
        ).fetchone()[0]
        
        stats["total_requests"] = conn.execute(
            "SELECT COUNT(*) FROM audit_logs"
        ).fetchone()[0]
         
        stats["allowed_requests"] = conn.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE decision='ALLOW'"
        ).fetchone()[0]
        
        stats["denied_requests"] = conn.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE decision='DENY'"
        ).fetchone()[0]
        
        stats["anomalies_detected"] = conn.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE anomaly_classification='ANOMALOUS'"
        ).fetchone()[0]
        
        stats["critical_alerts"] = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL' AND is_acknowledged=0"
        ).fetchone()[0]
        
        return stats
