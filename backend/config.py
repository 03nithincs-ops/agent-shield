"""Configuration settings for AGENT SHIELD."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_DB_PATH = Path(os.environ.get("AGENT_SHIELD_DB_PATH", str(DATA_DIR / "agent_shield.db")))

# AVISHKAR'26 Hackathon Identity & Compliance Metadata
PROJECT_NAME = "AGENT SHIELD"
TAGLINE = "Secure AI Agents. Monitor Every Action. Protect Every Resource."
EVENT_NAME = "AVISHKAR'26 – 24-Hour Hackathon"
INSTITUTION = "Adichunchanagiri Institute of Technology, Chikkamagaluru"
PROBLEM_STATEMENT_ID = 9
PROBLEM_STATEMENT = "Problem Statement 9: AI Agent Authorization Monitoring and Permission Enforcement"
DOMAIN = "AI in Cybersecurity and FinTech"
TEAM_ID = "AV26-374ACC2CF2"
TEAM_NAME = "sonic"
TEAM_SIZE = 4

# Administrator API key for management operations (demo default for local hackathon prototype)
ADMIN_API_KEY = os.environ.get("AGENT_SHIELD_ADMIN_KEY", "admin-shield-local-key-2026")

# Behaviour Monitoring Thresholds (sliding window in seconds)
BEHAVIOUR_WINDOW_SECONDS = int(os.environ.get("AGENT_SHIELD_WINDOW_SECONDS", "60"))
MONITOR_REQUEST_THRESHOLD = int(os.environ.get("AGENT_SHIELD_MONITOR_REQ_THRESHOLD", "6"))
BLOCK_REQUEST_THRESHOLD = int(os.environ.get("AGENT_SHIELD_BLOCK_REQ_THRESHOLD", "12"))
MONITOR_UNIQUE_RECORDS_THRESHOLD = int(os.environ.get("AGENT_SHIELD_MONITOR_REC_THRESHOLD", "15"))
BLOCK_UNIQUE_RECORDS_THRESHOLD = int(os.environ.get("AGENT_SHIELD_BLOCK_REC_THRESHOLD", "35"))
FAILED_AUTHZ_ALERT_THRESHOLD = int(os.environ.get("AGENT_SHIELD_FAILED_AUTHZ_THRESHOLD", "3"))
REPEATED_PATTERN_THRESHOLD = int(os.environ.get("AGENT_SHIELD_REPEATED_THRESHOLD", "5"))

# Normal operating hours and timezone for trusted per-agent behaviour baselines
DEFAULT_TIMEZONE = os.environ.get("AGENT_SHIELD_TIMEZONE", "Asia/Kolkata")
DEFAULT_NORMAL_HOUR_START = int(os.environ.get("AGENT_SHIELD_NORMAL_HOUR_START", "8"))
DEFAULT_NORMAL_HOUR_END = int(os.environ.get("AGENT_SHIELD_NORMAL_HOUR_END", "20"))

# Payment / Sensitive operation thresholds
PAYMENT_APPROVAL_THRESHOLD = float(os.environ.get("AGENT_SHIELD_PAYMENT_APPROVAL_THRESHOLD", "5000.0"))
PAYMENT_MAX_AMOUNT = float(os.environ.get("AGENT_SHIELD_PAYMENT_MAX_AMOUNT", "100000.0"))

# Resource sensitivity weights (0-100 base score)
RESOURCE_SENSITIVITY = {
    "customers": 20,
    "loans": 40,
    "payments": 65,
    "employees": 70,
    "payroll": 90,
}

# Action sensitivity modifiers
ACTION_SENSITIVITY = {
    "read": 0,
    "update": 15,
    "execute": 25,
    "delete": 35,
}
