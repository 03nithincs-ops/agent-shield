"""
AGENT SHIELD - Settings (Page 10)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import streamlit as st
from frontend.api_client import api_get, api_post, check_backend_health
from frontend.components.ui import get_global_css, page_header

st.markdown(get_global_css(), unsafe_allow_html=True)
page_header("Settings", "System configuration and status", "⚙️")

# ── System Status ──────────────────────────────────────────────────────────
st.markdown('<div class="section-header">🏥 System Health</div>', unsafe_allow_html=True)

backend_ok = check_backend_health()

if backend_ok:
    health = api_get("/health") or {}
    
    col1, col2, col3 = st.columns(3)
    with col1:
        db_status = health.get("database", "unknown")
        icon = "🟢" if db_status == "connected" else "🔴"
        st.metric(f"{icon} Database", db_status.title())
    with col2:
        ml_status = health.get("ml_model", "unknown")
        icon = "🟢" if ml_status == "loaded" else "🟡"
        st.metric(f"{icon} ML Model", ml_status.replace("_", " ").title())
    with col3:
        status = health.get("status", "unknown")
        icon = "🟢" if status == "healthy" else "🟡"
        st.metric(f"{icon} API Status", status.title())
    
    # Stats
    stats = health.get("stats", {})
    if stats:
        st.markdown("**Current Statistics:**")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Active Agents", stats.get("total_agents", 0))
        with col2:
            st.metric("Total Requests", stats.get("total_requests", 0))
        with col3:
            st.metric("Anomalies", stats.get("anomalies_detected", 0))
        with col4:
            st.metric("Critical Alerts", stats.get("critical_alerts", 0))
else:
    st.error("🔴 Backend is offline. Start the backend with: `uvicorn backend.main:app --reload`")

st.markdown("---")

# ── ML Model Management ──────────────────────────────────────────────────
st.markdown('<div class="section-header">🧠 ML Model Management</div>', unsafe_allow_html=True)

model_status = api_get("/anomaly/model-status") or {} if backend_ok else {}

col1, col2 = st.columns(2)
with col1:
    st.markdown(f"**Model Type:** Isolation Forest (Scikit-learn)")
    st.markdown(f"**Status:** {'✅ Loaded' if model_status.get('loaded') else '❌ Not Loaded'}")
    st.markdown(f"**Model File:** `{model_status.get('model_path', 'N/A')}`")
    st.markdown(f"**File Exists:** {'Yes' if model_status.get('model_exists_on_disk') else 'No'}")

with col2:
    if st.button("🔄 Retrain Isolation Forest", use_container_width=True):
        with st.spinner("Training model on synthetic data..."):
            result = api_post("/anomaly/train", {})
            if result and result.get("success"):
                st.success("✅ Model retrained successfully!")
                st.rerun()
    
    st.caption("""
    Training data: 2000 synthetic normal activity samples
    
    Parameters:
    - n_estimators: 200
    - contamination: 8% 
    - random_state: 42
    """)

st.markdown("---")

# ── About ──────────────────────────────────────────────────────────────────
st.markdown('<div class="section-header">ℹ️ About Agent Shield</div>', unsafe_allow_html=True)

st.markdown("""
### 🛡️ AGENT SHIELD
**Every Agent. Every Action. Under Control.**

A cybersecurity prototype for AI Agent Authorization Monitoring and Permission Enforcement.

**Domain:** AI in Cybersecurity and FinTech  
**Purpose:** Hackathon Demo — 24-hour prototype

---

**Core Components:**
- 🔐 Runtime Policy Engine — Backend authorization enforcement
- 🔍 Isolation Forest — ML anomaly detection (Scikit-learn)
- ⚖️ Risk Analyzer — Explainable risk scoring (0-100)
- 📋 Audit Logger — Immutable event trail in SQLite
- 🚨 Alert Manager — Automated security alerting
- 🧪 Testing Centre — Real automated security tests

**Technology Stack:**
- Frontend: Streamlit
- Backend: FastAPI (Python)
- Database: SQLite
- ML: Scikit-learn (Isolation Forest)
- Charts: Plotly

---

**⚠️ IMPORTANT DISCLAIMER:**
This is a demonstration prototype using **simulated AI agents** and **synthetic data only**.
No real external AI agents, real customer data, or real financial systems are connected.
All operations are simulated for demonstration purposes.

---

**Quick Start:**
```bash
# Backend (from agent_shield/ directory)
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend (from agent_shield/ directory)
streamlit run frontend/app.py
```

**Version:** 1.0.0  
**Build Date:** 2026-11-25
""")
