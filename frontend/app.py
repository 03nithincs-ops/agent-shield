"""
AGENT SHIELD - Main Streamlit Application Entry Point
"""
import sys
import os

# Ensure paths are correct
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import streamlit as st

# Page configuration - MUST be first Streamlit call
st.set_page_config(
    page_title="Agent Shield — Every Agent. Every Action. Under Control.",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

from frontend.components.ui import get_global_css
from frontend.api_client import check_backend_health as check_health

st.markdown(get_global_css(), unsafe_allow_html=True)

# ── Sidebar ────────────────────────────────────────────────────────────────
with st.sidebar:
    # Logo / Brand
    st.markdown("""
    <div class="sidebar-logo">
        <div style="font-size: 2.5rem;">🛡️</div>
        <div style="font-size: 1.3rem; font-weight: 700; color: #00b4d8; letter-spacing: 1px;">AGENT SHIELD</div>
        <div style="font-size: 0.7rem; color: #64748b; margin-top: 4px;">Every Agent. Every Action. Under Control.</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Backend status indicator
    backend_ok = check_health()
    if backend_ok:
        st.markdown('<div style="text-align:center; padding: 4px; background: #002e1f; border-radius: 6px; color: #00d4aa; font-size: 0.8rem; margin-bottom: 16px;">🟢 Backend Connected</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div style="text-align:center; padding: 4px; background: #2d0a14; border-radius: 6px; color: #ff4b6e; font-size: 0.8rem; margin-bottom: 16px;">🔴 Backend Offline</div>', unsafe_allow_html=True)
    
    st.markdown("""
    <div style="color: #64748b; font-size: 0.75rem; margin-top: 20px; border-top: 1px solid #1e3a5f; padding-top: 16px;">
        <strong style="color: #94a3b8;">Navigate:</strong><br>
        Use the pages listed above to access different modules.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div style="color: #64748b; font-size: 0.75rem; margin-top: 16px;">
        <strong style="color: #94a3b8;">Quick Start:</strong><br>
        1. 📋 Check Security Overview<br>
        2. 🤖 Register/View Agents<br>
        3. 🧪 Run Request Simulator<br>
        4. 🔬 Check Testing Centre<br>
        5. 🚨 Review Alerts
    </div>
    """, unsafe_allow_html=True)

# ── Home Page ──────────────────────────────────────────────────────────────
st.markdown("""
<div style="text-align: center; padding: 40px 0 20px 0;">
    <div style="font-size: 4rem;">🛡️</div>
    <h1 style="font-size: 3rem; font-weight: 800; background: linear-gradient(135deg, #00b4d8, #00d4aa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; margin: 0;">
        AGENT SHIELD
    </h1>
    <p style="color: #64748b; font-size: 1.1rem; margin-top: 8px;">
        Every Agent. Every Action. Under Control.
    </p>
</div>
""", unsafe_allow_html=True)

# Backend status check
if not backend_ok:
    st.error("""
    ⚠️ **Backend is offline!**
    
    Start the FastAPI backend before using Agent Shield:
    
    ```bash
    # From the agent_shield/ directory:
    uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
    ```
    """)

# Feature overview
st.markdown('<div style="text-align: center; color: #64748b; margin-bottom: 24px;">← Use the navigation sidebar to access all features</div>', unsafe_allow_html=True)

col1, col2, col3 = st.columns(3)

features = [
    ("🔐", "Agent Permission Registry", "Register, configure, and manage AI agents with granular resource and action permissions."),
    ("⚡", "Runtime Policy Engine", "Backend authorization enforcement — every request validated before execution."),
    ("🔍", "Isolation Forest Anomaly Detection", "ML-powered detection of unusual agent behaviour using Scikit-learn."),
    ("⚖️", "Explainable Risk Scoring", "Transparent 0-100 risk scores with contributing factors and suggested actions."),
    ("📋", "Comprehensive Audit Logs", "Every event logged with full context — searchable, filterable, exportable."),
    ("🚨", "Live Dashboard & Alerts", "Real-time metrics, charts, and automated security alerting."),
    ("💬", "Local LLM Agent Chat", "Ollama (qwen2.5:3b) tool-calling agent with strict Runtime Policy Engine gating."),
]

for i, (icon, title, desc) in enumerate(features):
    col = [col1, col2, col3][i % 3]
    with col:
        st.markdown(f"""
        <div style="background: #111827; border: 1px solid #1e3a5f; border-radius: 12px; 
                    padding: 20px; margin-bottom: 16px; height: 160px;">
            <div style="font-size: 2rem; margin-bottom: 8px;">{icon}</div>
            <div style="font-weight: 600; color: #00b4d8; margin-bottom: 8px; font-size: 0.95rem;">{title}</div>
            <div style="color: #64748b; font-size: 0.85rem; line-height: 1.4;">{desc}</div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("---")

# Demo workflow
st.markdown('<div style="color: #00b4d8; font-size: 1.1rem; font-weight: 600; margin-bottom: 12px;">🎯 Hackathon Demo Workflow</div>', unsafe_allow_html=True)

demo_steps = [
    "**1. Security Overview** — Review live dashboard metrics and system status",
    "**2. Agent Management** — Explore pre-configured agents (Customer Support, Payment, Analytics)",
    "**3. Permission Registry** — View the permission matrix and access control rules",
    "**4. AI Agent Chat** — Chat with local LLM (Ollama qwen2.5:3b) with tool calling and runtime policy gating",
    "**5. Request Simulator** → Run Scenario A (Authorized), B (Unauthorized), C (High-Frequency), D (Unknown Agent), E (Privilege Escalation)",
    "**6. Anomaly Detection** — Analyze activity patterns with Isolation Forest",
    "**7. Risk Analysis** — View risk scores and contributing factors",
    "**8. Audit Logs** — Browse the complete security event trail (including AI agent tool calls)",
    "**9. Alerts** — Review auto-generated security alerts",
    "**10. Security Testing** — Run all automated test cases and view results",
]

for step in demo_steps:
    st.markdown(f"→ {step}")

st.markdown("---")
st.caption("⚠️ Agent Shield is a demonstration prototype using simulated agents and synthetic data only. No real external systems are connected.")
