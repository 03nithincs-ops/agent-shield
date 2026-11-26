"""
AGENT SHIELD - Audit Logs (Page 7)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import streamlit as st
import pandas as pd
import requests
from frontend.api_client import api_get, check_backend_health
from frontend.components.ui import get_global_css, page_header, badge, COLORS

BASE_URL = "http://localhost:8000"

st.markdown(get_global_css(), unsafe_allow_html=True)
page_header("Audit Logs", "Complete audit trail of all agent requests and security events", "📋")

if not check_backend_health():
    st.error("🔴 Backend Offline.")
    st.stop()

# ── Filters ──────────────────────────────────────────────────────────────
st.markdown('<div class="section-header">🔍 Search & Filter</div>', unsafe_allow_html=True)

col1, col2, col3, col4, col5 = st.columns(5)

agents = api_get("/agents/") or []
agent_options = {"All Agents": None}
agent_options.update({f"{a['agent_name']}": a['agent_id'] for a in agents})

with col1:
    selected_agent_label = st.selectbox("Agent", list(agent_options.keys()))
    selected_agent_id = agent_options[selected_agent_label]

with col2:
    decision_filter = st.selectbox("Decision", ["All", "ALLOW", "DENY"])

with col3:
    risk_filter = st.selectbox("Risk Level", ["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"])

with col4:
    date_from = st.date_input("From Date", value=None)

with col5:
    limit = st.number_input("Limit", min_value=10, max_value=1000, value=100, step=10)

col_refresh, col_export = st.columns([1, 1])
with col_refresh:
    if st.button("🔄 Refresh Logs", use_container_width=True):
        st.rerun()
with col_export:
    # Export button
    export_params = {}
    if selected_agent_id:
        export_params["agent_id"] = selected_agent_id
    if decision_filter != "All":
        export_params["decision"] = decision_filter
    if risk_filter != "All":
        export_params["risk_level"] = risk_filter
    
    try:
        export_url = f"{BASE_URL}/audit-logs/export"
        st.markdown(f'<a href="{export_url}" target="_blank"><button style="width:100%; background: #1e3a5f; color: white; border: 1px solid #00b4d8; border-radius: 8px; padding: 8px; cursor: pointer;">📥 Export CSV</button></a>', unsafe_allow_html=True)
    except Exception:
        pass

# ── Fetch Logs ─────────────────────────────────────────────────────────────
params = {"limit": limit}
if selected_agent_id:
    params["agent_id"] = selected_agent_id
if decision_filter != "All":
    params["decision"] = decision_filter
if risk_filter != "All":
    params["risk_level"] = risk_filter
if date_from:
    params["date_from"] = date_from.isoformat()

logs_response = api_get("/audit-logs", params) or {}
log_data = logs_response.get("logs", []) if isinstance(logs_response, dict) else []
total = logs_response.get("total", 0) if isinstance(logs_response, dict) else 0

st.markdown(f"**Showing {len(log_data)} of {total} total events**")

# ── Stats Summary Row ──────────────────────────────────────────────────────
if log_data:
    allowed_count = sum(1 for l in log_data if l.get("decision") == "ALLOW")
    denied_count = sum(1 for l in log_data if l.get("decision") == "DENY")
    anomaly_count = sum(1 for l in log_data if l.get("anomaly_classification") == "ANOMALOUS")
    critical_count = sum(1 for l in log_data if l.get("risk_level") == "CRITICAL")
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Allowed", allowed_count)
    col2.metric("Denied", denied_count)
    col3.metric("Anomalies", anomaly_count)
    col4.metric("Critical Risk", critical_count)

st.markdown("---")

# ── Log Table ─────────────────────────────────────────────────────────────
if log_data:
    view_mode = st.radio("View Mode", ["Table", "Detailed Cards"], horizontal=True)
    
    if view_mode == "Table":
        df_cols = ["timestamp", "agent_name", "resource", "action",
                   "decision", "anomaly_classification", "risk_score", "risk_level"]
        df_display = pd.DataFrame(log_data)[df_cols] if log_data else pd.DataFrame()
        
        if not df_display.empty:
            df_display["timestamp"] = pd.to_datetime(df_display["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
            df_display.columns = ["Timestamp", "Agent", "Resource", "Action",
                                   "Decision", "Anomaly", "Risk Score", "Risk Level"]
        
        st.dataframe(df_display, use_container_width=True, height=500)
    
    else:
        # Detailed cards
        for log in log_data[:50]:  # Limit cards for performance
            decision = log.get("decision", "")
            risk_level = log.get("risk_level", "")
            ts = log.get("timestamp", "")[:19].replace("T", " ")
            agent = log.get("agent_name", "Unknown")
            resource = log.get("resource", "")
            action = log.get("action", "")
            
            border_color = "#00d4aa" if decision == "ALLOW" else "#ff4b6e"
            
            with st.expander(
                f"[{ts}] {agent} — {resource} ({action}) — {decision}",
                expanded=False
            ):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.markdown(f"**Event ID:** `{log.get('event_id', '')[:8]}...`")
                    st.markdown(f"**Agent:** {agent}")
                    st.markdown(f"**Agent ID:** `{log.get('agent_id', '')}`")
                    st.markdown(f"**Resource:** `{resource}`")
                    st.markdown(f"**Action:** `{action}`")
                
                with col2:
                    st.markdown(f"**Decision:** {badge(decision)}", unsafe_allow_html=True)
                    
                    if log.get("denial_reason"):
                        st.error(f"**Denial:** {log['denial_reason']}")
                    
                    anomaly = log.get("anomaly_classification", "N/A")
                    st.markdown(f"**Anomaly:** {badge(anomaly)}", unsafe_allow_html=True)
                    
                    if log.get("anomaly_score") is not None:
                        st.markdown(f"**Anomaly Score:** `{log['anomaly_score']:.4f}`")
                
                with col3:
                    if risk_level:
                        st.markdown(f"**Risk Level:** {badge(risk_level)}", unsafe_allow_html=True)
                    
                    if log.get("risk_score") is not None:
                        st.markdown(f"**Risk Score:** {log['risk_score']}/100")
                    
                    factors = log.get("risk_factors", [])
                    if isinstance(factors, str):
                        import json
                        try:
                            factors = json.loads(factors)
                        except Exception:
                            factors = []
                    
                    if factors:
                        st.markdown("**Risk Factors:**")
                        for f in factors:
                            st.markdown(f"• {f}")
                    
                    if log.get("suggested_action"):
                        st.info(f"💡 {log['suggested_action']}")
else:
    st.info("No audit logs found. Use the Request Simulator to generate events.")
