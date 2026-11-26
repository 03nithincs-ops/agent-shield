"""
AGENT SHIELD - Alerts & Monitoring (Page 8)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import streamlit as st
import pandas as pd
from frontend.api_client import api_get, api_patch, check_backend_health
from frontend.components.ui import get_global_css, page_header, badge, COLORS

st.markdown(get_global_css(), unsafe_allow_html=True)
page_header("Alerts & Monitoring", "Real-time security alerts and incident tracking", "🚨")

if not check_backend_health():
    st.error("🔴 Backend Offline.")
    st.stop()

# ── Filters ──────────────────────────────────────────────────────────────
col1, col2, col3 = st.columns([2, 2, 1])

with col1:
    severity_filter = st.selectbox("Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
with col2:
    ack_filter = st.radio("Show", ["Unacknowledged", "All", "Acknowledged"], horizontal=True)
with col3:
    if st.button("🔄 Refresh", use_container_width=True):
        st.rerun()

# Map filter
params = {"limit": 100}
if severity_filter != "All":
    params["severity"] = severity_filter

ack_bool = None
if ack_filter == "Unacknowledged":
    ack_bool = False
elif ack_filter == "Acknowledged":
    ack_bool = True

if ack_bool is not None:
    params["acknowledged"] = ack_bool

alerts = api_get("/alerts", params) or []

# ── Alert Stats ──────────────────────────────────────────────────────────
all_alerts = api_get("/alerts", {"limit": 500}) or []

col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    total_alerts = len(all_alerts)
    st.metric("Total Alerts", total_alerts)
with col2:
    critical = sum(1 for a in all_alerts if a.get("severity") == "CRITICAL")
    st.metric("🔴 Critical", critical)
with col3:
    high = sum(1 for a in all_alerts if a.get("severity") == "HIGH")
    st.metric("🟠 High", high)
with col4:
    medium = sum(1 for a in all_alerts if a.get("severity") == "MEDIUM")
    st.metric("🟡 Medium", medium)
with col5:
    unacked = sum(1 for a in all_alerts if not a.get("is_acknowledged"))
    st.metric("⚠️ Unacknowledged", unacked)

st.markdown("---")

# ── Alert Types Reference ──────────────────────────────────────────────────
with st.expander("ℹ️ Alert Types Reference", expanded=False):
    st.markdown("""
    | Alert Type | Severity | Trigger Condition |
    |------------|----------|-------------------|
    | `CRITICAL_RISK` | CRITICAL | Risk score ≥ 80 |
    | `PRIVILEGE_ESCALATION` | HIGH | Agent attempts action/resource beyond its role |
    | `REPEATED_UNAUTHORIZED` | HIGH | ≥ 5 denied requests in 10 minutes |
    | `ANOMALOUS_ACTIVITY` | MEDIUM | Isolation Forest detects anomaly |
    | `HIGH_FREQUENCY` | MEDIUM | > 20 requests per minute |
    
    *Alerts are deduplicated — the same alert type for an agent is not generated more than once every 5 minutes.*
    """)

# ── Alert List ──────────────────────────────────────────────────────────
st.markdown(f'<div class="section-header">🚨 Security Alerts ({len(alerts)} shown)</div>', unsafe_allow_html=True)

if alerts:
    icon_map = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    
    for alert in alerts:
        severity = alert.get("severity", "LOW")
        icon = icon_map.get(severity, "⚪")
        agent_name = alert.get("agent_name", "Unknown")
        alert_type = alert.get("alert_type", "")
        message = alert.get("message", "")
        ts = alert.get("timestamp", "")[:19].replace("T", " ")
        is_acked = alert.get("is_acknowledged", 0)
        alert_id = alert.get("alert_id", "")
        
        # Style based on severity
        border_color = {
            "CRITICAL": "#ff4b6e", "HIGH": "#ff9f43",
            "MEDIUM": "#ffd32a", "LOW": "#00d4aa"
        }.get(severity, "#64748b")
        
        opacity = "0.5" if is_acked else "1.0"
        
        with st.expander(
            f"{icon} [{severity}] {message[:80]}{'...' if len(message) > 80 else ''} — {ts}",
            expanded=(severity == "CRITICAL" and not is_acked)
        ):
            col_info, col_action = st.columns([3, 1])
            
            with col_info:
                st.markdown(f"**Agent:** {agent_name} (`{alert.get('agent_id', '')}`)")
                st.markdown(f"**Alert Type:** `{alert_type}`")
                st.markdown(f"**Message:** {message}")
                st.markdown(f"**Time:** {ts}")
                
                details = alert.get("details", {})
                if details and isinstance(details, dict):
                    st.markdown("**Details:**")
                    for k, v in details.items():
                        st.markdown(f"• {k.replace('_', ' ').title()}: {v}")
                
                st.markdown(f"**Status:** {'✅ Acknowledged' if is_acked else '⚠️ Active'}")
            
            with col_action:
                if not is_acked:
                    if st.button(f"✅ Acknowledge", key=f"ack_{alert_id}"):
                        result = api_patch(f"/alerts/{alert_id}/acknowledge")
                        if result:
                            st.success("Alert acknowledged!")
                            st.rerun()
                else:
                    st.success("Acknowledged")
else:
    if ack_filter == "Unacknowledged":
        st.success("✅ No active alerts! System is operating normally.")
    else:
        st.info("No alerts found with the current filters.")

# ── Acknowledge All ────────────────────────────────────────────────────────
if alerts and any(not a.get("is_acknowledged") for a in alerts):
    st.markdown("---")
    if st.button("✅ Acknowledge All Active Alerts", use_container_width=True):
        for alert in alerts:
            if not alert.get("is_acknowledged"):
                api_patch(f"/alerts/{alert['alert_id']}/acknowledge")
        st.success("All alerts acknowledged!")
        st.rerun()
