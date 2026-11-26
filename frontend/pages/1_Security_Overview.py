"""
AGENT SHIELD - Security Overview Dashboard (Page 1)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from frontend.api_client import api_get, check_backend_health
from frontend.components.ui import (
    get_global_css, page_header, metric_card, plotly_dark_layout, badge, COLORS
)

st.markdown(get_global_css(), unsafe_allow_html=True)
page_header("Security Overview", "Real-time AI Agent Activity Monitoring", "🛡️")

# Backend health check
if not check_backend_health():
    st.error("🔴 **Backend Offline** — Start the FastAPI backend: `uvicorn backend.main:app --reload`")
    st.stop()

# Auto-refresh option
col_refresh, col_auto = st.columns([3, 1])
with col_refresh:
    if st.button("🔄 Refresh Dashboard", use_container_width=True):
        st.rerun()
with col_auto:
    auto_refresh = st.checkbox("Auto (30s)", value=False)

if auto_refresh:
    import time
    st.empty()

# ── Key Metrics ────────────────────────────────────────────────────────────
stats = api_get("/dashboard/stats") or {}

col1, col2, col3, col4, col5, col6 = st.columns(6)
with col1:
    metric_card(stats.get("total_agents", 0), "Active Agents", COLORS["accent"], "🤖")
with col2:
    metric_card(stats.get("total_requests", 0), "Total Requests", COLORS["accent"], "📡")
with col3:
    metric_card(stats.get("allowed_requests", 0), "Allowed", COLORS["allow"], "✅")
with col4:
    metric_card(stats.get("denied_requests", 0), "Denied", COLORS["deny"], "🚫")
with col5:
    metric_card(stats.get("anomalies_detected", 0), "Anomalies", COLORS["high"], "⚠️")
with col6:
    metric_card(stats.get("critical_alerts", 0), "Critical Alerts", COLORS["critical"], "🔴")

st.markdown("---")

# ── Charts ─────────────────────────────────────────────────────────────────
col_left, col_right = st.columns(2)

with col_left:
    st.markdown('<div class="section-header">📈 Request Activity (Last 24h)</div>', unsafe_allow_html=True)
    activity = api_get("/dashboard/activity-chart") or []
    
    if activity:
        df_act = pd.DataFrame(activity)
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df_act["hour"], y=df_act["allowed"],
            name="Allowed", fill="tozeroy",
            line=dict(color=COLORS["allow"], width=2),
            fillcolor="rgba(0,212,170,0.15)"
        ))
        fig.add_trace(go.Scatter(
            x=df_act["hour"], y=df_act["denied"],
            name="Denied", fill="tozeroy",
            line=dict(color=COLORS["deny"], width=2),
            fillcolor="rgba(255,75,110,0.15)"
        ))
        plotly_dark_layout(fig, height=300)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No activity data yet. Run some simulations to see activity.")
        # Empty chart placeholder
        fig = go.Figure()
        fig.add_annotation(text="No data yet — Run simulations first",
                          xref="paper", yref="paper", x=0.5, y=0.5,
                          font=dict(color="#64748b", size=14), showarrow=False)
        plotly_dark_layout(fig, height=300)
        st.plotly_chart(fig, use_container_width=True)

with col_right:
    st.markdown('<div class="section-header">🎯 Allowed vs Denied</div>', unsafe_allow_html=True)
    
    allowed = stats.get("allowed_requests", 0)
    denied = stats.get("denied_requests", 0)
    
    if allowed + denied > 0:
        fig_pie = go.Figure(go.Pie(
            labels=["Allowed", "Denied"],
            values=[allowed, denied],
            hole=0.5,
            marker=dict(colors=[COLORS["allow"], COLORS["deny"]]),
            textinfo="label+percent",
            textfont=dict(color="#e2e8f0")
        ))
        plotly_dark_layout(fig_pie, height=300)
        st.plotly_chart(fig_pie, use_container_width=True)
    else:
        st.info("No request data yet.")

# Second row of charts
col_risk, col_agent = st.columns(2)

with col_risk:
    st.markdown('<div class="section-header">📊 Risk Distribution</div>', unsafe_allow_html=True)
    risk_dist = api_get("/dashboard/risk-distribution") or []
    
    if risk_dist:
        df_risk = pd.DataFrame(risk_dist)
        risk_colors = {
            "LOW": COLORS["low"], "MEDIUM": COLORS["medium"],
            "HIGH": COLORS["high"], "CRITICAL": COLORS["critical"]
        }
        fig_risk = go.Figure(go.Bar(
            x=df_risk["risk_level"],
            y=df_risk["count"],
            marker_color=[risk_colors.get(r, COLORS["accent"]) for r in df_risk["risk_level"]],
            text=df_risk["count"],
            textposition="outside",
            textfont=dict(color="#e2e8f0")
        ))
        plotly_dark_layout(fig_risk, height=300)
        st.plotly_chart(fig_risk, use_container_width=True)
    else:
        st.info("No risk data yet.")

with col_agent:
    st.markdown('<div class="section-header">🤖 Agent Activity</div>', unsafe_allow_html=True)
    agent_act = api_get("/dashboard/agent-activity") or []
    
    if agent_act:
        df_agent = pd.DataFrame(agent_act)
        fig_agent = go.Figure()
        fig_agent.add_trace(go.Bar(
            name="Allowed", x=df_agent["agent_name"], y=df_agent["allowed"],
            marker_color=COLORS["allow"]
        ))
        fig_agent.add_trace(go.Bar(
            name="Denied", x=df_agent["agent_name"], y=df_agent["denied"],
            marker_color=COLORS["deny"]
        ))
        fig_agent.update_layout(barmode="stack")
        plotly_dark_layout(fig_agent, height=300)
        st.plotly_chart(fig_agent, use_container_width=True)
    else:
        st.info("No agent activity data yet.")

# ── Recent Events ──────────────────────────────────────────────────────────
st.markdown('<div class="section-header">🕐 Recent Security Events</div>', unsafe_allow_html=True)
recent = api_get("/dashboard/recent-events", {"limit": 10}) or []

if recent:
    for event in recent:
        decision = event.get("decision", "")
        risk_level = event.get("risk_level", "")
        agent_name = event.get("agent_name", "Unknown")
        resource = event.get("resource", "")
        action = event.get("action", "")
        ts = event.get("timestamp", "")[:19].replace("T", " ") if event.get("timestamp") else ""
        
        col_ts, col_agent, col_resource, col_decision, col_risk = st.columns([2, 2, 2, 1, 1])
        with col_ts:
            st.caption(ts)
        with col_agent:
            st.caption(f"🤖 {agent_name}")
        with col_resource:
            st.caption(f"📁 {resource} ({action})")
        with col_decision:
            st.markdown(badge(decision), unsafe_allow_html=True)
        with col_risk:
            if risk_level:
                st.markdown(badge(risk_level), unsafe_allow_html=True)
    
    st.markdown("---")
else:
    st.info("No events recorded yet. Use the Request Simulator to generate activity.")

# ── Active Alerts ──────────────────────────────────────────────────────────
st.markdown('<div class="section-header">🚨 Active Security Alerts</div>', unsafe_allow_html=True)
alerts = api_get("/alerts", {"acknowledged": False, "limit": 5}) or []

if alerts:
    for alert in alerts:
        severity = alert.get("severity", "")
        color_map = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        icon = color_map.get(severity, "⚪")
        ts = alert.get("timestamp", "")[:19].replace("T", " ")
        
        st.markdown(f"""
        <div class="alert-banner">
            <strong>{icon} [{severity}]</strong> {alert.get("message", "")}
            <span style="color: #64748b; font-size: 0.8rem; float: right;">{ts}</span>
        </div>
        """, unsafe_allow_html=True)
else:
    st.success("✅ No active alerts. System is operating normally.")

# Auto-refresh using time
if auto_refresh:
    import time
    time.sleep(30)
    st.rerun()
