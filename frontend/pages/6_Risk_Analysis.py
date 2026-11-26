"""
AGENT SHIELD - Risk Analysis (Page 6)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from frontend.api_client import api_get, api_post, check_backend_health
from frontend.components.ui import get_global_css, page_header, badge, risk_gauge, plotly_dark_layout, COLORS

st.markdown(get_global_css(), unsafe_allow_html=True)
page_header("Risk Analysis", "Explainable risk scoring and security assessment", "⚖️")

if not check_backend_health():
    st.error("🔴 Backend Offline.")
    st.stop()

# ── Agent Risk Overview ──────────────────────────────────────────────────
st.markdown('<div class="section-header">📊 Agent Risk Overview</div>', unsafe_allow_html=True)

agents = api_get("/agents/") or []
agent_map = {f"{a['agent_name']} ({a['agent_id']})": a['agent_id'] for a in agents}

col1, col2 = st.columns([2, 3])

with col1:
    st.markdown("**Risk Scoring Formula:**")
    st.markdown("""
    | Factor | Points |
    |--------|--------|
    | Unauthorized access attempt | +35 |
    | Sensitive resource targeted | +20 |
    | Anomaly detection positive | +15 |
    | Repeated denials (last 1h) | +5 each (max +20) |
    | High request frequency | +10 |
    | Privilege escalation pattern | +25 |
    
    **Risk Levels:**
    """)
    
    for level, color, rng in [
        ("LOW (0-29)", "#00d4aa", "Safe — no immediate action needed"),
        ("MEDIUM (30-59)", "#ffd32a", "Monitor — review access patterns"),
        ("HIGH (60-79)", "#ff9f43", "Alert — investigate activity"),
        ("CRITICAL (80-100)", "#ff4b6e", "Immediate action required"),
    ]:
        st.markdown(f'<span style="color: {color}; font-weight: bold;">● {level}</span> — {rng}', unsafe_allow_html=True)

with col2:
    # Agent risk history chart
    if agent_map:
        selected_agent_label = st.selectbox("Select Agent for History", list(agent_map.keys()))
        selected_id = agent_map[selected_agent_label]
        
        risk_history = api_get(f"/risk/agent/{selected_id}") or []
        
        if risk_history:
            df_risk = pd.DataFrame(risk_history)
            df_risk["timestamp"] = pd.to_datetime(df_risk["timestamp"]).dt.strftime("%m-%d %H:%M")
            
            fig = go.Figure()
            
            color_map = {"LOW": COLORS["low"], "MEDIUM": COLORS["medium"],
                        "HIGH": COLORS["high"], "CRITICAL": COLORS["critical"]}
            
            for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                df_level = df_risk[df_risk["risk_level"] == level]
                if not df_level.empty:
                    fig.add_trace(go.Scatter(
                        x=df_level["timestamp"],
                        y=df_level["risk_score"],
                        mode="markers+lines",
                        name=level,
                        marker=dict(color=color_map[level], size=8),
                        line=dict(color=color_map[level])
                    ))
            
            # Risk threshold lines
            for y, label, color in [(30, "Medium", "#ffd32a"), (60, "High", "#ff9f43"), (80, "Critical", "#ff4b6e")]:
                fig.add_hline(y=y, line_dash="dash", line_color=color,
                            annotation_text=label, annotation_font_color=color)
            
            plotly_dark_layout(fig, f"Risk Score History — {selected_agent_label}", height=350)
            fig.update_yaxes(range=[0, 105])
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info(f"No risk history for {selected_agent_label} yet.")

# ── Risk Assessment Details ────────────────────────────────────────────────
st.markdown("---")
st.markdown('<div class="section-header">🔎 Recent Risk Events</div>', unsafe_allow_html=True)

logs = api_get("/audit-logs", {"limit": 50}) or {}
log_data = logs.get("logs", []) if isinstance(logs, dict) else []

if log_data:
    # Filter to events with risk scores
    risk_logs = [l for l in log_data if l.get("risk_score") is not None]
    
    if risk_logs:
        for log in risk_logs[:10]:
            risk_score = log.get("risk_score", 0)
            risk_level = log.get("risk_level", "LOW")
            agent_name = log.get("agent_name", "Unknown")
            resource = log.get("resource", "")
            action = log.get("action", "")
            decision = log.get("decision", "")
            ts = log.get("timestamp", "")[:19].replace("T", " ")
            
            color_map = {"LOW": "#00d4aa", "MEDIUM": "#ffd32a",
                        "HIGH": "#ff9f43", "CRITICAL": "#ff4b6e"}
            color = color_map.get(risk_level, "#64748b")
            
            with st.expander(
                f"[{risk_level}] {agent_name} — Score: {risk_score} | {ts}",
                expanded=risk_level in ("HIGH", "CRITICAL")
            ):
                col_gauge, col_details = st.columns([1, 2])
                
                with col_gauge:
                    st.plotly_chart(risk_gauge(risk_score, risk_level), use_container_width=True)
                
                with col_details:
                    st.markdown(f"**Agent:** {agent_name}")
                    st.markdown(f"**Resource:** `{resource}` | **Action:** `{action}`")
                    st.markdown(f"**Decision:** {badge(decision)}", unsafe_allow_html=True)
                    st.markdown(f"**Anomaly:** {badge(log.get('anomaly_classification', 'N/A'))}", unsafe_allow_html=True)
                    
                    factors = log.get("risk_factors", [])
                    if isinstance(factors, str):
                        import json
                        try:
                            factors = json.loads(factors)
                        except Exception:
                            factors = []
                    
                    if factors:
                        st.markdown("**Contributing Factors:**")
                        for f in factors:
                            st.markdown(f"• {f}")
    else:
        st.info("No risk assessments yet. Run simulations to generate risk data.")

# ── Risk Distribution Summary ──────────────────────────────────────────────
st.markdown("---")
st.markdown('<div class="section-header">📈 Risk Distribution Summary</div>', unsafe_allow_html=True)

risk_dist = api_get("/dashboard/risk-distribution") or []

if risk_dist:
    col1, col2 = st.columns(2)
    
    with col1:
        df = pd.DataFrame(risk_dist)
        risk_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        df["risk_level"] = pd.Categorical(df["risk_level"], categories=risk_order, ordered=True)
        df = df.sort_values("risk_level")
        
        fig = go.Figure(go.Bar(
            x=df["risk_level"],
            y=df["count"],
            marker_color=[COLORS.get(r.lower(), COLORS["accent"]) for r in df["risk_level"]],
            text=df["count"],
            textposition="outside",
            textfont=dict(color="#e2e8f0")
        ))
        plotly_dark_layout(fig, "Risk Level Distribution", height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        fig_donut = go.Figure(go.Pie(
            labels=df["risk_level"].tolist(),
            values=df["count"].tolist(),
            hole=0.4,
            marker=dict(colors=[COLORS.get(r.lower(), COLORS["accent"]) for r in df["risk_level"]])
        ))
        plotly_dark_layout(fig_donut, "Risk Level Proportion", height=300)
        st.plotly_chart(fig_donut, use_container_width=True)
else:
    st.info("No risk distribution data yet.")
