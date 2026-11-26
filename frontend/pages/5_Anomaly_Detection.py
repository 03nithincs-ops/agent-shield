"""
AGENT SHIELD - Anomaly Detection (Page 5)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from frontend.api_client import api_get, api_post, check_backend_health
from frontend.components.ui import get_global_css, page_header, badge, plotly_dark_layout, COLORS

st.markdown(get_global_css(), unsafe_allow_html=True)
page_header("Anomaly Detection", "Isolation Forest ML-based behavioural analysis", "🔍")

if not check_backend_health():
    st.error("🔴 Backend Offline.")
    st.stop()

# Model status
model_status = api_get("/anomaly/model-status") or {}

col_status, col_train = st.columns([3, 1])
with col_status:
    if model_status.get("loaded"):
        st.success(f"✅ Isolation Forest model loaded | Type: {model_status.get('model_type', 'N/A')}")
    else:
        st.warning("⚠️ Model not loaded. Click 'Train Model' to initialize.")
with col_train:
    if st.button("🔄 Train/Reload Model"):
        with st.spinner("Training Isolation Forest..."):
            result = api_post("/anomaly/train", {})
            if result and result.get("success"):
                st.success("✅ Model trained!")
                st.rerun()

st.markdown("---")

# ── Manual Activity Analysis ───────────────────────────────────────────────
st.markdown('<div class="section-header">🧪 Analyze Activity Data</div>', unsafe_allow_html=True)
st.markdown("""
> The **Isolation Forest** algorithm detects anomalous behaviour by learning 
> patterns from normal agent activity. Provide activity metrics below to classify 
> whether the behaviour is **NORMAL** or **ANOMALOUS**.
>
> ℹ️ Anomaly detection is **independent of authorization** — a permitted request 
> can still be anomalous, and anomaly detection does not block authorized access.
""")

agents = api_get("/agents/") or []
agent_map = {f"{a['agent_name']} ({a['agent_id']})": a['agent_id'] for a in agents}

col1, col2 = st.columns(2)

with col1:
    selected_agent = st.selectbox("Agent", list(agent_map.keys()) if agent_map else ["No agents"])
    agent_id = agent_map.get(selected_agent, "unknown")
    
    requests_per_minute = st.slider(
        "Requests per Minute",
        min_value=0.0, max_value=100.0, value=5.0, step=0.5,
        help="Average number of requests per minute from this agent"
    )
    resources_accessed = st.slider(
        "Resources Accessed",
        min_value=0, max_value=50, value=2,
        help="Number of distinct resource access attempts"
    )
    failed_attempts = st.slider(
        "Failed Authorization Attempts",
        min_value=0, max_value=50, value=0,
        help="Number of denied requests"
    )

with col2:
    access_frequency = st.slider(
        "Access Frequency Score",
        min_value=0.0, max_value=100.0, value=3.0, step=0.5,
        help="Relative frequency of access patterns"
    )
    unique_resources = st.slider(
        "Unique Resources Accessed",
        min_value=0, max_value=20, value=1,
        help="Number of distinct resources the agent tried to access"
    )
    off_hours_requests = st.slider(
        "Off-Hours Requests",
        min_value=0, max_value=50, value=0,
        help="Requests made outside normal business hours"
    )
    sensitive_resource_access = st.slider(
        "Sensitive Resource Access Attempts",
        min_value=0, max_value=20, value=0,
        help="Attempts to access payment, financial, or admin resources"
    )

# Quick scenario presets
st.markdown("**Quick Presets:**")
preset_cols = st.columns(4)
with preset_cols[0]:
    if st.button("🟢 Normal Activity"):
        st.session_state.update({
            "preset_rpm": 3.0, "preset_failed": 0, "preset_res": 2,
            "preset_freq": 2.0, "preset_unique": 1, "preset_off": 0, "preset_sens": 0
        })
        st.rerun()
with preset_cols[1]:
    if st.button("🟡 Elevated Activity"):
        st.session_state.update({
            "preset_rpm": 15.0, "preset_failed": 3, "preset_res": 8,
            "preset_freq": 15.0, "preset_unique": 4, "preset_off": 5, "preset_sens": 1
        })
        st.rerun()
with preset_cols[2]:
    if st.button("🔴 Suspicious Activity"):
        st.session_state.update({
            "preset_rpm": 60.0, "preset_failed": 20, "preset_res": 25,
            "preset_freq": 60.0, "preset_unique": 12, "preset_off": 20, "preset_sens": 5
        })
        st.rerun()
with preset_cols[3]:
    if st.button("⚫ Extreme Activity"):
        st.session_state.update({
            "preset_rpm": 100.0, "preset_failed": 50, "preset_res": 50,
            "preset_freq": 100.0, "preset_unique": 20, "preset_off": 50, "preset_sens": 15
        })
        st.rerun()

if st.button("🔍 Analyze Activity", type="primary", use_container_width=True):
    payload = {
        "agent_id": agent_id,
        "requests_per_minute": requests_per_minute,
        "resources_accessed": resources_accessed,
        "failed_attempts": failed_attempts,
        "access_frequency": access_frequency,
        "unique_resources": unique_resources,
        "off_hours_requests": off_hours_requests,
        "sensitive_resource_access": sensitive_resource_access
    }
    
    with st.spinner("Running Isolation Forest analysis..."):
        result = api_post("/anomaly/detect", payload)
    
    if result:
        classification = result.get("classification", "UNAVAILABLE")
        anomaly_score = result.get("anomaly_score", 0.0)
        
        st.markdown("---")
        st.markdown('<div class="section-header">📊 Analysis Results</div>', unsafe_allow_html=True)
        
        col_res, col_chart = st.columns([1, 2])
        
        with col_res:
            if classification == "ANOMALOUS":
                st.markdown(f"""
                <div style="background: #2d0a14; border: 2px solid #ff4b6e; border-radius: 12px; padding: 20px; text-align: center;">
                    <h1 style="color: #ff4b6e; margin: 0;">⚠️</h1>
                    <h2 style="color: #ff4b6e;">ANOMALOUS</h2>
                    <p style="color: #94a3b8;">Unusual activity pattern detected</p>
                </div>
                """, unsafe_allow_html=True)
            elif classification == "NORMAL":
                st.markdown(f"""
                <div style="background: #002e1f; border: 2px solid #00d4aa; border-radius: 12px; padding: 20px; text-align: center;">
                    <h1 style="color: #00d4aa; margin: 0;">✅</h1>
                    <h2 style="color: #00d4aa;">NORMAL</h2>
                    <p style="color: #94a3b8;">Activity within expected parameters</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.warning(f"Model status: {classification}")
            
            st.markdown(f"""
            **Isolation Forest Score:** `{anomaly_score:.4f}`
            
            > ℹ️ This score reflects the model's internal path length metric.  
            > It is **not a probability**. Lower values indicate more anomalous behaviour.
            """)
        
        with col_chart:
            # Radar chart of activity features
            features = result.get("features_used", {})
            categories = list(features.keys())
            values = list(features.values())
            
            # Normalize for radar chart
            max_vals = {
                "requests_per_minute": 100, "resources_accessed": 50,
                "failed_attempts": 50, "access_frequency": 100,
                "unique_resources": 20, "off_hours_requests": 50,
                "sensitive_resource_access": 20
            }
            normalized = [min(v / max_vals.get(k, 100), 1.0) for k, v in zip(categories, values)]
            
            fig = go.Figure(go.Scatterpolar(
                r=normalized + [normalized[0]],
                theta=[c.replace("_", " ").title() for c in categories] + [categories[0].replace("_", " ").title()],
                fill="toself",
                fillcolor=f"rgba(255,75,110,0.2)" if classification == "ANOMALOUS" else "rgba(0,212,170,0.2)",
                line=dict(color=COLORS["deny"] if classification == "ANOMALOUS" else COLORS["allow"], width=2),
                name="Activity Profile"
            ))
            
            fig.update_layout(
                polar=dict(
                    bgcolor="#1a2535",
                    radialaxis=dict(visible=True, range=[0, 1], gridcolor="#1e3a5f", tickcolor="#64748b"),
                    angularaxis=dict(gridcolor="#1e3a5f", tickcolor="#64748b")
                ),
                paper_bgcolor="#111827",
                font=dict(color="#e2e8f0"),
                height=350,
                margin=dict(l=30, r=30, t=30, b=30),
                title="Activity Feature Profile"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        st.markdown(f"**Explanation:** {result.get('explanation', 'N/A')}")
        
        st.info("""
        ℹ️ **Important:** Anomaly detection results are supplementary security signals. 
        They do not control access authorization. An anomalous but authorized request 
        still proceeds; an anomalous unauthorized request is still denied by the policy engine.
        """)

# ── Historical Anomaly Data ────────────────────────────────────────────────
st.markdown("---")
st.markdown('<div class="section-header">📈 Historical Anomaly Detections</div>', unsafe_allow_html=True)

logs = api_get("/audit-logs", {"limit": 200}) or {}
log_data = logs.get("logs", []) if isinstance(logs, dict) else []

if log_data:
    anomaly_logs = [l for l in log_data if l.get("anomaly_classification") in ("NORMAL", "ANOMALOUS")]
    
    if anomaly_logs:
        df = pd.DataFrame(anomaly_logs)[["timestamp", "agent_name", "resource", "action",
                                          "decision", "anomaly_classification", "anomaly_score"]]
        df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M")
        st.dataframe(df, use_container_width=True, height=300)
    else:
        st.info("No anomaly detection data yet.")
else:
    st.info("No data yet. Run simulations to generate anomaly detection data.")
