"""
AGENT SHIELD - Request Simulator (Page 4)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import streamlit as st
import time
import pandas as pd
from frontend.api_client import api_get, api_post, check_backend_health
from frontend.components.ui import (
    get_global_css, page_header, decision_banner, badge, risk_gauge, COLORS
)

st.markdown(get_global_css(), unsafe_allow_html=True)
page_header("Request Simulator", "Test AI agent access scenarios through the backend", "🧪")

if not check_backend_health():
    st.error("🔴 Backend Offline — Start the FastAPI backend.")
    st.stop()

# Predefined scenarios
SCENARIOS = {
    "A: Authorized Access": {
        "agent_id": "agent-001",
        "resource": "customer_files",
        "action": "READ",
        "description": "Customer Support Agent requests READ access to customer_files. Expected: ALLOW"
    },
    "B: Unauthorized Access": {
        "agent_id": "agent-001",
        "resource": "payment_api",
        "action": "EXECUTE",
        "description": "Customer Support Agent requests EXECUTE on payment_api. Expected: DENY"
    },
    "C: High-Frequency Activity": {
        "agent_id": "agent-003",
        "resource": "analytics_database",
        "action": "READ",
        "description": "Analytics Agent sends multiple rapid requests. Expected: Anomaly detection triggered."
    },
    "D: Unknown Agent": {
        "agent_id": "unknown-agent-999",
        "resource": "customer_files",
        "action": "READ",
        "description": "Unregistered agent requests access. Expected: DENY"
    },
    "E: Privilege Escalation": {
        "agent_id": "agent-001",
        "resource": "transaction_database",
        "action": "EXECUTE",
        "description": "Support Agent tries admin-level EXECUTE on financial resource. Expected: DENY + Alert"
    },
    "F: Permission Revocation Test": {
        "agent_id": "agent-002",
        "resource": "payment_api",
        "action": "EXECUTE",
        "description": "Payment Agent (normal access). First ALLOW, then deactivate agent to test revocation."
    },
    "Custom Request": {
        "agent_id": "",
        "resource": "",
        "action": "READ",
        "description": "Create your own test request."
    }
}

col_scenario, col_config = st.columns([2, 3])

with col_scenario:
    st.markdown('<div class="section-header">📋 Predefined Scenarios</div>', unsafe_allow_html=True)
    selected_scenario = st.selectbox("Select Scenario", list(SCENARIOS.keys()))
    
    scenario_data = SCENARIOS[selected_scenario]
    st.info(scenario_data["description"])
    
    if st.button("▶️ Load Scenario", use_container_width=True):
        st.session_state["sim_agent_id"] = scenario_data["agent_id"]
        st.session_state["sim_resource"] = scenario_data["resource"]
        st.session_state["sim_action"] = scenario_data["action"]
        st.rerun()

with col_config:
    st.markdown('<div class="section-header">⚙️ Request Configuration</div>', unsafe_allow_html=True)
    
    # Load agents for dropdown
    agents = api_get("/agents/") or []
    agent_map = {f"{a['agent_name']} ({a['agent_id']})": a['agent_id'] for a in agents}
    agent_map["Custom Agent ID..."] = "__custom__"
    
    selected_agent_label = st.selectbox(
        "Agent",
        list(agent_map.keys()),
        key="agent_select"
    )
    
    if selected_agent_label == "Custom Agent ID...":
        agent_id_input = st.text_input(
            "Custom Agent ID",
            value=st.session_state.get("sim_agent_id", ""),
            placeholder="e.g., unknown-agent-123"
        )
    else:
        agent_id_input = agent_map[selected_agent_label]
        # Override with scenario if loaded
        if st.session_state.get("sim_agent_id"):
            agent_id_input = st.session_state.get("sim_agent_id", agent_id_input)
    
    AVAILABLE_RESOURCES = [
        "customer_files", "support_database", "transaction_database",
        "payment_api", "analytics_database", "reports",
        "admin_panel", "system_config", "user_credentials",
        "financial_records", "Custom..."
    ]
    
    resource_default = st.session_state.get("sim_resource", "customer_files")
    if resource_default not in AVAILABLE_RESOURCES:
        resource_choice = "Custom..."
    else:
        resource_choice = resource_default
    
    resource_select = st.selectbox(
        "Resource",
        AVAILABLE_RESOURCES,
        index=AVAILABLE_RESOURCES.index(resource_choice) if resource_choice in AVAILABLE_RESOURCES else 0
    )
    
    if resource_select == "Custom...":
        resource_input = st.text_input("Custom Resource", value=st.session_state.get("sim_resource", ""))
    else:
        resource_input = resource_select
    
    action_options = ["READ", "WRITE", "EXECUTE"]
    action_default = st.session_state.get("sim_action", "READ")
    action = st.radio(
        "Action",
        action_options,
        index=action_options.index(action_default) if action_default in action_options else 0,
        horizontal=True
    )
    
    repeat_count = st.slider(
        "Repeat Count (for frequency testing)",
        min_value=1, max_value=20, value=1,
        help="Send multiple requests to test frequency detection"
    )
    
    # Clear scenario state
    if st.button("🗑️ Clear"):
        for key in ["sim_agent_id", "sim_resource", "sim_action"]:
            st.session_state.pop(key, None)
        st.rerun()

st.markdown("---")

# ── Submit Button ──────────────────────────────────────────────────────────
col_submit, col_spacer = st.columns([1, 2])
with col_submit:
    submit = st.button(
        "🚀 Send Request",
        use_container_width=True,
        type="primary"
    )

if submit:
    final_agent_id = agent_id_input if selected_agent_label == "Custom Agent ID..." else agent_map.get(selected_agent_label, agent_id_input)
    
    if not final_agent_id or not final_agent_id.strip():
        st.error("❌ Agent ID is required.")
        st.stop()
    if not resource_input or not resource_input.strip():
        st.error("❌ Resource is required.")
        st.stop()
    
    results_list = []
    
    with st.spinner(f"Processing {repeat_count} request(s)..."):
        for i in range(repeat_count):
            payload = {
                "agent_id": final_agent_id.strip(),
                "resource": resource_input.strip(),
                "action": action,
                "metadata": {"scenario": selected_scenario, "repeat_index": i + 1}
            }
            
            result = api_post("/authorize/", payload)
            if result:
                results_list.append(result)
            
            if repeat_count > 1 and i < repeat_count - 1:
                time.sleep(0.1)  # Brief delay between requests
    
    if results_list:
        last_result = results_list[-1]
        
        # Decision Banner
        decision_banner(
            last_result.get("decision", "DENY"),
            last_result.get("explanation", "")
        )
        
        st.markdown("---")
        
        # Results in columns
        col_auth, col_anomaly, col_risk = st.columns(3)
        
        with col_auth:
            st.markdown('<div class="section-header">🔐 Authorization</div>', unsafe_allow_html=True)
            st.markdown(f"**Decision:** {badge(last_result.get('decision', ''))}", unsafe_allow_html=True)
            st.markdown(f"**Agent:** {last_result.get('agent_name', 'Unknown')}")
            st.markdown(f"**Resource:** `{last_result.get('resource', '')}`")
            st.markdown(f"**Action:** `{last_result.get('action', '')}`")
            
            if last_result.get("denial_reason"):
                st.error(f"**Denial Reason:** {last_result['denial_reason']}")
            
            if last_result.get("is_privilege_escalation"):
                st.warning("⚠️ **Privilege Escalation Detected**")
            
            # Simulated resource operation
            if last_result.get("resource_operation"):
                op = last_result["resource_operation"]
                st.success(f"✅ **Simulated Operation:** {op['result'].get('data', 'Completed')}")
                st.caption("⚠️ Synthetic data only — no real operations performed.")
        
        with col_anomaly:
            st.markdown('<div class="section-header">🔍 Anomaly Detection</div>', unsafe_allow_html=True)
            anomaly = last_result.get("anomaly", {})
            classification = anomaly.get("classification", "UNAVAILABLE")
            
            st.markdown(f"**Classification:** {badge(classification)}", unsafe_allow_html=True)
            
            if anomaly.get("anomaly_score") is not None:
                score_val = anomaly["anomaly_score"]
                st.markdown(f"**Isolation Forest Score:** `{score_val:.4f}`")
                st.caption("Note: Lower score = more anomalous. This is not a probability.")
            
            st.markdown(f"**Analysis:** {anomaly.get('explanation', 'N/A')}")
        
        with col_risk:
            st.markdown('<div class="section-header">⚖️ Risk Assessment</div>', unsafe_allow_html=True)
            risk = last_result.get("risk", {})
            risk_score = risk.get("score", 0)
            risk_level = risk.get("level", "LOW")
            
            st.plotly_chart(risk_gauge(risk_score, risk_level), use_container_width=True)
            
            if risk.get("factors"):
                st.markdown("**Contributing Factors:**")
                for factor in risk["factors"]:
                    st.markdown(f"• {factor}")
            
            if risk.get("suggested_action"):
                st.info(f"💡 **Suggested Action:** {risk['suggested_action']}")
        
        # Multi-request summary
        if repeat_count > 1:
            st.markdown(f"---")
            st.markdown(f"**Batch Summary ({repeat_count} requests):**")
            
            allowed_count = sum(1 for r in results_list if r.get("decision") == "ALLOW")
            denied_count = sum(1 for r in results_list if r.get("decision") == "DENY")
            anomaly_count = sum(1 for r in results_list if r.get("anomaly", {}).get("classification") == "ANOMALOUS")
            
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.metric("Allowed", allowed_count)
            with col_b:
                st.metric("Denied", denied_count)
            with col_c:
                st.metric("Anomalies Detected", anomaly_count)
        
        st.markdown(f"**Event ID:** `{last_result.get('event_id', 'N/A')}`")
        st.markdown(f"**Timestamp:** {last_result.get('timestamp', 'N/A')}")
