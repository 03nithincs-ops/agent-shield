"""
AGENT SHIELD - Permission Registry (Page 3)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import streamlit as st
import pandas as pd
from frontend.api_client import api_get, api_put, check_backend_health
from frontend.components.ui import get_global_css, page_header, badge, COLORS

st.markdown(get_global_css(), unsafe_allow_html=True)
page_header("Permission Registry", "View and manage agent permissions and access control", "🔑")

if not check_backend_health():
    st.error("🔴 Backend Offline.")
    st.stop()

# ── Permission Matrix ──────────────────────────────────────────────────────
st.markdown('<div class="section-header">📊 Permission Matrix</div>', unsafe_allow_html=True)

agents = api_get("/agents/") or []

if agents:
    # Build permission matrix
    all_resources = set()
    agent_perms = {}
    
    for agent in agents:
        aid = agent["agent_id"]
        agent_perms[aid] = {
            "name": agent["agent_name"],
            "type": agent["agent_type"],
            "status": agent["status"],
            "resources": agent.get("resources") or [],
            "actions": agent.get("actions") or []
        }
        
        resources = agent.get("resources") or []
        if isinstance(resources, str):
            resources = resources.split(",") if resources else []
        all_resources.update(r for r in resources if r)
    
    # Display as table
    RESOURCES = sorted(all_resources) if all_resources else [
        "customer_files", "support_database", "transaction_database",
        "payment_api", "analytics_database", "reports"
    ]
    
    # Create permission matrix DataFrame
    matrix_data = []
    for aid, perm in agent_perms.items():
        row = {
            "Agent": perm["name"],
            "Type": perm["type"],
            "Status": perm["status"]
        }
        
        resources = perm["resources"]
        if isinstance(resources, str):
            resources = resources.split(",") if resources else []
        
        actions = perm["actions"]
        if isinstance(actions, str):
            actions = list(set(actions.split(","))) if actions else []
        
        for resource in RESOURCES:
            if resource in [r.strip() for r in resources]:
                allowed_actions = [a for a in actions if a in ["READ", "WRITE", "EXECUTE"]]
                row[resource] = " | ".join(allowed_actions) if allowed_actions else "✅"
            else:
                row[resource] = "🚫"
        
        matrix_data.append(row)
    
    if matrix_data:
        df_matrix = pd.DataFrame(matrix_data)
        st.dataframe(df_matrix, use_container_width=True, height=200)
    
    st.caption("✅ = Access granted | 🚫 = No access | Actions shown when multiple exist")
    
    st.markdown("---")
    
    # ── Detailed Permission View ──────────────────────────────────────────
    st.markdown('<div class="section-header">🔍 Detailed Permission View</div>', unsafe_allow_html=True)
    
    for agent in agents:
        aid = agent["agent_id"]
        name = agent["agent_name"]
        status = agent["status"]
        
        resources = agent.get("resources") or []
        if isinstance(resources, str):
            resources = resources.split(",") if resources else []
        
        actions = agent.get("actions") or []
        if isinstance(actions, str):
            actions = list(set(actions.split(","))) if actions else []
        
        with st.expander(f"🤖 {name} ({aid}) — {status}", expanded=False):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown(f"**Agent ID:** `{aid}`")
                st.markdown(f"**Type:** {agent.get('agent_type', 'N/A')}")
                st.markdown(f"**Status:** {badge(status)}", unsafe_allow_html=True)
            
            with col2:
                st.markdown("**Allowed Resources:**")
                for r in sorted(resources):
                    if r:
                        is_sensitive = r in {"payment_api", "transaction_database",
                                             "admin_panel", "system_config", "user_credentials"}
                        icon = "⚠️" if is_sensitive else "📁"
                        st.markdown(f"{icon} `{r}`")
                
                if not resources:
                    st.markdown("*No resources assigned*")
            
            with col3:
                st.markdown("**Allowed Actions:**")
                action_icons = {"READ": "👁️", "WRITE": "✏️", "EXECUTE": "⚡"}
                for a in sorted(set(actions)):
                    if a:
                        icon = action_icons.get(a, "•")
                        st.markdown(f"{icon} `{a}`")
                
                if not actions:
                    st.markdown("*No actions assigned*")
            
            # Quick permission update
            st.markdown("**Quick Permission Update:**")
            with st.form(f"perm_form_{aid}"):
                col_res, col_act = st.columns(2)
                
                current_resources = [r.strip() for r in resources if r.strip()]
                current_actions = [a.strip() for a in actions if a.strip() and a in ["READ", "WRITE", "EXECUTE"]]
                
                with col_res:
                    new_resources = st.text_input(
                        "Resources (comma-separated)",
                        value=", ".join(current_resources),
                        key=f"res_{aid}"
                    )
                with col_act:
                    new_actions = st.multiselect(
                        "Actions",
                        ["READ", "WRITE", "EXECUTE"],
                        default=current_actions,
                        key=f"act_{aid}"
                    )
                
                if st.form_submit_button("💾 Update Permissions"):
                    res_list = [r.strip().lower() for r in new_resources.split(",") if r.strip()]
                    
                    payload = {
                        "resources": res_list,
                        "actions": new_actions
                    }
                    
                    result = api_put(f"/agents/{aid}", payload)
                    if result and result.get("success"):
                        st.success(f"✅ Permissions updated for {name}!")
                        st.rerun()

else:
    st.info("No agents registered yet. Go to Agent Management to register agents.")

# ── Sensitive Resources Warning ────────────────────────────────────────────
st.markdown("---")
st.markdown('<div class="section-header">⚠️ Sensitive Resource Registry</div>', unsafe_allow_html=True)

SENSITIVE = [
    {"Resource": "payment_api", "Risk Level": "CRITICAL", "Description": "Payment processing API — financial impact"},
    {"Resource": "transaction_database", "Risk Level": "HIGH", "Description": "Financial transaction records"},
    {"Resource": "admin_panel", "Risk Level": "CRITICAL", "Description": "System administration interface"},
    {"Resource": "system_config", "Risk Level": "HIGH", "Description": "System configuration data"},
    {"Resource": "user_credentials", "Risk Level": "CRITICAL", "Description": "Authentication credentials"},
    {"Resource": "financial_records", "Risk Level": "HIGH", "Description": "Financial audit records"},
    {"Resource": "secret_vault", "Risk Level": "CRITICAL", "Description": "Secret keys and sensitive config"},
]

df_sensitive = pd.DataFrame(SENSITIVE)
st.dataframe(df_sensitive, use_container_width=True, hide_index=True)

st.warning("""
⚠️ **Security Note:** Any agent accessing sensitive resources requires careful permission review.
The Risk Analyzer applies additional penalties when agents access or attempt to access these resources without authorization.
""")
