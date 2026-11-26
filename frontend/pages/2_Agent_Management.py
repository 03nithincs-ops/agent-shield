"""
AGENT SHIELD - Agent Management (Page 2)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import streamlit as st
import pandas as pd
from frontend.api_client import api_get, api_post, api_put, api_patch, api_delete, check_backend_health
from frontend.components.ui import get_global_css, page_header, badge

st.markdown(get_global_css(), unsafe_allow_html=True)
page_header("Agent Management", "Register, configure, and control AI agents", "🤖")

if not check_backend_health():
    st.error("🔴 Backend Offline — Start the FastAPI backend.")
    st.stop()

tab_list, tab_register, tab_edit = st.tabs(["📋 All Agents", "➕ Register Agent", "✏️ Edit / Manage"])

# ── Tab 1: List Agents ──────────────────────────────────────────────────────
with tab_list:
    col_search, col_status, col_refresh = st.columns([3, 2, 1])
    with col_search:
        search = st.text_input("🔍 Search agents...", placeholder="Name, type, or ID")
    with col_status:
        status_filter = st.selectbox("Status", ["All", "ACTIVE", "INACTIVE"])
    with col_refresh:
        st.write("")
        if st.button("🔄 Refresh"):
            st.rerun()
    
    params = {}
    if search:
        params["search"] = search
    if status_filter != "All":
        params["status"] = status_filter
    
    agents = api_get("/agents/", params) or []
    
    if agents:
        st.markdown(f"**{len(agents)} agent(s) found**")
        
        for agent in agents:
            with st.expander(
                f"🤖 {agent['agent_name']} ({agent['agent_id']}) — {agent['status']}",
                expanded=False
            ):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.markdown(f"**Agent ID:** `{agent['agent_id']}`")
                    st.markdown(f"**Type:** {agent['agent_type']}")
                    st.markdown(f"**Created:** {agent.get('created_at', '')[:10]}")
                with col2:
                    status = agent.get("status", "")
                    st.markdown(f"**Status:** ", unsafe_allow_html=False)
                    st.markdown(badge(status), unsafe_allow_html=True)
                    
                    resources = agent.get("resources") or []
                    if isinstance(resources, str):
                        resources = resources.split(",") if resources else []
                    st.markdown(f"**Resources:** {', '.join(resources) if resources else 'None'}")
                with col3:
                    actions = agent.get("actions") or []
                    if isinstance(actions, str):
                        actions = list(set(actions.split(","))) if actions else []
                    st.markdown(f"**Actions:** {', '.join(actions) if actions else 'None'}")
                    st.markdown(f"**Description:** {agent.get('description', 'N/A')}")
                
                # Quick actions
                col_act, col_deact, col_del = st.columns(3)
                current_status = agent.get("status")
                agent_id = agent["agent_id"]
                
                with col_act:
                    if current_status == "INACTIVE":
                        if st.button("✅ Activate", key=f"act_{agent_id}"):
                            result = api_patch(f"/agents/{agent_id}/status", params={"status": "ACTIVE"})
                            if result:
                                st.success("Agent activated!")
                                st.rerun()
                with col_deact:
                    if current_status == "ACTIVE":
                        if st.button("⏸️ Deactivate", key=f"deact_{agent_id}"):
                            result = api_patch(f"/agents/{agent_id}/status", params={"status": "INACTIVE"})
                            if result:
                                st.success("Agent deactivated!")
                                st.rerun()
                with col_del:
                    if agent_id not in ("agent-001", "agent-002", "agent-003"):
                        if st.button("🗑️ Delete", key=f"del_{agent_id}"):
                            result = api_delete(f"/agents/{agent_id}")
                            if result:
                                st.success("Agent deleted!")
                                st.rerun()
    else:
        st.info("No agents found. Register your first agent using the 'Register Agent' tab.")


# ── Tab 2: Register Agent ───────────────────────────────────────────────────
with tab_register:
    st.markdown('<div class="section-header">Register New AI Agent</div>', unsafe_allow_html=True)
    
    with st.form("register_agent_form", clear_on_submit=True):
        col1, col2 = st.columns(2)
        
        with col1:
            agent_id = st.text_input(
                "Agent ID *",
                placeholder="e.g., agent-004",
                help="Unique identifier. Letters, numbers, hyphens, underscores only."
            )
            agent_name = st.text_input("Agent Name *", placeholder="e.g., Inventory Agent")
            agent_type = st.selectbox(
                "Agent Type *",
                ["Support", "Financial", "Analytics", "Security", "Operations",
                 "Integration", "Data", "Monitoring", "Custom"]
            )
        
        with col2:
            description = st.text_area(
                "Description",
                placeholder="Describe the agent's purpose...",
                height=100
            )
            status = st.radio("Initial Status", ["ACTIVE", "INACTIVE"], horizontal=True)
        
        st.markdown("**Permissions**")
        col_res, col_act = st.columns(2)
        
        with col_res:
            resources_input = st.text_input(
                "Allowed Resources *",
                placeholder="customer_files, reports (comma-separated)",
                help="Resources this agent is allowed to access"
            )
        
        with col_act:
            actions = st.multiselect(
                "Allowed Actions *",
                ["READ", "WRITE", "EXECUTE"],
                help="Actions this agent can perform"
            )
        
        submitted = st.form_submit_button("🛡️ Register Agent", use_container_width=True)
        
        if submitted:
            # Validation
            errors = []
            if not agent_id or len(agent_id) < 3:
                errors.append("Agent ID must be at least 3 characters.")
            if not agent_name or not agent_name.strip():
                errors.append("Agent Name is required.")
            if not resources_input or not resources_input.strip():
                errors.append("At least one resource is required.")
            if not actions:
                errors.append("At least one action must be selected.")
            
            if errors:
                for err in errors:
                    st.error(f"❌ {err}")
            else:
                resources = [r.strip().lower() for r in resources_input.split(",") if r.strip()]
                
                payload = {
                    "agent_id": agent_id.strip(),
                    "agent_name": agent_name.strip(),
                    "agent_type": agent_type,
                    "description": description.strip() if description else "",
                    "status": status,
                    "resources": resources,
                    "actions": actions
                }
                
                result = api_post("/agents/", payload)
                if result and result.get("success"):
                    st.success(f"✅ Agent '{agent_name}' registered successfully!")
                    st.balloons()


# ── Tab 3: Edit Agent ───────────────────────────────────────────────────────
with tab_edit:
    st.markdown('<div class="section-header">Edit Agent Details</div>', unsafe_allow_html=True)
    
    agents_list = api_get("/agents/") or []
    agent_options = {f"{a['agent_name']} ({a['agent_id']})": a['agent_id'] for a in agents_list}
    
    if not agent_options:
        st.info("No agents to edit. Register agents first.")
    else:
        selected_label = st.selectbox("Select Agent to Edit", list(agent_options.keys()))
        selected_id = agent_options[selected_label]
        
        agent_data = api_get(f"/agents/{selected_id}")
        
        if agent_data:
            with st.form("edit_agent_form"):
                col1, col2 = st.columns(2)
                
                with col1:
                    new_name = st.text_input("Agent Name", value=agent_data.get("agent_name", ""))
                    new_type = st.text_input("Agent Type", value=agent_data.get("agent_type", ""))
                    new_description = st.text_area("Description", value=agent_data.get("description", ""))
                
                with col2:
                    new_status = st.radio(
                        "Status",
                        ["ACTIVE", "INACTIVE"],
                        index=0 if agent_data.get("status") == "ACTIVE" else 1
                    )
                    
                    existing_resources = agent_data.get("resources", [])
                    if isinstance(existing_resources, str):
                        existing_resources = existing_resources.split(",") if existing_resources else []
                    
                    new_resources = st.text_input(
                        "Resources",
                        value=", ".join(existing_resources)
                    )
                    
                    existing_actions = agent_data.get("actions", [])
                    if isinstance(existing_actions, str):
                        existing_actions = list(set(existing_actions.split(","))) if existing_actions else []
                    
                    new_actions = st.multiselect(
                        "Actions",
                        ["READ", "WRITE", "EXECUTE"],
                        default=[a for a in existing_actions if a in ["READ", "WRITE", "EXECUTE"]]
                    )
                
                update_submitted = st.form_submit_button("💾 Save Changes", use_container_width=True)
                
                if update_submitted:
                    resources_list = [r.strip().lower() for r in new_resources.split(",") if r.strip()]
                    
                    payload = {
                        "agent_name": new_name.strip(),
                        "agent_type": new_type.strip(),
                        "description": new_description.strip(),
                        "status": new_status,
                        "resources": resources_list,
                        "actions": new_actions
                    }
                    
                    result = api_put(f"/agents/{selected_id}", payload)
                    if result and result.get("success"):
                        st.success("✅ Agent updated successfully!")
                        st.rerun()
