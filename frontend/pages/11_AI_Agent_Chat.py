"""
AGENT SHIELD - AI Agent Chat (Page 11)
Interactive Local LLM Chat powered by Ollama (qwen2.5:3b) with Runtime Policy Enforcement.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import streamlit as st
import json
from frontend.api_client import api_get, api_post, check_backend_health
from frontend.components.ui import get_global_css, page_header, badge, COLORS

st.markdown(get_global_css(), unsafe_allow_html=True)
page_header("AI Agent Chat", "Autonomous AI Agent with Runtime Policy Engine Enforcement (Ollama qwen2.5:3b)", "💬")

if not check_backend_health():
    st.error("🔴 Backend Offline — Please start the FastAPI backend on port 8000.")
    st.stop()

# ── Ollama Status & Setup Guidance ─────────────────────────────────────────
status_data = api_get("/agent-chat/status") or {}
is_online = status_data.get("online", False)
model_avail = status_data.get("model_available", False)
model_name = status_data.get("model", "qwen2.5:3b")

col_status1, col_status2, col_status3 = st.columns([2, 2, 1])

with col_status1:
    if is_online:
        st.markdown(f"**Ollama Server:** 🟢 Online (`http://localhost:11434`)")
    else:
        st.markdown(f"**Ollama Server:** 🟡 Offline *(Using Intelligent Local Policy Engine Simulator)*")

with col_status2:
    if is_online and model_avail:
        st.markdown(f"**Model:** 🟢 `{model_name}` *(Tool Calling Supported)*")
    elif is_online:
        st.markdown(f"**Model:** ⚠️ `{model_name}` not pulled yet")
    else:
        st.markdown(f"**Model:** 🛡️ `qwen2.5:3b` *(Simulation Mode Active)*")

with col_status3:
    if st.button("🔄 Check Status"):
        st.rerun()

with st.expander("ℹ️ How to Run with Live Ollama (qwen2.5:3b)", expanded=not is_online):
    st.markdown("""
    **Agent Shield** supports free, local, 100% offline inference using **Ollama** and **Qwen 2.5 (3B)**. No API keys or paid services required!
    
    ```bash
    # 1. Install Ollama from: https://ollama.com
    # 2. Pull the tool-capable model in a terminal:
    ollama run qwen2.5:3b
    
    # 3. Ollama runs locally at: http://localhost:11434
    ```
    *If Ollama is not running, Agent Shield automatically uses its integrated Local Policy Engine Simulator to test tool calls seamlessly.*
    """)

st.markdown("---")

# ── Agent Selector & Permissions Context ────────────────────────────────────
agents = api_get("/agents/") or []
agent_options = {f"{a['agent_name']} ({a['agent_id']})": a['agent_id'] for a in agents}

col_agent_sel, col_agent_info = st.columns([2, 3])

with col_agent_sel:
    selected_label = st.selectbox(
        "Active Agent Role",
        list(agent_options.keys()) if agent_options else ["Customer Support Agent (agent-001)"],
        key="chat_agent_selector"
    )
    current_agent_id = agent_options.get(selected_label, "agent-001")

with col_agent_info:
    agent_obj = api_get(f"/agents/{current_agent_id}") or {}
    res_list = agent_obj.get("resources", [])
    if isinstance(res_list, str):
        res_list = res_list.split(",")
    act_list = agent_obj.get("actions", [])
    if isinstance(act_list, str):
        act_list = act_list.split(",")
        
    has_customer_perm = "customer_files" in res_list and "READ" in act_list
    
    st.markdown(f"**Agent Identity:** `{agent_obj.get('agent_name', 'Customer Support Agent')}` (`{current_agent_id}`)")
    st.markdown(f"**Permissions:** Resources: `{', '.join(res_list) if res_list else 'None'}` | Actions: `{', '.join(act_list) if act_list else 'None'}`")
    if has_customer_perm:
        st.markdown(f"**Policy Status for `lookup_customer`:** {badge('ALLOW')} *(Authorized to access customer_files)*", unsafe_allow_html=True)
    else:
        st.markdown(f"**Policy Status for `lookup_customer`:** {badge('DENY')} *(NOT authorized to access customer_files)*", unsafe_allow_html=True)

st.markdown("---")

# ── Quick Test Scenario Buttons ─────────────────────────────────────────────
st.markdown('<div class="section-header">⚡ One-Click Security Test Scenarios</div>', unsafe_allow_html=True)

col_t1, col_t2, col_t3 = st.columns(3)

with col_t1:
    if st.button("🟢 Scenario 1: Authorized Lookup", help="Customer Support Agent looks up Alice (CUST-101)", use_container_width=True):
        st.session_state["preset_prompt"] = "Please look up the account profile for customer Alice (CUST-101)."
        st.session_state["preset_agent"] = "agent-001"
        st.rerun()

with col_t2:
    if st.button("🔴 Scenario 2: Unauthorized Lookup", help="Analytics Agent tries to lookup Alice (CUST-101)", use_container_width=True):
        st.session_state["preset_prompt"] = "Look up customer Alice (CUST-101) details immediately."
        st.session_state["preset_agent"] = "agent-003"
        st.rerun()

with col_t3:
    if st.button("💬 Scenario 3: Normal Conversation", help="Chat message with no tool request", use_container_width=True):
        st.session_state["preset_prompt"] = "Hello! What are your capabilities and what security policies do you follow?"
        st.rerun()

# ── Chat Messages Container ────────────────────────────────────────────────
if "chat_messages" not in st.session_state:
    st.session_state["chat_messages"] = [
        {
            "role": "assistant",
            "content": "Hello! I am an AI agent running under **Agent Shield Runtime Governance**. I can assist you with inquiries or look up customer records using the `lookup_customer` tool — provided your selected agent has authorization."
        }
    ]

# Display conversation history
for msg in st.session_state["chat_messages"]:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])
        
        # Display security decision badge & details if present
        if "security_decision" in msg and msg["security_decision"]:
            sec = msg["security_decision"]
            decision = sec.get("decision", "NOT_APPLICABLE")
            
            if decision in ("ALLOW", "DENY"):
                st.markdown("---")
                if decision == "ALLOW":
                    st.markdown(f"""
                    <div style="background: #002e1f; border: 1px solid #00d4aa; border-radius: 8px; padding: 12px; margin-top: 8px;">
                        <span style="color: #00d4aa; font-weight: bold; font-size: 1rem;">🛡️ POLICY ENGINE DECISION: ALLOW</span><br>
                        <span style="color: #cbd5e1; font-size: 0.85rem;"><strong>Tool Called:</strong> <code>{msg.get('tool_called')}</code> | <strong>Resource:</strong> <code>{sec.get('resource')}</code> | <strong>Action:</strong> <code>{sec.get('action')}</code></span><br>
                        <span style="color: #94a3b8; font-size: 0.85rem;"><strong>Reason:</strong> {sec.get('explanation')}</span><br>
                        <span style="color: #64748b; font-size: 0.75rem;">Audit Event ID: <code>{sec.get('event_id', 'N/A')}</code> | Risk Level: <strong>{sec.get('risk_level', 'LOW')}</strong> ({sec.get('risk_score', 0)}/100)</span>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div style="background: #2d0a14; border: 1px solid #ff4b6e; border-radius: 8px; padding: 12px; margin-top: 8px;">
                        <span style="color: #ff4b6e; font-weight: bold; font-size: 1rem;">🛡️ POLICY ENGINE DECISION: DENY — TOOL EXECUTION BLOCKED</span><br>
                        <span style="color: #cbd5e1; font-size: 0.85rem;"><strong>Tool Intercepted:</strong> <code>{msg.get('tool_called')}</code> | <strong>Restricted Resource:</strong> <code>{sec.get('resource')}</code></span><br>
                        <span style="color: #ff9f43; font-size: 0.85rem;"><strong>Policy Reason:</strong> {sec.get('explanation')}</span><br>
                        <span style="color: #ff4b6e; font-size: 0.85rem;"><strong>Security Safeguard:</strong> The customer database was NEVER accessed.</span><br>
                        <span style="color: #64748b; font-size: 0.75rem;">Audit Event ID: <code>{sec.get('event_id', 'N/A')}</code> | Risk Level: <strong>{sec.get('risk_level', 'HIGH')}</strong> ({sec.get('risk_score', 0)}/100)</span>
                    </div>
                    """, unsafe_allow_html=True)

# ── Handle Input ───────────────────────────────────────────────────────────
preset_input = st.session_state.pop("preset_prompt", None)
preset_agent = st.session_state.pop("preset_agent", None)

if preset_agent:
    current_agent_id = preset_agent

user_input = st.chat_input("Enter your message...") or preset_input

if user_input:
    # Append user message
    st.session_state["chat_messages"].append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)
        
    with st.chat_message("assistant"):
        with st.spinner("Processing through local model & Agent Shield Policy Engine..."):
            history_payload = [
                {"role": m["role"], "content": m["content"]}
                for m in st.session_state["chat_messages"][-6:-1]
            ]
            
            chat_payload = {
                "agent_id": current_agent_id,
                "message": user_input,
                "model": model_name,
                "history": history_payload,
                "force_mock_llm": not is_online
            }
            
            result = api_post("/agent-chat/message", chat_payload)
            
            if result:
                response_text = result.get("response", "No response received.")
                st.markdown(response_text)
                
                # Display security decision badge
                sec = result.get("security_decision", {})
                decision = sec.get("decision", "NOT_APPLICABLE")
                
                if decision in ("ALLOW", "DENY"):
                    st.markdown("---")
                    if decision == "ALLOW":
                        st.markdown(f"""
                        <div style="background: #002e1f; border: 1px solid #00d4aa; border-radius: 8px; padding: 12px; margin-top: 8px;">
                            <span style="color: #00d4aa; font-weight: bold; font-size: 1rem;">🛡️ POLICY ENGINE DECISION: ALLOW</span><br>
                            <span style="color: #cbd5e1; font-size: 0.85rem;"><strong>Tool Called:</strong> <code>{result.get('tool_called')}</code> | <strong>Resource:</strong> <code>{sec.get('resource')}</code> | <strong>Action:</strong> <code>{sec.get('action')}</code></span><br>
                            <span style="color: #94a3b8; font-size: 0.85rem;"><strong>Reason:</strong> {sec.get('explanation')}</span><br>
                            <span style="color: #64748b; font-size: 0.75rem;">Audit Event ID: <code>{sec.get('event_id', 'N/A')}</code> | Risk Level: <strong>{sec.get('risk_level', 'LOW')}</strong> ({sec.get('risk_score', 0)}/100)</span>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                        <div style="background: #2d0a14; border: 1px solid #ff4b6e; border-radius: 8px; padding: 12px; margin-top: 8px;">
                            <span style="color: #ff4b6e; font-weight: bold; font-size: 1rem;">🛡️ POLICY ENGINE DECISION: DENY — TOOL EXECUTION BLOCKED</span><br>
                            <span style="color: #cbd5e1; font-size: 0.85rem;"><strong>Tool Intercepted:</strong> <code>{result.get('tool_called')}</code> | <strong>Restricted Resource:</strong> <code>{sec.get('resource')}</code></span><br>
                            <span style="color: #ff9f43; font-size: 0.85rem;"><strong>Policy Reason:</strong> {sec.get('explanation')}</span><br>
                            <span style="color: #ff4b6e; font-size: 0.85rem;"><strong>Security Safeguard:</strong> The customer database was NEVER accessed.</span><br>
                            <span style="color: #64748b; font-size: 0.75rem;">Audit Event ID: <code>{sec.get('event_id', 'N/A')}</code> | Risk Level: <strong>{sec.get('risk_level', 'HIGH')}</strong> ({sec.get('risk_score', 0)}/100)</span>
                        </div>
                        """, unsafe_allow_html=True)
                
                # Save assistant message in state
                st.session_state["chat_messages"].append({
                    "role": "assistant",
                    "content": response_text,
                    "tool_called": result.get("tool_called"),
                    "security_decision": sec
                })

col_clear, _ = st.columns([1, 4])
with col_clear:
    if st.button("🗑️ Clear Chat History"):
        st.session_state["chat_messages"] = [
            {
                "role": "assistant",
                "content": "Conversation history cleared. Ready for security monitoring."
            }
        ]
        st.rerun()
