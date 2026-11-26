"""
AGENT SHIELD - Security Testing Centre (Page 9)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import streamlit as st
import pandas as pd
import time
from frontend.api_client import api_get, api_post, check_backend_health
from frontend.components.ui import get_global_css, page_header, badge, COLORS

st.markdown(get_global_css(), unsafe_allow_html=True)
page_header("Security Testing Centre", "Execute real security tests against the backend", "🔬")

if not check_backend_health():
    st.error("🔴 Backend Offline — Start the FastAPI backend.")
    st.stop()

st.info("""
ℹ️ **About Security Testing Centre**

This page runs **actual tests** against the backend API and policy engine. 
Tests use isolated test data and clean up after themselves — real agent data is not modified.
Results are based on actual system behaviour, not hardcoded values.
""")

# ── Test Cases Description ──────────────────────────────────────────────────
with st.expander("📋 View All Test Cases", expanded=False):
    test_cases = [
        ("TC-001", "Authorized Access", "Valid agent + valid resource + valid action → ALLOW"),
        ("TC-002", "Unauthorized Resource", "Valid agent + unauthorized resource → DENY"),
        ("TC-003", "Unknown Agent", "Non-existent agent ID → DENY"),
        ("TC-004", "Inactive Agent", "Inactive agent → DENY regardless of permissions"),
        ("TC-005", "Invalid Action", "Valid agent + 'HACK' action → DENY"),
        ("TC-006", "Missing Agent ID", "Empty agent ID → DENY"),
        ("TC-007", "Duplicate Registration", "Register existing agent ID → Conflict error"),
        ("TC-008", "Permission Update", "Update permissions → New permissions enforced"),
        ("TC-009", "Permission Revocation", "Remove permission → DENY on next request"),
        ("TC-010", "Privilege Escalation", "Support agent → financial EXECUTE → DENY"),
        ("TC-011", "Repeated Denials Risk", "Multiple denials → Elevated risk score"),
        ("TC-012", "High Frequency Anomaly", "50 req/min + 10 fails → ANOMALOUS"),
        ("TC-013", "Normal Activity", "2 req/min + 0 fails → NORMAL"),
        ("TC-014", "Risk Score - Authorized", "ALLOW on regular resource → LOW risk"),
        ("TC-015", "Risk Score - Sensitive", "DENY on payment_api EXECUTE → HIGH/CRITICAL"),
        ("TC-016", "Audit Log Creation", "Event correctly logged in database"),
        ("TC-017", "Model Availability", "Isolation Forest model returns valid classification"),
        ("TC-018", "Dashboard Update", "Dashboard stats reflect actual DB data"),
        ("TC-019", "AI Agent Chat - Normal Message", "Conversational message with no tool request → NOT_APPLICABLE"),
        ("TC-020", "AI Agent Chat - Authorized Tool", "Customer Support Agent requests lookup_customer → Policy ALLOW"),
        ("TC-021", "AI Agent Chat - Unauthorized Tool", "Analytics Agent requests lookup_customer → Policy DENY (Blocked)"),
    ]
    
    df_desc = pd.DataFrame(test_cases, columns=["Test ID", "Scenario", "Description"])
    st.dataframe(df_desc, use_container_width=True, hide_index=True)

# ── Run Controls ──────────────────────────────────────────────────────────
st.markdown('<div class="section-header">▶️ Test Execution</div>', unsafe_allow_html=True)

col1, col2 = st.columns([1, 1])

with col1:
    if st.button("🚀 Run All Tests", type="primary", use_container_width=True):
        with st.spinner("Running 18 security tests against the backend..."):
            start_time = time.time()
            result = api_post("/testing/run-all", {})
            elapsed = time.time() - start_time
        
        if result:
            st.session_state["test_results"] = result
            st.session_state["test_elapsed"] = elapsed
            st.rerun()

with col2:
    if st.button("📊 Load Previous Results", use_container_width=True):
        previous = api_get("/testing/results") or []
        if previous:
            # Group by most recent run
            latest_run = previous[0].get("run_at", "")
            st.session_state["previous_results"] = previous
            st.info(f"Loaded {len(previous)} previous test results.")
        else:
            st.info("No previous test results found.")

# ── Display Results ───────────────────────────────────────────────────────
test_data = st.session_state.get("test_results")

if test_data:
    summary = test_data.get("summary", {})
    results = test_data.get("results", [])
    
    # Summary Metrics
    st.markdown('<div class="section-header">📊 Test Summary</div>', unsafe_allow_html=True)
    
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Tests", summary.get("total", 0))
    with col2:
        passed = summary.get("passed", 0)
        st.metric("✅ Passed", passed, delta=None)
    with col3:
        failed = summary.get("failed", 0)
        st.metric("❌ Failed", failed, delta=None)
    with col4:
        errors = summary.get("errors", 0)
        st.metric("⚠️ Errors", errors)
    with col5:
        total_ms = summary.get("total_execution_ms", 0)
        st.metric("⏱️ Total Time", f"{total_ms:.0f}ms")
    
    # Pass rate progress bar
    total = summary.get("total", 1)
    pass_rate = (passed / total * 100) if total > 0 else 0
    
    color = "#00d4aa" if pass_rate >= 90 else "#ffd32a" if pass_rate >= 70 else "#ff4b6e"
    st.markdown(f"""
    <div style="margin: 10px 0;">
        <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
            <span style="color: #94a3b8;">Pass Rate</span>
            <span style="color: {color}; font-weight: bold;">{pass_rate:.1f}%</span>
        </div>
        <div style="background: #1a2535; border-radius: 8px; height: 12px; overflow: hidden;">
            <div style="background: {color}; width: {pass_rate}%; height: 100%; border-radius: 8px;"></div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown('<div class="section-header">🔍 Detailed Test Results</div>', unsafe_allow_html=True)
    
    # Filter options
    col_filter1, col_filter2 = st.columns(2)
    with col_filter1:
        status_filter = st.selectbox("Filter by Status", ["All", "PASS", "FAIL", "ERROR"])
    
    # Display results
    for result in results:
        status = result.get("status", "PENDING")
        
        if status_filter != "All" and status != status_filter:
            continue
        
        test_id = result.get("test_id", "")
        test_name = result.get("test_name", "")
        scenario = result.get("test_scenario", "")
        expected = result.get("expected_result", "")
        actual = result.get("actual_result", "")
        exec_time = result.get("execution_time_ms", 0)
        error = result.get("error_details")
        
        icon = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️", "PENDING": "⏳"}.get(status, "❓")
        
        with st.expander(
            f"{icon} [{test_id}] {test_name} — {status} ({exec_time:.1f}ms)",
            expanded=(status in ("FAIL", "ERROR"))
        ):
            col_a, col_b = st.columns(2)
            
            with col_a:
                st.markdown(f"**Test ID:** `{test_id}`")
                st.markdown(f"**Scenario:** {scenario}")
                st.markdown(f"**Status:** {badge(status)}", unsafe_allow_html=True)
                st.markdown(f"**Execution Time:** {exec_time:.1f}ms")
            
            with col_b:
                st.markdown(f"**Input:** `{result.get('test_input', 'N/A')}`")
                st.markdown(f"**Expected:** {expected}")
                st.markdown(f"**Actual:** {actual}")
                
                if error:
                    st.error(f"**Error:** {error}")
    
    # Run info
    st.caption(f"Tests run at: {test_data.get('run_at', 'N/A')}")

# ── Previous Results ────────────────────────────────────────────────────────
elif "previous_results" in st.session_state:
    prev = st.session_state["previous_results"]
    st.markdown('<div class="section-header">📊 Previous Test Results</div>', unsafe_allow_html=True)
    
    df_prev = pd.DataFrame(prev)[["test_id", "test_name", "status", "expected_result",
                                    "actual_result", "execution_time_ms", "run_at"]]
    df_prev.columns = ["Test ID", "Test Name", "Status", "Expected", "Actual", "Time (ms)", "Run At"]
    st.dataframe(df_prev, use_container_width=True, height=500)

else:
    st.markdown("""
    <div style="text-align: center; padding: 60px; color: #64748b;">
        <div style="font-size: 3rem;">🔬</div>
        <h3>Ready to Test</h3>
        <p>Click <strong>"Run All Tests"</strong> to execute 18 security test cases against the live backend.</p>
        <p>Tests use isolated data and clean up after themselves.</p>
    </div>
    """, unsafe_allow_html=True)
