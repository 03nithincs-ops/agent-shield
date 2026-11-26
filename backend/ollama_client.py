"""
AGENT SHIELD - Ollama Local AI Agent Client
Integrates with local Ollama instance (qwen2.5:3b) at http://localhost:11434.
Enforces runtime policy engine authorization before executing any tool.
"""

import json
import logging
import requests
from typing import Dict, Any, List, Optional, Tuple

from .policy_engine import evaluate_authorization, check_privilege_escalation, get_agent_recent_stats
from .anomaly_detector import detect_anomaly
from .risk_analyzer import calculate_risk_score
from .audit_logger import log_event
from .alert_manager import evaluate_and_create_alerts
from .database import get_agent_by_id

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5:3b"

# Mock customer records for lookup_customer tool (Synthetic data only)
MOCK_CUSTOMERS: Dict[str, Dict[str, Any]] = {
    "cust-101": {
        "customer_id": "CUST-101",
        "name": "Alice Johnson",
        "tier": "Enterprise",
        "email": "alice.j@example-corp.com",
        "phone": "+1-555-0142",
        "status": "Active",
        "account_balance": "$0.00",
        "assigned_support_tier": "Tier 3 Priority"
    },
    "cust-102": {
        "customer_id": "CUST-102",
        "name": "Bob Smith",
        "tier": "Standard",
        "email": "bob.smith@example.net",
        "phone": "+1-555-0198",
        "status": "Active",
        "account_balance": "$120.50",
        "assigned_support_tier": "Standard Support"
    },
    "cust-103": {
        "customer_id": "CUST-103",
        "name": "Charlie Davis",
        "tier": "Premium",
        "email": "c.davis@fintech-demo.org",
        "phone": "+1-555-0177",
        "status": "Suspended",
        "account_balance": "$45.00",
        "assigned_support_tier": "Tier 2 Support"
    }
}

# Mapping of AI Agent tools to required Agent Shield resources and actions
TOOL_PERMISSION_MAP = {
    "lookup_customer": {
        "resource": "customer_files",
        "action": "READ",
        "description": "Access customer profile and account details"
    }
}

# Ollama tool definition following Ollama / OpenAI tool schema
AGENT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "lookup_customer",
            "description": "Look up customer account, subscription, and profile details by customer ID or name.",
            "parameters": {
                "type": "object",
                "properties": {
                    "customer_id": {
                        "type": "string",
                        "description": "The customer ID (e.g. CUST-101) or customer name (e.g. Alice)"
                    }
                },
                "required": ["customer_id"]
            }
        }
    }
]


def check_ollama_status(model_name: str = DEFAULT_MODEL) -> Dict[str, Any]:
    """
    Check if Ollama server is running and if the requested model is available.
    Also verifies tool-calling support.
    """
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            models = [m.get("name", "") for m in data.get("models", [])]
            # Match model name with or without tag
            model_available = any(
                m == model_name or m.startswith(f"{model_name}:") or m.startswith(model_name.split(":")[0])
                for m in models
            )
            
            # Known local models supporting tool-calling
            tool_supported_families = ["qwen2.5", "llama3.1", "mistral", "firefunction", "command-r"]
            supports_tools = any(family in model_name.lower() for family in tool_supported_families)
            
            return {
                "online": True,
                "url": OLLAMA_BASE_URL,
                "model": model_name,
                "model_available": model_available,
                "available_models": models,
                "supports_tools": supports_tools,
                "recommended_model": DEFAULT_MODEL,
                "message": (
                    f"Ollama is running. Model '{model_name}' is "
                    + ("available and supports tool calling." if model_available and supports_tools else "not pulled or doesn't support tools.")
                )
            }
    except Exception as e:
        logger.warning(f"Ollama server not reachable at {OLLAMA_BASE_URL}: {e}")
    
    return {
        "online": False,
        "url": OLLAMA_BASE_URL,
        "model": model_name,
        "model_available": False,
        "available_models": [],
        "supports_tools": True,
        "recommended_model": DEFAULT_MODEL,
        "message": f"Ollama is offline or unreachable at {OLLAMA_BASE_URL}. Run 'ollama serve' and 'ollama run {model_name}'."
    }


def execute_mock_lookup_customer(customer_id: str) -> Dict[str, Any]:
    """Execute customer lookup against synthetic dataset."""
    search_key = customer_id.strip().lower()
    
    # Try exact match by ID
    if search_key in MOCK_CUSTOMERS:
        return {"found": True, "customer": MOCK_CUSTOMERS[search_key]}
    
    # Try match by partial name or ID
    for cid, data in MOCK_CUSTOMERS.items():
        if search_key in cid or search_key in data["name"].lower():
            return {"found": True, "customer": data}
            
    return {
        "found": False,
        "message": f"No customer record found matching '{customer_id}'. Available test IDs: CUST-101, CUST-102, CUST-103."
    }


def process_agent_chat(
    agent_id: str,
    user_message: str,
    conversation_history: Optional[List[Dict[str, str]]] = None,
    model_name: str = DEFAULT_MODEL,
    use_mock_llm: bool = False
) -> Dict[str, Any]:
    """
    Process an AI agent chat turn:
    1. Send user prompt to local Ollama model with lookup_customer tool definition.
    2. If Ollama requests tool calling:
       a) Pass agent_id, resource, action through Runtime Policy Engine.
       b) If DENIED: NEVER execute tool; feed security denial back to agent context.
       c) If ALLOWED: Execute mock customer lookup; feed result back to agent.
       d) Record audit event, anomaly detection, and risk assessment.
    3. Return final LLM response along with security decision details.
    """
    agent = get_agent_by_id(agent_id)
    agent_name = agent["agent_name"] if agent else "Unknown Agent"
    
    # Prepare messages
    system_prompt = (
        f"You are {agent_name} (ID: {agent_id}) running inside the Agent Shield security environment. "
        "You help users with customer support and inquiries. "
        "When the user asks to look up, check, or view a customer's profile, account, or details, "
        "call the 'lookup_customer' tool with their customer ID or name. "
        "If a security policy denies your tool call, politely inform the user that access was blocked by the security policy."
    )
    
    messages = [{"role": "system", "content": system_prompt}]
    if conversation_history:
        for msg in conversation_history:
            messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})
    messages.append({"role": "user", "content": user_message})
    
    # Check Ollama connection
    status = check_ollama_status(model_name)
    
    # If Ollama is offline or use_mock_llm is requested, use simulated local LLM reasoning
    if not status["online"] or not status["model_available"] or use_mock_llm:
        return _simulate_llm_chat_turn(agent_id, agent_name, user_message, messages)

    try:
        # Step 1: Call Ollama API with tools
        payload = {
            "model": model_name,
            "messages": messages,
            "tools": AGENT_TOOLS,
            "stream": False
        }
        
        resp = requests.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload, timeout=30)
        resp.raise_for_status()
        ollama_data = resp.json()
        
        response_msg = ollama_data.get("message", {})
        tool_calls = response_msg.get("tool_calls", [])
        
        # Scenario A: LLM decided NOT to call any tools
        if not tool_calls:
            assistant_content = response_msg.get("content", "")
            return {
                "response": assistant_content,
                "tool_called": None,
                "tool_arguments": None,
                "security_decision": {
                    "decision": "NOT_APPLICABLE",
                    "explanation": "No restricted resources requested. Regular conversational response.",
                    "agent_id": agent_id,
                    "agent_name": agent_name
                },
                "customer_data": None,
                "audit_event_id": None
            }
            
        # Scenario B: LLM requested a tool call
        tool_call = tool_calls[0]
        func = tool_call.get("function", {})
        func_name = func.get("name", "")
        raw_args = func.get("arguments", {})
        
        # Parse arguments if string
        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args)
            except Exception:
                args = {"customer_id": raw_args}
        else:
            args = raw_args
            
        customer_id_arg = args.get("customer_id", "CUST-101")
        
        # Step 2: Policy Engine Evaluation (MANDATORY GATEWAY)
        perm_info = TOOL_PERMISSION_MAP.get(func_name, {"resource": "customer_files", "action": "READ"})
        req_resource = perm_info["resource"]
        req_action = perm_info["action"]
        
        # Check authorization with backend policy engine
        decision, explanation, _ = evaluate_authorization(agent_id, req_resource, req_action)
        is_escalation = check_privilege_escalation(agent_id, req_resource, req_action) if decision == "DENY" else False
        
        # Stats & Anomaly Detection
        stats = get_agent_recent_stats(agent_id)
        anomaly_res = detect_anomaly(
            requests_per_minute=stats.get("requests_last_minute", 0),
            resources_accessed=stats.get("total_requests", 0),
            failed_attempts=stats.get("recent_denied", 0),
            access_frequency=stats.get("requests_last_minute", 0),
            unique_resources=1,
            off_hours_requests=0,
            sensitive_resource_access=stats.get("sensitive_access", 0)
        )
        is_anomalous = (anomaly_res.get("classification") == "ANOMALOUS")
        
        # Risk assessment
        risk_res = calculate_risk_score(
            agent_id=agent_id,
            decision=decision,
            resource=req_resource,
            action=req_action,
            is_anomalous=is_anomalous,
            anomaly_score=anomaly_res.get("anomaly_score"),
            agent_name=agent_name
        )
        
        # Audit logging
        event_id = log_event(
            agent_id=agent_id,
            agent_name=agent_name,
            resource=req_resource,
            action=req_action,
            decision=decision,
            denial_reason=explanation if decision == "DENY" else None,
            anomaly_classification=anomaly_res.get("classification"),
            anomaly_score=anomaly_res.get("anomaly_score"),
            risk_score=risk_res.get("risk_score"),
            risk_level=risk_res.get("risk_level"),
            risk_factors=risk_res.get("contributing_factors"),
            suggested_action=risk_res.get("suggested_action"),
            request_metadata={
                "tool_name": func_name,
                "tool_arguments": args,
                "model": model_name,
                "trigger": "ollama_tool_call"
            }
        )
        
        # Alert check
        evaluate_and_create_alerts(
            agent_id=agent_id,
            agent_name=agent_name,
            decision=decision,
            resource=req_resource,
            action=req_action,
            risk_score=risk_res.get("risk_score", 0),
            risk_level=risk_res.get("risk_level", "LOW"),
            is_anomalous=is_anomalous,
            is_privilege_escalation=is_escalation
        )
        
        security_summary = {
            "decision": decision,
            "explanation": explanation,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "resource": req_resource,
            "action": req_action,
            "risk_score": risk_res.get("risk_score"),
            "risk_level": risk_res.get("risk_level"),
            "anomaly_classification": anomaly_res.get("classification"),
            "event_id": event_id
        }
        
        # Step 3: Branch on authorization decision
        if decision == "DENY":
            # NEVER execute tool. Provide tool denial message to model
            tool_response_msg = {
                "role": "tool",
                "content": f"SECURITY DENIAL: Access to resource '{req_resource}' for action '{req_action}' was DENIED by the Agent Shield Policy Engine. Reason: {explanation}"
            }
            messages.append(response_msg)
            messages.append(tool_response_msg)
            
            # Request final response from Ollama explaining rejection
            final_payload = {"model": model_name, "messages": messages, "stream": False}
            try:
                final_resp = requests.post(f"{OLLAMA_BASE_URL}/api/chat", json=final_payload, timeout=20)
                final_text = final_resp.json().get("message", {}).get("content", "")
            except Exception:
                final_text = f"🚫 Access Denied by Security Policy: {explanation}"
                
            return {
                "response": final_text,
                "tool_called": func_name,
                "tool_arguments": args,
                "security_decision": security_summary,
                "customer_data": None,
                "audit_event_id": event_id
            }
            
        else: # ALLOW
            # Execute mock customer lookup tool
            tool_data = execute_mock_lookup_customer(customer_id_arg)
            tool_response_msg = {
                "role": "tool",
                "content": json.dumps(tool_data)
            }
            messages.append(response_msg)
            messages.append(tool_response_msg)
            
            # Send tool output back to Ollama to synthesize final answer
            final_payload = {"model": model_name, "messages": messages, "stream": False}
            try:
                final_resp = requests.post(f"{OLLAMA_BASE_URL}/api/chat", json=final_payload, timeout=20)
                final_text = final_resp.json().get("message", {}).get("content", "")
            except Exception:
                cust = tool_data.get("customer", {})
                final_text = f"✅ Customer Details Retrieved:\n- Name: {cust.get('name')}\n- Tier: {cust.get('tier')}\n- Email: {cust.get('email')}\n- Status: {cust.get('status')}"
                
            return {
                "response": final_text,
                "tool_called": func_name,
                "tool_arguments": args,
                "security_decision": security_summary,
                "customer_data": tool_data.get("customer"),
                "audit_event_id": event_id
            }
            
    except Exception as e:
        logger.error(f"Error during Ollama chat processing: {e}", exc_info=True)
        return _simulate_llm_chat_turn(agent_id, agent_name, user_message, messages, fallback_reason=str(e))


def _simulate_llm_chat_turn(
    agent_id: str,
    agent_name: str,
    user_message: str,
    messages: List[Dict[str, str]],
    fallback_reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Simulates local LLM decision logic for testing or when Ollama service is offline.
    Follows the EXACT same tool-decision and policy engine gateway as live Ollama.
    """
    user_lower = user_message.lower()
    
    # Check if user message triggers tool lookup
    lookup_keywords = ["customer", "lookup", "cust-", "alice", "bob", "charlie", "account details", "who is"]
    needs_tool = any(kw in user_lower for kw in lookup_keywords) and not ("what can you do" in user_lower or "hello" in user_lower)
    
    if not needs_tool:
        return {
            "response": (
                f"Hello! I am {agent_name} (ID: {agent_id}). "
                "I operate under the Agent Shield Runtime Policy Engine. "
                "I can answer general questions or look up customer account records using the 'lookup_customer' tool if you have permission."
            ),
            "tool_called": None,
            "tool_arguments": None,
            "security_decision": {
                "decision": "NOT_APPLICABLE",
                "explanation": "No restricted resources requested. Regular conversational response.",
                "agent_id": agent_id,
                "agent_name": agent_name
            },
            "customer_data": None,
            "audit_event_id": None
        }
        
    # Extract customer ID target
    cust_id = "CUST-101"
    if "cust-102" in user_lower or "bob" in user_lower:
        cust_id = "CUST-102"
    elif "cust-103" in user_lower or "charlie" in user_lower:
        cust_id = "CUST-103"
    elif "alice" in user_lower:
        cust_id = "CUST-101"
        
    func_name = "lookup_customer"
    args = {"customer_id": cust_id}
    req_resource = "customer_files"
    req_action = "READ"
    
    # Evaluate authorization with policy engine
    decision, explanation, _ = evaluate_authorization(agent_id, req_resource, req_action)
    is_escalation = check_privilege_escalation(agent_id, req_resource, req_action) if decision == "DENY" else False
    
    # Anomaly detection & risk assessment
    stats = get_agent_recent_stats(agent_id)
    anomaly_res = detect_anomaly(
        requests_per_minute=stats.get("requests_last_minute", 0),
        resources_accessed=stats.get("total_requests", 0),
        failed_attempts=stats.get("recent_denied", 0),
        access_frequency=stats.get("requests_last_minute", 0),
        unique_resources=1,
        off_hours_requests=0,
        sensitive_resource_access=stats.get("sensitive_access", 0)
    )
    is_anomalous = (anomaly_res.get("classification") == "ANOMALOUS")
    
    risk_res = calculate_risk_score(
        agent_id=agent_id,
        decision=decision,
        resource=req_resource,
        action=req_action,
        is_anomalous=is_anomalous,
        anomaly_score=anomaly_res.get("anomaly_score"),
        agent_name=agent_name
    )
    
    event_id = log_event(
        agent_id=agent_id,
        agent_name=agent_name,
        resource=req_resource,
        action=req_action,
        decision=decision,
        denial_reason=explanation if decision == "DENY" else None,
        anomaly_classification=anomaly_res.get("classification"),
        anomaly_score=anomaly_res.get("anomaly_score"),
        risk_score=risk_res.get("risk_score"),
        risk_level=risk_res.get("risk_level"),
        risk_factors=risk_res.get("contributing_factors"),
        suggested_action=risk_res.get("suggested_action"),
        request_metadata={
            "tool_name": func_name,
            "tool_arguments": args,
            "model": "qwen2.5:3b (offline-fallback)",
            "trigger": "ollama_tool_call"
        }
    )
    
    evaluate_and_create_alerts(
        agent_id=agent_id,
        agent_name=agent_name,
        decision=decision,
        resource=req_resource,
        action=req_action,
        risk_score=risk_res.get("risk_score", 0),
        risk_level=risk_res.get("risk_level", "LOW"),
        is_anomalous=is_anomalous,
        is_privilege_escalation=is_escalation
    )
    
    security_summary = {
        "decision": decision,
        "explanation": explanation,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "resource": req_resource,
        "action": req_action,
        "risk_score": risk_res.get("risk_score"),
        "risk_level": risk_res.get("risk_level"),
        "anomaly_classification": anomaly_res.get("classification"),
        "event_id": event_id
    }
    
    if decision == "DENY":
        response_text = (
            f"🚫 I attempted to access customer files to look up '{cust_id}', "
            f"but the Agent Shield Policy Engine DENIED the request.\n\n"
            f"**Reason:** {explanation}\n\n"
            "As an AI agent under security governance, I cannot bypass this restriction."
        )
        return {
            "response": response_text,
            "tool_called": func_name,
            "tool_arguments": args,
            "security_decision": security_summary,
            "customer_data": None,
            "audit_event_id": event_id
        }
    else:
        tool_data = execute_mock_lookup_customer(cust_id)
        cust = tool_data.get("customer", {})
        response_text = (
            f"✅ Policy authorization granted. Here are the details for customer **{cust.get('name')}**:\n\n"
            f"- **Customer ID:** `{cust.get('customer_id')}`\n"
            f"- **Email:** `{cust.get('email')}`\n"
            f"- **Plan Tier:** `{cust.get('tier')}`\n"
            f"- **Account Status:** `{cust.get('status')}`\n"
            f"- **Balance:** `{cust.get('account_balance')}`\n"
            f"- **Support Tier:** `{cust.get('assigned_support_tier')}`"
        )
        return {
            "response": response_text,
            "tool_called": func_name,
            "tool_arguments": args,
            "security_decision": security_summary,
            "customer_data": cust,
            "audit_event_id": event_id
        }
