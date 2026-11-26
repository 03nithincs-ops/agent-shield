"""
AGENT SHIELD - FastAPI Route: AI Agent Chat with Local Ollama
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from ..ollama_client import (
    check_ollama_status,
    process_agent_chat,
    MOCK_CUSTOMERS,
    DEFAULT_MODEL
)

router = APIRouter(prefix="/agent-chat", tags=["AI Agent Chat"])


class ChatMessageRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=64)
    message: str = Field(..., min_length=1, max_length=2000)
    model: str = Field(default=DEFAULT_MODEL)
    history: Optional[List[Dict[str, str]]] = Field(default_factory=list)
    force_mock_llm: bool = Field(default=False)


@router.get("/status")
async def get_chat_status(model: str = DEFAULT_MODEL):
    """Check status of the local Ollama server and model."""
    return check_ollama_status(model)


@router.get("/customers")
async def list_mock_customers():
    """List mock customer IDs available for testing lookup_customer tool."""
    return {"customers": list(MOCK_CUSTOMERS.values())}


@router.post("/message")
async def send_agent_message(request: ChatMessageRequest):
    """
    Handle user message to an AI Agent:
    - Pass prompt and tools to Ollama (or fallback)
    - If tool call is triggered, evaluate through Agent Shield Policy Engine
    - Deny or execute tool accordingly
    - Audit log the outcome
    """
    try:
        result = process_agent_chat(
            agent_id=request.agent_id,
            user_message=request.message,
            conversation_history=request.history,
            model_name=request.model,
            use_mock_llm=request.force_mock_llm
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat processing error: {str(e)}")
