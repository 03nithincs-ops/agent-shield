"""
AGENT SHIELD - FastAPI Backend Routes: Agents
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from datetime import datetime, timezone
import uuid

from ..database import get_db_connection
from ..schemas import AgentCreate, AgentUpdate, AgentResponse

router = APIRouter(prefix="/agents", tags=["Agent Registry"])


@router.post("/", response_model=dict, status_code=201)
async def register_agent(agent: AgentCreate):
    """Register a new AI agent with permissions."""
    now = datetime.now(timezone.utc).isoformat()
    
    try:
        with get_db_connection() as conn:
            # Check for duplicate ID
            existing = conn.execute(
                "SELECT agent_id FROM agents WHERE agent_id = ?", (agent.agent_id,)
            ).fetchone()
            if existing:
                raise HTTPException(status_code=409, detail=f"Agent ID '{agent.agent_id}' already exists.")
            
            # Check for duplicate name
            name_exists = conn.execute(
                "SELECT agent_id FROM agents WHERE agent_name = ?", (agent.agent_name,)
            ).fetchone()
            if name_exists:
                raise HTTPException(status_code=409, detail=f"Agent name '{agent.agent_name}' already exists.")
            
            # Insert agent
            conn.execute("""
                INSERT INTO agents (agent_id, agent_name, agent_type, status, description, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (agent.agent_id, agent.agent_name, agent.agent_type,
                  agent.status.value, agent.description, now, now))
            
            # Insert permissions
            for resource in agent.resources:
                for action in agent.actions:
                    conn.execute("""
                        INSERT OR IGNORE INTO permissions (agent_id, resource, action, created_at)
                        VALUES (?, ?, ?, ?)
                    """, (agent.agent_id, resource, action.value, now))
            
            conn.commit()
        
        return {
            "success": True,
            "agent_id": agent.agent_id,
            "message": f"Agent '{agent.agent_name}' registered successfully."
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@router.get("/", response_model=List[dict])
async def list_agents(
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None)
):
    """List all registered agents with optional filtering."""
    try:
        with get_db_connection() as conn:
            query = """
                SELECT a.agent_id, a.agent_name, a.agent_type, a.status,
                       a.description, a.created_at, a.updated_at,
                       GROUP_CONCAT(DISTINCT p.resource) as resources,
                       GROUP_CONCAT(DISTINCT p.action) as actions
                FROM agents a
                LEFT JOIN permissions p ON a.agent_id = p.agent_id
                WHERE 1=1
            """
            params = []
            
            if status:
                query += " AND a.status = ?"
                params.append(status.upper())
            
            if search:
                query += " AND (a.agent_name LIKE ? OR a.agent_type LIKE ? OR a.agent_id LIKE ?)"
                s = f"%{search}%"
                params.extend([s, s, s])
            
            query += " GROUP BY a.agent_id ORDER BY a.created_at DESC"
            
            rows = conn.execute(query, params).fetchall()
            agents = []
            for r in rows:
                d = dict(r)
                d["resources"] = d["resources"].split(",") if d.get("resources") else []
                d["actions"] = list(set(d["actions"].split(","))) if d.get("actions") else []
                agents.append(d)
            
            return agents
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching agents: {str(e)}")


@router.get("/{agent_id}", response_model=dict)
async def get_agent(agent_id: str):
    """Get a specific agent by ID."""
    try:
        with get_db_connection() as conn:
            agent = conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            
            if not agent:
                raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
            
            agent_dict = dict(agent)
            
            perms = conn.execute(
                "SELECT resource, action FROM permissions WHERE agent_id = ?", (agent_id,)
            ).fetchall()
            
            agent_dict["permissions"] = [dict(p) for p in perms]
            agent_dict["resources"] = list(set(p["resource"] for p in perms))
            agent_dict["actions"] = list(set(p["action"] for p in perms))
            
            return agent_dict
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{agent_id}", response_model=dict)
async def update_agent(agent_id: str, update: AgentUpdate):
    """Update agent details and permissions."""
    now = datetime.now(timezone.utc).isoformat()
    
    try:
        with get_db_connection() as conn:
            agent = conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            
            if not agent:
                raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
            
            # Build update query dynamically
            updates = []
            params = []
            
            if update.agent_name is not None:
                updates.append("agent_name = ?")
                params.append(update.agent_name)
            if update.agent_type is not None:
                updates.append("agent_type = ?")
                params.append(update.agent_type)
            if update.description is not None:
                updates.append("description = ?")
                params.append(update.description)
            if update.status is not None:
                updates.append("status = ?")
                params.append(update.status.value)
            
            updates.append("updated_at = ?")
            params.append(now)
            params.append(agent_id)
            
            if len(updates) > 1:
                conn.execute(
                    f"UPDATE agents SET {', '.join(updates)} WHERE agent_id = ?",
                    params
                )
            
            # Update permissions if provided
            if update.resources is not None and update.actions is not None:
                conn.execute("DELETE FROM permissions WHERE agent_id = ?", (agent_id,))
                for resource in update.resources:
                    for action in update.actions:
                        conn.execute("""
                            INSERT OR IGNORE INTO permissions (agent_id, resource, action, created_at)
                            VALUES (?, ?, ?, ?)
                        """, (agent_id, resource.strip().lower(), action.value, now))
            
            conn.commit()
        
        return {"success": True, "message": f"Agent '{agent_id}' updated successfully."}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{agent_id}/status", response_model=dict)
async def update_agent_status(agent_id: str, status: str = Query(...)):
    """Activate or deactivate an agent."""
    if status.upper() not in ("ACTIVE", "INACTIVE"):
        raise HTTPException(status_code=400, detail="Status must be ACTIVE or INACTIVE")
    
    try:
        with get_db_connection() as conn:
            agent = conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            
            if not agent:
                raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
            
            conn.execute(
                "UPDATE agents SET status = ?, updated_at = ? WHERE agent_id = ?",
                (status.upper(), datetime.now(timezone.utc).isoformat(), agent_id)
            )
            conn.commit()
        
        return {
            "success": True,
            "agent_id": agent_id,
            "new_status": status.upper(),
            "message": f"Agent '{agent_id}' status updated to {status.upper()}."
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{agent_id}", response_model=dict)
async def delete_agent(agent_id: str):
    """Delete an agent and its permissions."""
    # Protect seed agents from deletion via API in demo
    if agent_id in ("agent-001", "agent-002", "agent-003"):
        raise HTTPException(
            status_code=403,
            detail="Cannot delete seed agents. Deactivate them instead."
        )
    
    try:
        with get_db_connection() as conn:
            agent = conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            
            if not agent:
                raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
            
            conn.execute("DELETE FROM permissions WHERE agent_id = ?", (agent_id,))
            conn.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
            conn.commit()
        
        return {"success": True, "message": f"Agent '{agent_id}' deleted."}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
