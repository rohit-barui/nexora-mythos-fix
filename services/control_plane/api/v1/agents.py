from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/agents", tags=["V2 Agents"])


class AgentRegisterRequest(BaseModel):
    agent_id: str = Field(..., description="Unique agent identifier")
    capabilities: List[str] = Field(default_factory=list)
    version: str = Field("2.0.0")


class AgentRegisterResponse(BaseModel):
    status: str
    agent_id: str
    message: str


class AgentHeartbeatRequest(BaseModel):
    agent_id: str
    timestamp: str
    status: str
    metrics: Dict[str, Any] = Field(default_factory=dict)
    services: List[str] = Field(default_factory=list)


class AgentHeartbeatResponse(BaseModel):
    status: str
    commands: List[Dict[str, Any]] = Field(default_factory=list)


# In-memory agent registry (replace with DB in production)
_agent_registry: Dict[str, Dict[str, Any]] = {}


@router.post("/register", response_model=AgentRegisterResponse)
async def register_agent(request: AgentRegisterRequest):
    if request.agent_id in _agent_registry:
        raise HTTPException(status_code=409, detail="Agent already registered")

    _agent_registry[request.agent_id] = {
        "agent_id": request.agent_id,
        "capabilities": request.capabilities,
        "version": request.version,
        "registered_at": "now",
        "last_heartbeat": None,
    }
    return AgentRegisterResponse(
        status="REGISTERED", agent_id=request.agent_id, message="Agent registered successfully"
    )


@router.post("/{agent_id}/heartbeat", response_model=AgentHeartbeatResponse)
async def agent_heartbeat(agent_id: str, request: AgentHeartbeatRequest):
    if agent_id not in _agent_registry:
        raise HTTPException(status_code=404, detail="Agent not found")

    _agent_registry[agent_id]["last_heartbeat"] = request.timestamp
    _agent_registry[agent_id]["status"] = request.status
    _agent_registry[agent_id]["metrics"] = request.metrics

    # Return any pending commands (empty for now)
    return AgentHeartbeatResponse(status="OK", commands=[])


@router.get("/")
async def list_agents():
    return list(_agent_registry.values())


@router.get("/{agent_id}")
async def get_agent(agent_id: str):
    if agent_id not in _agent_registry:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _agent_registry[agent_id]


@router.delete("/{agent_id}")
async def delete_agent(agent_id: str):
    if agent_id not in _agent_registry:
        raise HTTPException(status_code=404, detail="Agent not found")
    del _agent_registry[agent_id]
    return {"message": "Agent deleted"}
