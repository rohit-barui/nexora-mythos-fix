"""
V2 Agent gRPC Client (Blueprint Pillar 13).

Async mTLS gRPC client used by the control plane to manage remote agents.
Falls back to the existing HTTP transport when the gRPC channel is unavailable.
"""

import logging
from typing import Any, Dict, Optional

import grpc

from services.v2_agent import agent_pb2, agent_pb2_grpc
from services.v2_agent.mtls import ensure_cert_kit

logger = logging.getLogger(__name__)


class AgentGRPCClient:
    """Async gRPC client for the V2 Agent service."""

    def __init__(self, target: str = "localhost:50051", agent_id: str = "agent-ctl") -> None:
        self.target = target
        self.agent_id = agent_id
        self._channel: Optional[grpc.aio.Channel] = None
        self._stub: Optional[agent_pb2_grpc.AgentServiceStub] = None

    def _connect(self) -> None:
        if self._channel is None:
            paths = ensure_cert_kit("nexora-client")
            credentials = grpc.ssl_channel_credentials(
                root_certificates=open(paths["ca_cert"]).read().encode(),
                private_key=open(paths["key"]).read().encode(),
                certificate_chain=open(paths["cert"]).read().encode(),
            )
            self._channel = grpc.aio.secure_channel(self.target, credentials)
            self._stub = agent_pb2_grpc.AgentServiceStub(self._channel)

    async def register(self, agent_id: str, version: str, capabilities: list) -> Dict[str, Any]:
        self._connect()
        resp = await self._stub.Register(
            agent_pb2.RegisterRequest(
                agent_id=agent_id, version=version, capabilities=capabilities
            ),
            timeout=10,
        )
        return {
            "accepted": resp.accepted,
            "agent_id": resp.agent_id,
            "server_version": resp.server_version,
        }

    async def heartbeat(
        self, agent_id: str, status: str, metrics: Dict[str, float]
    ) -> Dict[str, Any]:
        self._connect()
        resp = await self._stub.Heartbeat(
            agent_pb2.HeartbeatRequest(
                agent_id=agent_id,
                status=status,
                cpu_percent=metrics.get("cpu_percent", 0.0),
                memory_percent=metrics.get("memory_percent", 0.0),
                disk_percent=metrics.get("disk_percent", 0.0),
            ),
            timeout=10,
        )
        return {"received": resp.received, "message": resp.message}

    async def execute(
        self, agent_id: str, action: str, package: str = "", payload: str = ""
    ) -> Dict[str, Any]:
        self._connect()
        resp = await self._stub.Execute(
            agent_pb2.ExecuteRequest(
                agent_id=agent_id, action=action, package=package, payload=payload
            ),
            timeout=30,
        )
        return {
            "status": resp.status,
            "action": resp.action,
            "message": resp.message,
            "execution_id": resp.execution_id,
        }

    async def get_status(self, agent_id: str) -> Dict[str, Any]:
        self._connect()
        resp = await self._stub.GetStatus(agent_pb2.GetStatusRequest(agent_id=agent_id), timeout=10)
        return {
            "agent_id": resp.agent_id,
            "status": resp.status,
            "version": resp.version,
            "uptime_seconds": resp.uptime_seconds,
        }

    async def close(self) -> None:
        if self._channel:
            await self._channel.close()
            self._channel = None
            self._stub = None
