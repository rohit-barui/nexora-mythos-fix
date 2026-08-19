"""
V2 Agent gRPC Server (Blueprint Pillar 13).

Exposes the control-plane agent interface over gRPC with mutual TLS. Requires
both parties to present certs signed by the shared CA. The HTTP REST surface
remains for backward compatibility; gRPC is the preferred transport.
"""

import logging
import time
import uuid
from typing import Dict, Optional

import grpc

from services.v2_agent import agent_pb2, agent_pb2_grpc
from services.v2_agent.mtls import ensure_cert_kit

logger = logging.getLogger(__name__)

SERVER_VERSION = "2.0.0-grpc"


class AgentServiceServicer(agent_pb2_grpc.AgentServiceServicer):
    """gRPC implementation of the V2 Agent service."""

    REGISTERED_AGENTS: Dict[str, float] = {}

    def __init__(self, executor=None) -> None:
        self.executor = executor

    def Register(self, request, context):
        self.REGISTERED_AGENTS[request.agent_id] = time.time()
        logger.info("gRPC register: %s v%s", request.agent_id, request.version)
        return agent_pb2.RegisterResponse(
            accepted=True,
            agent_id=request.agent_id,
            server_version=SERVER_VERSION,
        )

    def Heartbeat(self, request, context):
        self.REGISTERED_AGENTS[request.agent_id] = time.time()
        return agent_pb2.HeartbeatResponse(
            received=True,
            message=f"ack {request.agent_id} cpu={request.cpu_percent}",
        )

    async def Execute(self, request, context):
        if request.agent_id not in self.REGISTERED_AGENTS:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "agent not registered")
        execution_id = uuid.uuid4().hex[:12]
        status, message = "SUCCESS", f"executed {request.action}"
        if self.executor is not None:
            result = await self.executor(request.action, request.package, request.payload)
            status = result.get("status", "SUCCESS")
            message = result.get("message", message)
        logger.info(
            "gRPC execute: %s action=%s id=%s", request.agent_id, request.action, execution_id
        )
        return agent_pb2.ExecuteResponse(
            status=status,
            action=request.action,
            message=message,
            execution_id=execution_id,
        )

    def GetStatus(self, request, context):
        return agent_pb2.GetStatusResponse(
            agent_id=request.agent_id,
            status="healthy",
            version=SERVER_VERSION,
            uptime_seconds=int(
                time.time() - self.REGISTERED_AGENTS.get(request.agent_id, time.time())
            ),
        )


class GRPCAgentServer:
    """mTLS gRPC server hosting the AgentService."""

    def __init__(self, bind_address: str = "localhost:50051", executor=None) -> None:
        self.bind_address = bind_address
        self._server: Optional[grpc.aio.Server] = None
        self.executor = executor

    async def start(self) -> None:
        paths = ensure_cert_kit("nexora-server")
        credentials = grpc.ssl_server_credentials(
            [(open(paths["key"]).read().encode(), open(paths["cert"]).read().encode())],
            root_certificates=open(paths["ca_cert"]).read().encode(),
            require_client_auth=True,
        )
        self._server = grpc.aio.server()
        agent_pb2_grpc.add_AgentServiceServicer_to_server(
            AgentServiceServicer(executor=self.executor), self._server
        )
        self._server.add_secure_port(self.bind_address, credentials)
        await self._server.start()
        logger.info("gRPC server listening on %s (mTLS)", self.bind_address)

    async def stop(self) -> None:
        if self._server:
            await self._server.stop(grace=None)
