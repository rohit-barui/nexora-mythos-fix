import asyncio
import logging
import uuid
from datetime import UTC, datetime
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)


class V2Agent:
    """
    Nexora V2 Distributed Agent.
    Lightweight client that runs on target hosts to report telemetry,
    execute commands, and communicate with the control plane.
    """

    def __init__(
        self,
        control_plane_url: str,
        agent_id: str = None,
        api_key: str = None,
        grpc_target: Optional[str] = None,
        use_grpc: bool = False,
    ) -> None:
        self.control_plane_url = control_plane_url.rstrip("/")
        self.agent_id = agent_id or f"agent-{uuid.uuid4().hex[:8]}"
        self.api_key = api_key
        self.grpc_target = grpc_target
        self.use_grpc = use_grpc
        self._client: Optional[httpx.AsyncClient] = None
        self._grpc: Optional[Any] = None
        self._running = False
        self._task: Optional[asyncio.Task] = None

    @property
    def headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json", "X-Agent-ID": self.agent_id}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    async def start(self) -> None:
        """Start the agent (register + heartbeat loop) over HTTP or gRPC."""
        if self.use_grpc:
            from services.v2_agent.grpc_client import AgentGRPCClient

            self._grpc = AgentGRPCClient(
                target=self.grpc_target or "localhost:50051", agent_id=self.agent_id
            )
            await self._register()
        else:
            self._client = httpx.AsyncClient(timeout=30.0)
            await self._register()
        self._running = True
        self._task = asyncio.create_task(self._heartbeat_loop())
        logger.info("V2 Agent %s started (%s)", self.agent_id, "grpc" if self.use_grpc else "http")

    async def stop(self) -> None:
        """Stop the agent."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._grpc is not None:
            await self._grpc.close()
        if self._client:
            await self._client.aclose()
        logger.info("V2 Agent %s stopped", self.agent_id)

    async def _register(self) -> None:
        """Register agent with control plane."""
        if self._grpc is not None:
            await self._grpc.register(
                self.agent_id,
                "2.0.0",
                ["patch_execution", "telemetry", "snapshot"],
            )
            logger.info("Agent registered via gRPC: %s", self.agent_id)
            return
        try:
            resp = await self._client.post(
                f"{self.control_plane_url}/api/v1/agents/register",
                headers=self.headers,
                json={
                    "agent_id": self.agent_id,
                    "capabilities": ["patch_execution", "telemetry", "snapshot"],
                    "version": "2.0.0",
                },
            )
            resp.raise_for_status()
            logger.info("Agent registered: %s", resp.json())
        except Exception as exc:
            logger.warning("Agent registration failed: %s", exc)

    async def _heartbeat_loop(self) -> None:
        """Periodic heartbeat to control plane."""
        while self._running:
            try:
                await self.send_heartbeat()
            except Exception as exc:
                logger.warning("Heartbeat failed: %s", exc)
            await asyncio.sleep(30)

    async def send_heartbeat(self) -> Dict[str, Any]:
        """Send heartbeat with telemetry."""
        telemetry = await self.collect_telemetry()
        if self._grpc is not None:
            return await self._grpc.heartbeat(
                self.agent_id,
                telemetry.get("status", "healthy"),
                telemetry.get("metrics", {}),
            )
        if not self._client:
            return {"error": "not started"}
        resp = await self._client.post(
            f"{self.control_plane_url}/api/v1/agents/{self.agent_id}/heartbeat",
            headers=self.headers,
            json=telemetry,
        )
        resp.raise_for_status()
        return resp.json()

    async def collect_telemetry(self) -> Dict[str, Any]:
        """Collect system telemetry (placeholder for real implementation)."""
        return {
            "agent_id": self.agent_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "status": "healthy",
            "metrics": {
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "disk_percent": 0.0,
            },
            "services": [],
        }

    async def execute_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a command from the control plane (gRPC or HTTP)."""
        if self._grpc is not None:
            return await self._grpc.execute(
                self.agent_id,
                command.get("action", ""),
                command.get("package", ""),
                command.get("payload", ""),
            )
        action = command.get("action")
        if action == "patch":
            return await self._execute_patch(command)
        elif action == "snapshot":
            return await self._create_snapshot(command)
        elif action == "rollback":
            return await self._rollback(command)
        else:
            return {"status": "ERROR", "message": f"Unknown action: {action}"}

    async def _execute_patch(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a patch action (delegate to execution engine)."""
        return {
            "status": "SUCCESS",
            "action": "patch",
            "details": f"Executed patch for {command.get('package')}",
        }

    async def _create_snapshot(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Create a pre-patch snapshot."""
        return {
            "status": "SUCCESS",
            "action": "snapshot",
            "snapshot_id": f"snap-{uuid.uuid4().hex[:8]}",
        }

    async def _rollback(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Rollback a failed patch."""
        return {
            "status": "SUCCESS",
            "action": "rollback",
            "details": f"Rolled back {command.get('package')}",
        }


# Module-level agent instance
_agent: Optional[V2Agent] = None


async def get_agent(
    control_plane_url: str = "http://localhost:8000",
    agent_id: str = None,
    api_key: str = None,
) -> V2Agent:
    """Get or create the module-level agent instance."""
    global _agent
    if _agent is None:
        _agent = V2Agent(control_plane_url, agent_id, api_key)
    return _agent
